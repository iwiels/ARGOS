export * as CodeReviewTool from "./code-review"

import { LLM, LLMClient, LLMError, ToolFailure, toolText } from "@argos/llm"
import { Context, Effect, Layer, Option, Schema } from "effect"
import { ChildProcess } from "effect/unstable/process"
import { Catalog } from "../catalog"
import { Location } from "../location"
import { PermissionV2 } from "../permission"
import { AppProcess } from "../process"
import { SessionRunnerModel } from "../session/runner/model"
import { SessionSchema } from "../session/schema"
import { SessionStore } from "../session/store"
import {
  canonicalVocabulary,
  isCanonicalTag,
  normalizeContractConfidence,
  normalizeContractCvss,
  normalizeContractCwe,
  normalizeContractSeverity,
} from "../security/contract"
import { Tool } from "./tool"
import { Tools } from "./tools"

export const name = "code-review"

/**
 * `source_tool` of the findings this tool produces. It is deliberately NOT the
 * tool name: the compliance and ATT&CK engines match on `code.review`, which is
 * also the value the `security-code` agent writes by hand when it reviews code
 * with grep/read. A finding produced here is indistinguishable from a manual
 * review, which is exactly what it is.
 */
export const SOURCE_TOOL = "code.review"

/** Permission action asserted before any diff is read. */
export const PERMISSION_ACTION = "code.review"

export const MAX_DIFF_CHARS = 120_000
export const MAX_FINDINGS = 50
export const MAX_MODEL_TOKENS = 8_192

export const description = `Review a code change for security defects that static analyzers cannot see.

Combines the diff under review with the deterministic findings already known (Semgrep, CodeQL) and asks the model to (a) discard the false positives of those scanners and (b) report what the rules missed: IDOR, broken authorization, business logic flaws, broken auth flows.

Every finding must be anchored in the diff: a file plus a line number of the new file, or a file plus an exact snippet of the diff. Findings without a verifiable anchor are discarded, never reported.

This tool is read-only: it reads the diff and never modifies the code under analysis.`

/* -------------------------------------------------------------------------- */
/* Schemas                                                                     */
/* -------------------------------------------------------------------------- */

const Cvss = Schema.Struct({
  AV: Schema.Literals(["N", "A", "L", "P"]),
  AC: Schema.Literals(["L", "H"]),
  PR: Schema.Literals(["N", "L", "H"]),
  UI: Schema.Literals(["N", "R"]),
  S: Schema.Literals(["U", "C"]),
  C: Schema.Literals(["N", "L", "H"]),
  I: Schema.Literals(["N", "L", "H"]),
  A: Schema.Literals(["N", "L", "H"]),
})

/** A deterministic finding already known (Semgrep, CodeQL) handed over as context. */
export const DeterministicFinding = Schema.Struct({
  rule_id: Schema.optional(Schema.String),
  title: Schema.optional(Schema.String),
  tool: Schema.optional(Schema.String),
  file: Schema.optional(Schema.String),
  line: Schema.optional(Schema.Number),
  severity: Schema.optional(Schema.String),
  cwe: Schema.optional(Schema.String),
  evidence: Schema.optional(Schema.String),
})
export type DeterministicFinding = typeof DeterministicFinding.Type

export const Input = Schema.Struct({
  base_ref: Schema.optional(Schema.String).annotate({
    description: "Base git ref of the change (e.g. main). Compared against head_ref.",
  }),
  head_ref: Schema.optional(Schema.String).annotate({
    description: "Head git ref of the change (e.g. feature/idor-fix).",
  }),
  path: Schema.optional(Schema.String).annotate({
    description: "Limit the review to this path (git pathspec).",
  }),
  focus: Schema.optional(Schema.Array(Schema.String)).annotate({
    description: "Files to prioritize in the review.",
  }),
  diff: Schema.optional(Schema.String).annotate({
    description: "Unified diff to review. When omitted the diff is read from the git repository of the workspace.",
  }),
  context: Schema.optional(Schema.Array(DeterministicFinding)).annotate({
    description: "Deterministic findings already known (Semgrep/CodeQL). The model triages them and reports what they missed.",
  }),
})

/** A finding in the canonical contract shape (see packages/core/src/security/contract.ts). */
export const Finding = Schema.Struct({
  source: Schema.String,
  source_tool: Schema.String,
  title: Schema.String,
  severity: Schema.String,
  confidence: Schema.String,
  cwe: Schema.optional(Schema.String),
  owasp: Schema.optional(Schema.Array(Schema.String)),
  target: Schema.optional(Schema.String),
  vector: Schema.optional(Schema.String),
  evidence: Schema.optional(Schema.Record(Schema.String, Schema.Unknown)),
  remediation: Schema.optional(Schema.String),
  cvss: Schema.optional(Cvss),
  tags: Schema.optional(Schema.Array(Schema.String)),
  references: Schema.optional(Schema.Array(Schema.String)),
})
export type Finding = typeof Finding.Type

export const Discarded = Schema.Struct({
  title: Schema.String,
  file: Schema.optional(Schema.String),
  line: Schema.optional(Schema.Number),
  reason: Schema.String,
})
export type Discarded = typeof Discarded.Type

export const DeterministicVerdict = Schema.Struct({
  ref: Schema.String,
  title: Schema.optional(Schema.String),
  file: Schema.optional(Schema.String),
  line: Schema.optional(Schema.Number),
  verdict: Schema.Literals(["confirmed", "false-positive"]),
  reason: Schema.optional(Schema.String),
})
export type DeterministicVerdict = typeof DeterministicVerdict.Type

export const Output = Schema.Struct({
  status: Schema.Literals(["reviewed", "no-diff", "failed"]),
  base_ref: Schema.optional(Schema.String),
  head_ref: Schema.optional(Schema.String),
  files: Schema.Array(Schema.String),
  summary: Schema.optional(Schema.String),
  findings: Schema.Array(Finding),
  discarded: Schema.Array(Discarded),
  deterministic: Schema.Array(DeterministicVerdict),
})
export type Output = typeof Output.Type

/* -------------------------------------------------------------------------- */
/* Diff model                                                                  */
/* -------------------------------------------------------------------------- */

export interface DiffLine {
  readonly kind: "add" | "remove" | "context"
  readonly text: string
  /** Line number in the NEW file (post-change). Absent for removed lines. */
  readonly newLine?: number
  /** Line number in the OLD file (pre-change). Absent for added lines. */
  readonly oldLine?: number
}

export interface DiffHunk {
  readonly header: string
  readonly oldStart: number
  readonly oldCount: number
  readonly newStart: number
  readonly newCount: number
  readonly lines: readonly DiffLine[]
}

export interface DiffFile {
  /** Repository relative path of the new side of the change. */
  readonly path: string
  readonly hunks: readonly DiffHunk[]
}

const HUNK_HEADER = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/

/** Normalizes a path so `a/src/x.ts`, `./src/x.ts` and `src\x.ts` compare equal. */
export const normalizePath = (value: string) => {
  let path = value.trim().replace(/\\/g, "/")
  path = path.replace(/^[ab]\//, "")
  path = path.replace(/^\.\//, "")
  return path
}

const stripQuotes = (value: string) => {
  const trimmed = value.trim()
  if (trimmed.length >= 2 && trimmed.startsWith('"') && trimmed.endsWith('"')) return trimmed.slice(1, -1)
  return trimmed
}

/**
 * Parses a unified diff into files, hunks and lines with the NEW file line
 * numbers. The new-side numbering is what makes an anchor verifiable: a line
 * number that does not exist in the new file is not a place in the change.
 */
export const parseDiff = (diff: string): DiffFile[] => {
  const files: DiffFile[] = []
  let path: string | undefined
  let hunks: DiffHunk[] = []
  let hunk:
    | { header: string; oldStart: number; oldCount: number; newStart: number; newCount: number; lines: DiffLine[] }
    | undefined
  let oldLine = 0
  let newLine = 0

  const flushHunk = () => {
    if (!hunk) return
    hunks.push(hunk)
    hunk = undefined
  }
  const flushFile = () => {
    flushHunk()
    if (path) files.push({ path, hunks })
    path = undefined
    hunks = []
  }

  for (const raw of diff.split(/\r?\n/)) {
    if (raw.startsWith("diff --git ")) {
      flushFile()
      continue
    }
    if (raw.startsWith("--- ")) {
      const value = normalizePath(stripQuotes(raw.slice(4).split("\t")[0] ?? ""))
      if (value && value !== "/dev/null" && !path) path = value
      continue
    }
    if (raw.startsWith("+++ ")) {
      const value = normalizePath(stripQuotes(raw.slice(4).split("\t")[0] ?? ""))
      if (value && value !== "/dev/null") path = value
      continue
    }
    const header = HUNK_HEADER.exec(raw)
    if (header) {
      flushHunk()
      oldLine = Number(header[1])
      newLine = Number(header[3])
      hunk = {
        header: raw,
        oldStart: oldLine,
        oldCount: header[2] === undefined ? 1 : Number(header[2]),
        newStart: newLine,
        newCount: header[4] === undefined ? 1 : Number(header[4]),
        lines: [],
      }
      continue
    }
    if (!hunk) continue
    if (raw.startsWith("\\")) continue
    const marker = raw[0]
    const text = raw.slice(1)
    if (marker === "+") {
      hunk.lines.push({ kind: "add", text, newLine })
      newLine += 1
    } else if (marker === "-") {
      hunk.lines.push({ kind: "remove", text, oldLine })
      oldLine += 1
    } else {
      hunk.lines.push({ kind: "context", text, newLine, oldLine })
      newLine += 1
      oldLine += 1
    }
  }
  flushFile()
  return files
}

/** Renders a hunk back into unified-diff text so it can travel as evidence. */
export const formatHunk = (hunk: DiffHunk) =>
  [
    `@@ -${hunk.oldStart},${hunk.oldCount} +${hunk.newStart},${hunk.newCount} @@`,
    ...hunk.lines.map((line) => `${line.kind === "add" ? "+" : line.kind === "remove" ? "-" : " "}${line.text}`),
  ].join("\n")

/* -------------------------------------------------------------------------- */
/* Anchor gate                                                                 */
/* -------------------------------------------------------------------------- */

export interface Anchor {
  /** Repository relative path of the file the finding is anchored to. */
  readonly file: string
  /** Line number inside the hunk (new side, or old side for a removed line). */
  readonly line: number
  /** Which side of the diff the line belongs to. */
  readonly side: "new" | "old"
  readonly hunk: DiffHunk
  readonly snippet?: string
}

const collapse = (value: string) => value.replace(/\s+/g, " ").trim()

const matchFile = (files: readonly DiffFile[], raw: string) => {
  const target = normalizePath(raw)
  if (!target) return undefined
  const exact = files.find((file) => file.path === target)
  if (exact) return exact
  const suffix = files.filter(
    (file) => target.endsWith(`/${file.path}`) || file.path.endsWith(`/${target}`),
  )
  return suffix.length === 1 ? suffix[0] : undefined
}

/**
 * Resolves a candidate finding to a verifiable anchor inside the diff.
 *
 * An anchor exists when the file is part of the change AND the line falls
 * inside one of its hunks — on the new side (the code as it will be merged) or
 * on the old side (a line the change removes, which is how "the authorization
 * check was deleted" is reported). Otherwise an exact snippet of the diff can
 * be located. Everything else is a hallucination and gets discarded.
 */
export const resolveAnchor = (
  files: readonly DiffFile[],
  candidate: { readonly file: string; readonly line?: number; readonly snippet?: string },
): Anchor | undefined => {
  const file = matchFile(files, candidate.file)
  if (!file) return undefined

  const line = candidate.line
  if (typeof line === "number" && Number.isInteger(line) && line > 0) {
    const hunk = file.hunks.find(
      (entry) => line >= entry.newStart && line < entry.newStart + Math.max(entry.newCount, 1),
    )
    if (hunk) return { file: file.path, line, side: "new", hunk, snippet: candidate.snippet }
    const removed = file.hunks.find(
      (entry) =>
        line >= entry.oldStart &&
        line < entry.oldStart + Math.max(entry.oldCount, 1) &&
        entry.lines.some((item) => item.kind === "remove" && item.oldLine === line),
    )
    if (removed) return { file: file.path, line, side: "old", hunk: removed, snippet: candidate.snippet }
  }

  const snippet = candidate.snippet?.trim()
  if (snippet) {
    const needle = collapse(snippet)
    for (const hunk of file.hunks) {
      for (const entry of hunk.lines) {
        if (entry.newLine === undefined) continue
        if (collapse(entry.text).includes(needle)) return { file: file.path, line: entry.newLine, side: "new", hunk, snippet }
      }
    }
    const haystack = (hunk: DiffHunk) => collapse(hunk.lines.map((entry) => entry.text).join(" "))
    for (const hunk of file.hunks) {
      if (!haystack(hunk).includes(needle)) continue
      for (const entry of hunk.lines) {
        if (entry.newLine === undefined) continue
        if (needle.includes(collapse(entry.text)) && collapse(entry.text).length > 0)
          return { file: file.path, line: entry.newLine, side: "new", hunk, snippet }
      }
    }
  }
  return undefined
}

export type DiscardReason =
  | "file-not-in-diff"
  | "line-not-in-diff"
  | "snippet-not-found"
  | "no-anchor"
  | "missing-title"

export interface Anchored {
  readonly candidate: Candidate
  readonly anchor: Anchor
}

export interface GateResult {
  readonly kept: readonly Anchored[]
  readonly discarded: readonly Discarded[]
}

/**
 * The anchoring gate: a candidate survives only when it can be pointed at a
 * concrete line of the diff. This is the difference between a reviewer and a
 * generator of noise — an unanchored claim is dropped, not reported.
 */
export const anchorGate = (files: readonly DiffFile[], candidates: readonly Candidate[]): GateResult => {
  const kept: Anchored[] = []
  const discarded: Discarded[] = []
  for (const candidate of candidates) {
    if (!candidate.title?.trim()) {
      discarded.push({ title: candidate.title ?? "", reason: "missing-title" })
      continue
    }
    const anchor = resolveAnchor(files, candidate)
    if (!anchor) {
      const file = matchFile(files, candidate.file)
      const reason: DiscardReason = !file
        ? "file-not-in-diff"
        : candidate.snippet?.trim()
          ? "snippet-not-found"
          : candidate.line === undefined
            ? "no-anchor"
            : "line-not-in-diff"
      discarded.push({
        title: candidate.title,
        file: candidate.file,
        line: candidate.line,
        reason,
      })
      continue
    }
    kept.push({ candidate, anchor })
  }
  return { kept, discarded }
}

/* -------------------------------------------------------------------------- */
/* Reviewer (LLM seam)                                                         */
/* -------------------------------------------------------------------------- */

/** A finding proposed by the model. It still has to pass the anchoring gate. */
export const Candidate = Schema.Struct({
  file: Schema.String,
  line: Schema.optional(Schema.Number),
  snippet: Schema.optional(Schema.String),
  title: Schema.String,
  severity: Schema.String,
  confidence: Schema.optional(Schema.String),
  cwe: Schema.optional(Schema.String),
  tags: Schema.optional(Schema.Array(Schema.String)),
  vector: Schema.optional(Schema.String),
  remediation: Schema.optional(Schema.String),
  exploit: Schema.optional(Schema.String),
  evidence: Schema.optional(Schema.String),
  cvss: Schema.optional(Cvss),
  cvss_justification: Schema.optional(Schema.String),
})
export type Candidate = typeof Candidate.Type

export const FalsePositive = Schema.Struct({
  /** rule_id (or title) of the deterministic finding that is a false positive. */
  ref: Schema.String,
  reason: Schema.String,
})
export type FalsePositive = typeof FalsePositive.Type

export const ReviewOutput = Schema.Struct({
  summary: Schema.String,
  findings: Schema.Array(Candidate),
  false_positives: Schema.Array(FalsePositive),
})
export type ReviewOutput = typeof ReviewOutput.Type

export interface ReviewRequest {
  readonly sessionID: SessionSchema.ID
  readonly diff: string
  readonly files: readonly DiffFile[]
  readonly deterministic: readonly DeterministicFinding[]
  readonly focus: readonly string[]
}

export interface Reviewer {
  readonly review: (request: ReviewRequest) => Effect.Effect<ReviewOutput, ToolFailure>
}

/**
 * The LLM seam of the tool. Tests replace this service with a deterministic
 * double: the review never needs a real provider to be exercised.
 */
export class ReviewerService extends Context.Service<ReviewerService, Reviewer>()("@argos/CodeReviewReviewer") {}

/* -------------------------------------------------------------------------- */
/* Prompt                                                                      */
/* -------------------------------------------------------------------------- */

const SYSTEM_PROMPT = `You are a senior application security engineer reviewing a code change before it is merged.

Your job is to find what static analysis cannot see: IDOR / broken object level authorization, broken function level authorization, missing ownership checks, business logic flaws, broken authentication and session flows, privilege escalation through the changed code, and newly introduced injection sinks.

You also receive the deterministic findings already produced by Semgrep and CodeQL. Triage them: report the ones that are false positives so the team stops chasing them. Do not repeat a deterministic finding as your own.

Hard rules:
1. Every finding MUST be anchored in the diff. Provide "file" (repository relative path exactly as it appears in the diff) plus "line" (the line number in the NEW file, as numbered by the diff) or, when you cannot state a line, an exact "snippet" copied from the diff. A finding without a verifiable anchor is discarded automatically and is worse than no finding at all.
2. Never invent a file, a line, a function or a CWE that is not visible in the diff.
3. Use only the canonical tags listed below. If no tag applies, omit "tags".
4. Only report a finding when the diff shows the vulnerable code path. "This function might be called elsewhere" is not a finding.
5. "cvss" is optional. If you provide it you must also provide "cvss_justification" explaining each base metric; without the justification the vector is dropped.
6. "severity" is one of: critical, high, medium, low, info. "confidence" is one of: confirmed, probable, possible.

Canonical tags (use only these):
`

const REVIEW_INSTRUCTIONS = `Review the change below and answer with the structured report.

Anchor every finding to the diff. Prefer "line" over "snippet".

The diff is a unified diff: the numbers in the "@@" headers are the line numbers of the OLD file (left) and of the NEW file (right). A "line" you report must be a line of the NEW file. If the defect is a line the change REMOVES (a deleted authorization check, for example), report the line number that line had in the OLD file.

Report "false_positives" for the deterministic findings that are not real vulnerabilities. Reference them by their "ref" (the rule id, or the title when there is no rule id) and explain why in "reason". Deterministic findings you do not list as false positives are treated as confirmed.
`

const formatDeterministic = (findings: readonly DeterministicFinding[]) =>
  findings.length === 0
    ? "(none)"
    : findings
        .map((finding) => {
          const location = finding.file ? ` at ${finding.file}${finding.line ? `:${finding.line}` : ""}` : ""
          return `- ref=${deterministicRef(finding)} | ${finding.title ?? "(untitled)"}${location}${
            finding.rule_id ? ` | rule_id=${finding.rule_id}` : ""
          }${finding.cwe ? ` | cwe=${finding.cwe}` : ""}${
            finding.evidence ? ` | evidence=${finding.evidence}` : ""
          }`
        })
        .join("\n")

/** Stable identifier of a deterministic finding, used to match false positives. */
export const deterministicRef = (finding: DeterministicFinding) =>
  finding.rule_id?.trim() || finding.title?.trim() || [finding.file, finding.line].filter(Boolean).join(":") || "unknown"

const formatFiles = (files: readonly DiffFile[]) =>
  files.length === 0 ? "(none)" : files.map((file) => `- ${file.path}`).join("\n")

export const buildPrompt = (request: ReviewRequest) =>
  [
    REVIEW_INSTRUCTIONS,
    `Files in this change:\n${formatFiles(request.files)}`,
    request.focus.length > 0 ? `Files to prioritize:\n${request.focus.map((item) => `- ${item}`).join("\n")}` : "",
    `Deterministic findings already known (triage them):\n${formatDeterministic(request.deterministic)}`,
    `Diff:\n${request.diff}`,
  ]
    .filter((section) => section.length > 0)
    .join("\n\n")

/* -------------------------------------------------------------------------- */
/* Contract mapping                                                            */
/* -------------------------------------------------------------------------- */

/**
 * Maps an anchored candidate onto the canonical finding contract. Only
 * canonical tags survive, the vector is always `file:line` and the CVSS vector
 * is only kept when the model justified it.
 */
export const toContractFinding = (entry: Anchored): Finding => {
  const { candidate, anchor } = entry
  const cvss =
    candidate.cvss && candidate.cvss_justification?.trim() ? normalizeContractCvss(candidate.cvss) : undefined
  const evidence: Record<string, unknown> = {
    category: "ai",
    file: anchor.file,
    line: anchor.line,
    side: anchor.side,
    diff: formatHunk(anchor.hunk),
    confidence: normalizeContractConfidence(candidate.confidence),
  }
  if (candidate.evidence?.trim()) evidence.explanation = candidate.evidence.trim()
  if (candidate.exploit?.trim()) evidence.exploit = candidate.exploit.trim()
  if (candidate.snippet?.trim()) evidence.snippet = candidate.snippet.trim()
  if (candidate.cvss_justification?.trim()) evidence.cvss_justification = candidate.cvss_justification.trim()
  return {
    source: SOURCE_TOOL,
    source_tool: SOURCE_TOOL,
    title: candidate.title.trim(),
    severity: normalizeContractSeverity(candidate.severity),
    confidence: normalizeContractConfidence(candidate.confidence),
    cwe: normalizeContractCwe(candidate.cwe),
    target: anchor.file,
    vector: `${anchor.file}:${anchor.line}`,
    evidence,
    remediation: candidate.remediation?.trim(),
    cvss,
    tags: (candidate.tags ?? []).filter((tag) => isCanonicalTag(tag)).map((tag) => tag.trim().toLowerCase()),
  }
}

/** Verdicts of the model over the deterministic findings it received. */
export const deterministicVerdicts = (
  findings: readonly DeterministicFinding[],
  falsePositives: readonly FalsePositive[],
): DeterministicVerdict[] => {
  const byRef = new Map<string, FalsePositive>()
  for (const entry of falsePositives) byRef.set(entry.ref.trim().toLowerCase(), entry)
  return findings.map((finding) => {
    const ref = deterministicRef(finding)
    const match = byRef.get(ref.toLowerCase()) ?? byRef.get((finding.title ?? "").trim().toLowerCase())
    return {
      ref,
      title: finding.title,
      file: finding.file,
      line: finding.line,
      verdict: match ? ("false-positive" as const) : ("confirmed" as const),
      reason: match?.reason,
    }
  })
}

/* -------------------------------------------------------------------------- */
/* Git                                                                         */
/* -------------------------------------------------------------------------- */

const gitAttempts = (input: typeof Input.Type): string[][] => {
  const base = ["diff", "--no-color", "--no-ext-diff"]
  const scoped = (args: string[]) => (input.path ? [...args, "--", input.path] : args)
  if (input.base_ref && input.head_ref) return [scoped([...base, `${input.base_ref}...${input.head_ref}`])]
  if (input.base_ref) return [scoped([...base, input.base_ref])]
  if (input.head_ref) return [scoped([...base, `${input.head_ref}^`, input.head_ref])]
  return [scoped([...base, "HEAD"]), scoped(base), scoped([...base, "--cached"])]
}

/**
 * Reads the diff of the repository of the workspace. Read-only by construction:
 * only `git diff` is ever executed, nothing is written to the working tree.
 */
export const readDiff = (process: AppProcess.Interface, directory: string, input: typeof Input.Type) =>
  Effect.gen(function* () {
    let last = "git diff failed"
    for (const args of gitAttempts(input)) {
      const result = yield* process
        .run(
          ChildProcess.make("git", args, { cwd: directory, extendEnv: true, stdin: "ignore" }),
          { maxOutputBytes: MAX_DIFF_CHARS * 2 },
        )
        .pipe(Effect.catch(() => Effect.succeed(undefined)))
      if (!result) continue
      if (result.exitCode !== 0) {
        last = result.stderr.toString("utf8").trim() || last
        continue
      }
      return result.stdout.toString("utf8")
    }
    return yield* new ToolFailure({ message: `Unable to read the diff: ${last}` })
  })

/* -------------------------------------------------------------------------- */
/* Model resolution                                                            */
/* -------------------------------------------------------------------------- */

const resolveModel = (catalog: Catalog.Interface, store: SessionStore.Interface, sessionID: SessionSchema.ID) =>
  Effect.gen(function* () {
    const session = yield* store.get(sessionID)
    const selected = session?.model
      ? yield* catalog.model.get(session.model.providerID, session.model.id).pipe(Effect.catch(() => Effect.succeed(undefined)))
      : Option.getOrUndefined(yield* catalog.model.default())
    if (!selected) return yield* new ModelNotSelectedError({ sessionID })
    const provider = yield* catalog.provider.get(selected.providerID).pipe(Effect.catch(() => Effect.succeed(undefined)))
    return yield* SessionRunnerModel.fromCatalogModel(selected, provider).pipe(
      Effect.catch(() => Effect.fail(new ModelNotSelectedError({ sessionID }))),
    )
  })

export class ModelNotSelectedError extends Schema.TaggedErrorClass<ModelNotSelectedError>()(
  "CodeReviewTool.ModelNotSelectedError",
  { sessionID: SessionSchema.ID },
) {}

/* -------------------------------------------------------------------------- */
/* Layers                                                                      */
/* -------------------------------------------------------------------------- */

/**
 * The real reviewer: it resolves the model of the session and asks it for a
 * structured report. Everything provider specific lives here, so the tool
 * itself stays a pure function of diff + deterministic findings.
 */
export const reviewerLayer = Layer.effect(
  ReviewerService,
  Effect.gen(function* () {
    const llm = yield* LLMClient.Service
    const catalog = yield* Catalog.Service
    const store = yield* SessionStore.Service
    return ReviewerService.of({
      review: (request) =>
        Effect.gen(function* () {
          const model = yield* resolveModel(catalog, store, request.sessionID)
          const diff =
            request.diff.length > MAX_DIFF_CHARS
              ? `${request.diff.slice(0, MAX_DIFF_CHARS)}\n[diff truncated]`
              : request.diff
          const response = yield* LLM.generateObject({
            model,
            system: `${SYSTEM_PROMPT}${canonicalVocabulary().join(", ")}`,
            prompt: buildPrompt({ ...request, diff }),
            schema: ReviewOutput,
            generation: { maxTokens: MAX_MODEL_TOKENS },
          }).pipe(
            // The client is captured when the layer is built: the call happens
            // later, outside the scope that provided it.
            Effect.provide(Layer.succeed(LLMClient.Service, llm)),
          )
          return {
            summary: response.object.summary,
            findings: response.object.findings.slice(0, MAX_FINDINGS),
            false_positives: response.object.false_positives,
          }
        }).pipe(
          Effect.mapError(
            (error) =>
              new ToolFailure({
                message:
                  error instanceof LLMError
                    ? `Code review failed: ${error.reason.message}`
                    : error instanceof ModelNotSelectedError
                      ? "Code review failed: no model is configured for this session"
                      : "Code review failed",
              }),
          ),
        ),
    })
  }),
)

export const layer = Layer.effectDiscard(
  Effect.gen(function* () {
    const tools = yield* Tools.Service
    const permission = yield* PermissionV2.Service
    const location = yield* Location.Service
    const process = yield* AppProcess.Service
    const reviewer = yield* ReviewerService

    yield* tools
      .register({
        [name]: Tool.make({
          description,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [
            toolText({
              type: "text",
              text: JSON.stringify(
                {
                  status: output.status,
                  summary: output.summary,
                  files: output.files,
                  findings: output.findings.map((finding) => ({
                    title: finding.title,
                    severity: finding.severity,
                    confidence: finding.confidence,
                    cwe: finding.cwe,
                    vector: finding.vector,
                  })),
                  discarded: output.discarded,
                  deterministic: output.deterministic,
                },
                null,
                2,
              ),
            }),
          ],
          execute: (input, context) =>
            Effect.gen(function* () {
              yield* permission
                .assert({
                  action: PERMISSION_ACTION,
                  resources: [input.path ?? location.directory],
                  save: ["*"],
                  metadata: input,
                  sessionID: context.sessionID,
                  agent: context.agent,
                  source: { type: "tool", messageID: context.assistantMessageID, callID: context.toolCallID },
                })
                .pipe(
                  Effect.mapError(
                    (error) =>
                      new ToolFailure({
                        message: `Code review denied by the permission policy: ${error instanceof Error ? error.message : String(error)}`,
                      }),
                  ),
                )

              const diff = input.diff ?? (yield* readDiff(process, location.directory, input))
              const files = parseDiff(diff)
              const deterministic = input.context ?? []
              if (files.length === 0) {
                return {
                  status: "no-diff" as const,
                  base_ref: input.base_ref,
                  head_ref: input.head_ref,
                  files: [],
                  summary: "No diff to review.",
                  findings: [],
                  discarded: [],
                  deterministic: deterministicVerdicts(deterministic, []),
                }
              }

              const review = yield* reviewer.review({
                sessionID: context.sessionID,
                diff,
                files,
                deterministic,
                focus: input.focus ?? [],
              })

              const gate = anchorGate(files, review.findings)
              const findings = gate.kept.map(toContractFinding).filter((finding) => finding.title.length > 0)
              return {
                status: "reviewed" as const,
                base_ref: input.base_ref,
                head_ref: input.head_ref,
                files: files.map((file) => file.path),
                summary: review.summary,
                findings,
                discarded: gate.discarded,
                deterministic: deterministicVerdicts(deterministic, review.false_positives),
              }
            }),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

/**
 * The shipped layer: the tool plus the real reviewer. The reviewer needs the
 * LLM client (process scoped) and the catalog (location scoped); both are
 * resolved by the runtime that assembles the location layer.
 */
export const defaultLayer = layer.pipe(Layer.provide(reviewerLayer))

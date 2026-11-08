import { describe, expect } from "bun:test"
import { execFile } from "child_process"
import fs from "fs/promises"
import path from "path"
import { promisify } from "util"
import { eq } from "drizzle-orm"
import { Effect, Layer } from "effect"
import { Database } from "@argos/core/database/database"
import { EventV2 } from "@argos/core/event"
import { Location } from "@argos/core/location"
import { PermissionV2 } from "@argos/core/permission"
import { Project } from "@argos/core/project"
import { ProjectTable } from "@argos/core/project/sql"
import { AppProcess } from "@argos/core/process"
import { AbsolutePath } from "@argos/core/schema"
import { SessionV2 } from "@argos/core/session"
import { SessionTable } from "@argos/core/session/sql"
import { FindingTable } from "@argos/core/security/sql"
import { ingestToolFindings } from "@argos/core/security/ingest"
import { CodeReviewTool } from "@argos/core/tool/code-review"
import { ToolRegistry } from "@argos/core/tool/registry"
import { testEffect } from "./lib/effect"
import { toolIdentity, executeTool, settleTool, toolDefinitions } from "./lib/tool"
import { tmpdir } from "./fixture/tmpdir"

const exec = promisify(execFile)

const SESSION_ID = SessionV2.ID.make("ses_code_review_test")

/**
 * A change that introduces an IDOR: the new endpoint loads an invoice by the
 * id coming from the request without checking who owns it.
 */
const DIFF = `diff --git a/src/api/invoices.ts b/src/api/invoices.ts
index 1111111..2222222 100644
--- a/src/api/invoices.ts
+++ b/src/api/invoices.ts
@@ -4,4 +4,10 @@ import { storage } from "../storage"
 export async function listInvoices(req: Request, res: Response) {
   const invoices = await db.invoice.findMany({ where: { userId: req.user.id } })
   return res.json(invoices)
 }
+
+export async function downloadInvoice(req: Request, res: Response) {
+  const invoice = await db.invoice.findUnique({ where: { id: req.params.id } })
+  const file = await storage.get(\`invoices/\${invoice.id}.pdf\`)
+  res.send(file)
+}
`

/** New-file line numbers of the added block above. */
const INVOICE_LOOKUP_LINE = 10

/**
 * A change that deletes the ownership check of the invoice handler: the
 * vulnerability is on the old side of the diff.
 */
const REMOVAL_DIFF = `diff --git a/src/api/invoices.ts b/src/api/invoices.ts
index 3333333..4444444 100644
--- a/src/api/invoices.ts
+++ b/src/api/invoices.ts
@@ -3,4 +3,3 @@ export async function downloadInvoice(req: Request, res: Response) {
   const invoice = await db.invoice.findUnique({ where: { id: req.params.id } })
   const owner = await db.user.findUnique({ where: { id: req.user.id } })
   return res.json(invoice)
-  if (!owner) return res.status(403)
`

const database = Database.layerFromPath(":memory:")
const events = EventV2.layer.pipe(Layer.provide(database))

const assertions: PermissionV2.AssertInput[] = []
const permission = Layer.succeed(
  PermissionV2.Service,
  PermissionV2.Service.of({
    assert: (input) => Effect.sync(() => assertions.push(input)),
    ask: () => Effect.die("unused"),
    reply: () => Effect.die("unused"),
    get: () => Effect.die("unused"),
    forSession: () => Effect.die("unused"),
    list: () => Effect.die("unused"),
  }),
)

let workspace = "/repo"
const location = Layer.succeed(
  Location.Service,
  Location.Service.of({
    get directory() {
      return AbsolutePath.make(workspace)
    },
    project: {
      id: Project.ID.global,
      directory: AbsolutePath.make(workspace),
    },
  }),
)

const requests: CodeReviewTool.ReviewRequest[] = []
let answer: CodeReviewTool.ReviewOutput = { summary: "nothing to report", findings: [], false_positives: [] }
const reviewer = Layer.succeed(
  CodeReviewTool.ReviewerService,
  CodeReviewTool.ReviewerService.of({
    review: (request) =>
      Effect.sync(() => {
        requests.push(request)
        return answer
      }),
  }),
)

const registryLayer = ToolRegistry.defaultLayer.pipe(Layer.provide(permission))
const tool = CodeReviewTool.layer.pipe(
  Layer.provide(registryLayer),
  Layer.provide(permission),
  Layer.provide(location),
  Layer.provide(AppProcess.defaultLayer),
  Layer.provide(reviewer),
)
const it = testEffect(
  Layer.mergeAll(database, events, registryLayer, permission, location, reviewer, AppProcess.defaultLayer, tool),
)

const call = (input: Record<string, unknown>) =>
  Effect.gen(function* () {
    yield* seed
    const registry = yield* ToolRegistry.Service
    return yield* executeTool(registry, {
      sessionID: SESSION_ID,
      ...toolIdentity,
      call: { type: "tool-call", id: "call-code-review", name: "code-review", input },
    })
  })

const review = (input: Record<string, unknown>) =>
  Effect.gen(function* () {
    yield* seed
    const registry = yield* ToolRegistry.Service
    return yield* settleTool(registry, {
      sessionID: SESSION_ID,
      ...toolIdentity,
      call: { type: "tool-call", id: "call-code-review", name: "code-review", input },
    })
  })

const seed = Effect.gen(function* () {
  const { db } = yield* Database.Service
  yield* db
    .insert(ProjectTable)
    .values({ id: Project.ID.global, worktree: AbsolutePath.make("/project"), sandboxes: [] })
    .onConflictDoNothing()
    .run()
    .pipe(Effect.orDie)
  yield* db
    .insert(SessionTable)
    .values({
      id: SESSION_ID,
      project_id: Project.ID.global,
      slug: "code-review-test",
      directory: "/project",
      title: "code review test",
      version: "test",
    })
    .onConflictDoNothing()
    .run()
    .pipe(Effect.orDie)
})

describe("CodeReviewTool", () => {
  it.effect("registers the tool and asserts the code.review permission", () =>
    Effect.gen(function* () {
      assertions.length = 0
      requests.length = 0
      answer = { summary: "nothing to report", findings: [], false_positives: [] }
      const tools = yield* ToolRegistry.Service

      expect((yield* toolDefinitions(tools)).map((definition) => definition.name)).toEqual(["code-review"])

      yield* call({ diff: DIFF })
      expect(assertions).toMatchObject([
        {
          sessionID: SESSION_ID,
          action: "code.review",
          resources: ["/repo"],
          save: ["*"],
        },
      ])
    }),
  )

  it.effect("anchors an IDOR finding to a verifiable line of the diff", () =>
    Effect.gen(function* () {
      assertions.length = 0
      requests.length = 0
      answer = {
        summary: "One authorization defect introduced by the change.",
        findings: [
          {
            file: "src/api/invoices.ts",
            line: INVOICE_LOOKUP_LINE,
            title: "IDOR: downloadInvoice returns any invoice by id",
            severity: "high",
            confidence: "confirmed",
            cwe: "CWE-639",
            tags: ["idor", "not-a-canonical-tag"],
            remediation: "Scope the query to the authenticated user.",
            exploit: "Any authenticated user can read another user's invoice by guessing its id.",
          },
        ],
        false_positives: [],
      }

      const settlement = yield* review({ diff: DIFF })

      expect(settlement.result.type).toBe("text")
      const output = settlement.output?.structured as CodeReviewTool.Output
      expect(output.status).toBe("reviewed")
      expect(output.files).toEqual(["src/api/invoices.ts"])
      expect(output.findings.length).toBe(1)
      const finding = output.findings[0]
      expect(finding.title).toBe("IDOR: downloadInvoice returns any invoice by id")
      expect(finding.source_tool).toBe("code.review")
      expect(finding.severity).toBe("high")
      expect(finding.confidence).toBe("confirmed")
      expect(finding.cwe).toBe("CWE-639")
      expect(finding.vector).toBe(`src/api/invoices.ts:${INVOICE_LOOKUP_LINE}`)
      expect(finding.target).toBe("src/api/invoices.ts")
      // Only canonical tags survive.
      expect(finding.tags).toEqual(["idor"])
      // The hunk of the diff travels as the evidence of the finding.
      const evidence = finding.evidence as Record<string, unknown>
      expect(evidence.category).toBe("ai")
      expect(evidence.file).toBe("src/api/invoices.ts")
      expect(evidence.line).toBe(INVOICE_LOOKUP_LINE)
      expect(String(evidence.diff)).toContain("@@ -4,4 +4,10 @@")
      expect(String(evidence.diff)).toContain("db.invoice.findUnique")
      expect(String(evidence.exploit)).toContain("another user's invoice")
      expect(output.discarded).toEqual([])
    }),
  )

  it.effect("discards a finding the model invented outside the diff", () =>
    Effect.gen(function* () {
      assertions.length = 0
      requests.length = 0
      answer = {
        summary: "Two claims.",
        findings: [
          {
            file: "src/api/legacy-payments.ts",
            line: 42,
            title: "Injected SQL in the legacy payment worker",
            severity: "critical",
          },
          {
            file: "src/api/invoices.ts",
            line: 9999,
            title: "Secret key hardcoded in the invoice template",
            severity: "high",
          },
          {
            file: "src/api/invoices.ts",
            title: "Missing rate limit on the invoice download endpoint",
            severity: "medium",
          },
        ],
        false_positives: [],
      }

      const settlement = yield* review({ diff: DIFF })

      const output = settlement.output?.structured as CodeReviewTool.Output
      expect(output.findings).toEqual([])
      expect(output.discarded.length).toBe(3)
      expect(output.discarded.map((entry) => entry.reason)).toEqual([
        "file-not-in-diff",
        "line-not-in-diff",
        "no-anchor",
      ])
      expect(output.discarded[0].file).toBe("src/api/legacy-payments.ts")
    }),
  )

  it.effect("anchors a finding that only carries an exact snippet of the diff", () =>
    Effect.gen(function* () {
      assertions.length = 0
      requests.length = 0
      answer = {
        summary: "One claim.",
        findings: [
          {
            file: "src/api/invoices.ts",
            snippet: "db.invoice.findUnique({ where: { id: req.params.id } })",
            title: "IDOR: the invoice is loaded without an ownership check",
            severity: "high",
          },
        ],
        false_positives: [],
      }

      const settlement = yield* review({ diff: DIFF })

      const output = settlement.output?.structured as CodeReviewTool.Output
      expect(output.findings.length).toBe(1)
      expect(output.findings[0].vector).toBe(`src/api/invoices.ts:${INVOICE_LOOKUP_LINE}`)
    }),
  )

  it.effect("anchors a finding that points at a line the change removes", () =>
    Effect.gen(function* () {
      assertions.length = 0
      requests.length = 0
      answer = {
        summary: "The change deletes the ownership check.",
        findings: [
          {
            file: "src/api/invoices.ts",
            line: 6,
            title: "The authorization check was removed from the invoice handler",
            severity: "high",
            confidence: "confirmed",
            cwe: "CWE-862",
            tags: ["broken-access-control"],
          },
        ],
        false_positives: [],
      }

      const settlement = yield* review({ diff: REMOVAL_DIFF })

      const output = settlement.output?.structured as CodeReviewTool.Output
      expect(output.findings.length).toBe(1)
      expect(output.findings[0].vector).toBe("src/api/invoices.ts:6")
      const evidence = output.findings[0].evidence as Record<string, unknown>
      expect(evidence.side).toBe("old")
      expect(String(evidence.diff)).toContain("-  if (!owner) return res.status(403)")
    }),
  )

  it.effect("reflects the false positives the model reports over the deterministic findings", () =>
    Effect.gen(function* () {
      assertions.length = 0
      requests.length = 0
      answer = {
        summary: "The Semgrep hit is a false positive.",
        findings: [],
        false_positives: [
          {
            ref: "semgrep:javascript.lang.security.audit.sql-injection",
            reason: "The value is a bound parameter, not string concatenation.",
          },
        ],
      }

      const settlement = yield* review({
        diff: DIFF,
        context: [
          {
            rule_id: "semgrep:javascript.lang.security.audit.sql-injection",
            title: "SQL injection",
            tool: "code.sast",
            file: "src/api/invoices.ts",
            line: 10,
          },
          {
            rule_id: "codeql:js/unsafe-deserialization",
            title: "Unsafe deserialization",
            tool: "code.semantic",
            file: "src/api/orders.ts",
            line: 22,
          },
        ],
      })

      const output = settlement.output?.structured as CodeReviewTool.Output
      expect(output.deterministic.length).toBe(2)
      const semgrep = output.deterministic.find((entry) => entry.ref.startsWith("semgrep:"))
      expect(semgrep?.verdict).toBe("false-positive")
      expect(semgrep?.reason).toContain("bound parameter")
      const codeql = output.deterministic.find((entry) => entry.ref.startsWith("codeql:"))
      expect(codeql?.verdict).toBe("confirmed")
      // The deterministic findings reach the model as context.
      expect(requests[0].deterministic.length).toBe(2)
    }),
  )

  it.effect("produces output the findings ingestor persists as canonical findings", () =>
    Effect.gen(function* () {
      yield* seed
      assertions.length = 0
      requests.length = 0
      answer = {
        summary: "One authorization defect introduced by the change.",
        findings: [
          {
            file: "src/api/invoices.ts",
            line: INVOICE_LOOKUP_LINE,
            title: "IDOR: downloadInvoice returns any invoice by id",
            severity: "high",
            confidence: "confirmed",
            cwe: "CWE-639",
            tags: ["idor"],
            remediation: "Scope the query to the authenticated user.",
          },
        ],
        false_positives: [],
      }

      const settlement = yield* review({ diff: DIFF })

      const output = settlement.output?.structured as CodeReviewTool.Output
      const { db } = yield* Database.Service
      yield* ingestToolFindings(db, {
        sessionID: SESSION_ID,
        type: "tool",
        tool: "code-review",
        state: { status: "completed", output: JSON.stringify(output) },
      }, { source: "import" })

      const rows = yield* db
        .select()
        .from(FindingTable)
        .where(eq(FindingTable.session_id, SESSION_ID))
        .all()
        .pipe(Effect.orDie)

      expect(rows.length).toBe(1)
      expect(rows[0].title).toBe("IDOR: downloadInvoice returns any invoice by id")
      expect(rows[0].severity).toBe("high")
      expect(rows[0].confidence).toBe("confirmed")
      expect(rows[0].cwe).toBe("CWE-639")
      expect(rows[0].source_tool).toBe("code.review")
      expect(rows[0].source).toBe("import")
      expect(rows[0].vector).toBe(`src/api/invoices.ts:${INVOICE_LOOKUP_LINE}`)
      expect(rows[0].tags).toContain("idor")
    }),
  )

  it.effect("reports no diff when the change is empty", () =>
    Effect.gen(function* () {
      assertions.length = 0
      requests.length = 0
      const settlement = yield* review({ diff: "" })
      const output = settlement.output?.structured as CodeReviewTool.Output
      expect(output.status).toBe("no-diff")
      expect(output.findings).toEqual([])
      expect(requests.length).toBe(0)
    }),
  )
})

describe("CodeReviewTool on a real repository", () => {
  it.live("reads the diff from git without touching the working tree", () =>
    Effect.acquireRelease(
      Effect.promise(() => tmpdir()),
      (dir) => Effect.promise(() => dir[Symbol.asyncDispose]()),
    ).pipe(
      Effect.flatMap((dir) =>
        Effect.gen(function* () {
          yield* seed
          const run = (...args: string[]) => Effect.promise(() => exec("git", args, { cwd: dir.path }))
          yield* run("init", "-q")
          yield* run("config", "user.email", "test@example.com")
          yield* run("config", "user.name", "Test")
          yield* Effect.promise(async () => {
            await fs.mkdir(path.join(dir.path, "src", "api"), { recursive: true })
            await fs.writeFile(
              path.join(dir.path, "src", "api", "invoices.ts"),
              "export async function listInvoices() {\n  return []\n}\n",
              "utf8",
            )
          })
          yield* run("add", ".")
          yield* run("commit", "-q", "-m", "initial")

          const vulnerable =
            "export async function listInvoices() {\n  return []\n}\n\nexport async function downloadInvoice(req, res) {\n  const invoice = await db.invoice.findUnique({ where: { id: req.params.id } })\n  res.send(invoice)\n}\n"
          yield* Effect.promise(() =>
            fs.writeFile(path.join(dir.path, "src", "api", "invoices.ts"), vulnerable, "utf8"),
          )

          const before = (yield* run("status", "--porcelain")).stdout
          workspace = dir.path
          answer = {
            summary: "One authorization defect.",
            findings: [
              {
                file: "src/api/invoices.ts",
                snippet: "db.invoice.findUnique({ where: { id: req.params.id } })",
                title: "IDOR: the invoice is loaded without an ownership check",
                severity: "high",
                confidence: "confirmed",
                cwe: "CWE-639",
                tags: ["idor"],
              },
            ],
            false_positives: [],
          }

          const registry = yield* ToolRegistry.Service
          const settlement = yield* settleTool(registry, {
            sessionID: SESSION_ID,
            ...toolIdentity,
            call: { type: "tool-call", id: "call-code-review", name: "code-review", input: {} },
          })

          const output = settlement.output?.structured as CodeReviewTool.Output
          expect(output.status).toBe("reviewed")
          expect(output.files).toEqual(["src/api/invoices.ts"])
          expect(output.findings.length).toBe(1)
          expect(output.findings[0].vector?.startsWith("src/api/invoices.ts:")).toBe(true)

          const after = (yield* run("status", "--porcelain")).stdout
          expect(after).toBe(before)
          const content = yield* Effect.promise(() =>
            fs.readFile(path.join(dir.path, "src", "api", "invoices.ts"), "utf8"),
          )
          expect(content).toBe(vulnerable)
        }),
      ),
    ),
  )
})

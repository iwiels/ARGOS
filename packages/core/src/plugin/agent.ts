export * as AgentPlugin from "./agent"

import path from "path"
import { Effect } from "effect"
import { AgentV2 } from "../agent"
import { Global } from "../global"
import { Location } from "../location"
import { PermissionV2 } from "../permission"
import { PluginV2 } from "../plugin"

const TRUNCATION_GLOB = path.join(Global.Path.data, "tool-output", "*")

const BUILD_SYSTEM = `You are the Security Analyst, the default agent of the Argos security operations platform. You help security teams analyze, triage, and correlate security findings across web applications, networks, source code, and infrastructure.

# Mission
Turn raw evidence into actionable intelligence. Validate findings, correlate them, and produce clear, prioritized, evidence-backed conclusions.

# Operating principles
- Evidence over assumptions. Every claim must trace to an observation, a tool output, or a documented source. Mark unverified claims explicitly as hypotheses.
- Follow the authorized scope. Before any active analysis, confirm the target is authorized.
- Non-destructive by default. Never modify target systems, deny service, or persist changes unless explicitly authorized and permitted.
- Methodology before speed. Recon → surface → deep analysis → correlation → report.

# How to work
1. Read the accumulated findings (memory search) before starting.
2. Validate each finding: reproduce evidence, check severity, confirm the affected vector.
3. Correlate: group findings sharing a root cause, component, or pattern (CWE, target, exposure).
4. Prioritize using severity, exploitability, business impact, and reachability.
5. Report with structured fields (title, severity, cwe, vector, evidence, remediation, tags).

# Output style
Be concise and structured. Use tables for comparisons, short bullets for evidence. Spanish is the default product language. Use security vocabulary precisely; never invent findings.`

const PROMPT_TRIAGE = `You are the Security Triage agent of the Argos platform. Your job is fast, accurate classification of security findings and alerts.

# Mission
Receive findings or alerts and classify them quickly so the team knows what matters. You do NOT remediate — you prioritize.

# Classification model
Classify every finding with:
- Severity: critical, high, medium, low, info (CVSS-style reasoning).
- Status: observed, suspected, validated.
- Priority: order of action based on severity, exploitability, and business impact — not severity alone.
- Affected vector: the specific URL, parameter, host, port, file, or identity.

# Rules
- Be fast and decisive. When evidence is ambiguous, classify conservatively (assume higher risk) and mark status as suspected.
- Never modify files, configurations, or target systems.
- Use read/grep/glob/bash (read-only commands) and memory tools to gather context.
- Flag false positives with a clear reason instead of silently dropping them.

# Output
For each finding, write a structured record to memory (title, severity, status, priority, vector, evidence, tags). End with a ranked shortlist of the top items for the analyst and responder.`

const PROMPT_HUNTER = `You are the Threat Hunter agent of the Argos platform. You hunt for threats that automated scans miss: lateral movement, persistence, suspicious behavior, exposed secrets, and indicators of compromise.

# Mission
Proactively search targets — web, network, code, and infrastructure — for signs of compromise and latent risk, going deeper than the standard audit engines.

# Hunting playbook
1. Recon the target surface first (domains, endpoints, network ranges, exposed services).
2. Look for IoCs and behavior patterns: exposed secrets, backdoors, undocumented endpoints, suspicious outbound callbacks, default credentials, outdated vulnerable versions.
3. Correlate findings across vectors into incident chains.
4. Enrich with passive OSINT where authorized.

# Rules
- Stay within authorized scope. Passive OSINT only unless active testing is explicitly authorized.
- Non-destructive. Read and search freely; never modify targets.
- Every hypothesis must be labeled and backed by evidence before it becomes a finding.

# Output
Write structured findings to memory (title, severity, cwe, vector, evidence, tags) and deliver a hunting report: what you searched, what you found, and what the analyst/responder should validate next.`

const PROMPT_RESPONDER = `You are the Incident Responder agent of the Argos platform. You convert validated findings into concrete remediation plans and approved fixes, and you document every step for the audit trail.

# Mission
Take validated findings and drive them to resolution: define the remediation, apply approved fixes in the audited environment when permissions allow, and deliver actionable runbooks for anything that must be executed by the client's own team.

# Response workflow
1. Validate the finding is real and confirmed before acting. Ask for confirmation when evidence is inconclusive.
2. Define the remediation plan: what to fix, where, how, and how to verify.
3. Apply changes ONLY when permissions allow AND the user approves. Prefer the least invasive fix that resolves the root cause.
4. For remediation that cannot be applied from the platform (firewall rules, EDR isolation, cloud/IAM changes, credential rotation on third-party systems), deliver a precise runbook: the exact commands, console steps, or API calls the operations team must run, with verification steps.
5. Verify what you can: re-run the relevant check or scan. Document residual risk when verification is not possible from the platform.

# Rules
- Human-in-the-loop: for high-impact remediation always request explicit user approval before executing or recommending execution.
- Never recommend or perform actions against third parties or outside the authorized scope.
- Prefer reversible actions. If a recommended fix is irreversible, call that out explicitly.
- Everything you do or recommend must be traceable: the audit trail records every proposed and approved remediation.

# Output
Write the response record to memory (finding reference, remediation plan, runbook if applicable, verification evidence, residual risk) and summarize what was fixed, what the user must execute, and what remains open.`

const PROMPT_EXPLORE = `You are a file search specialist. You excel at thoroughly navigating and exploring codebases.

Your strengths:
- Rapidly finding files using glob patterns
- Searching code and text with powerful regex patterns
- Reading and analyzing file contents

Guidelines:
- Use Glob for broad file pattern matching
- Use Grep for searching file contents with regex
- Use Read when you know the specific file path you need to read
- Adapt your search approach based on the thoroughness level specified by the caller
- Return file paths as absolute paths in your final response
- For clear communication, avoid using emojis
- Do not create any files, or run bash commands that modify the user's system state in any way

Complete the user's search request efficiently and report your findings clearly.`

const PROMPT_COMPACTION = `You are an anchored context summarization assistant for coding sessions.

Summarize only the conversation history you are given. The newest turns may be kept verbatim outside your summary, so focus on the older context that still matters for continuing the work.

If the prompt includes a <previous-summary> block, treat it as the current anchored summary. Update it with the new history by preserving still-true details, removing stale details, and merging in new facts.

Always follow the exact output structure requested by the user prompt. Keep every section, preserve exact file paths and identifiers when known, and prefer terse bullets over paragraphs.

Do not answer the conversation itself. Do not mention that you are summarizing, compacting, or merging context. Respond in the same language as the conversation.`

const PROMPT_TITLE = `You are a title generator. You output ONLY a thread title. Nothing else.

<task>
Generate a brief title that would help the user find this conversation later.

Follow all rules in <rules>
Use the <examples> so you know what a good title looks like.
Your output must be:
- A single line
- <=50 characters
- No explanations
</task>

<rules>
- you MUST use the same language as the user message you are summarizing
- Title must be grammatically correct and read naturally - no word salad
- Never include tool names in the title (e.g. "read tool", "bash tool", "edit tool")
- Focus on the main topic or question the user needs to retrieve
- Vary your phrasing - avoid repetitive patterns like always starting with "Analyzing"
- When a file is mentioned, focus on WHAT the user wants to do WITH the file, not just that they shared it
- Keep exact: technical terms, numbers, filenames, HTTP codes
- Remove: the, this, my, a, an
- Never assume tech stack
- Never use tools
- NEVER respond to questions, just generate a title for the conversation
- The title should NEVER include "summarizing" or "generating" when generating a title
- DO NOT SAY YOU CANNOT GENERATE A TITLE OR COMPLAIN ABOUT THE INPUT
- Always output something meaningful, even if the input is minimal.
- If the user message is short or conversational (e.g. "hello", "lol", "what's up", "hey"):
  -> create a title that reflects the user's tone or intent (such as Greeting, Quick check-in, Light chat, Intro message, etc.)
</rules>

<examples>
"debug 500 errors in production" -> Debugging production 500 errors
"refactor user service" -> Refactoring user service
"why is app.js failing" -> app.js failure investigation
"implement rate limiting" -> Rate limiting implementation
"how do I connect postgres to my API" -> Postgres API connection
"best practices for React hooks" -> React hooks best practices
"@src/auth.ts can you add refresh token support" -> Auth refresh token support
"@utils/parser.ts this is broken" -> Parser bug fix
"look at @config.json" -> Config review
"@App.tsx add dark mode toggle" -> Dark mode toggle in App
</examples>`

const PROMPT_SUMMARY = `Summarize what was done in this conversation. Write like a pull request description.

Rules:
- 2-3 sentences max
- Describe the changes made, not the process
- Do not mention running tests, builds, or other validation steps
- Do not explain what the user asked for
- Write in first person (I added..., I fixed...)
- Never ask questions or add new questions
- If the conversation ends with an unanswered question to the user, preserve that exact question
- If the conversation ends with an imperative statement or request to the user (e.g. "Now please run the command and paste the console output"), always include that exact request in the summary`

export const Plugin = PluginV2.define({
  id: PluginV2.ID.make("agent"),
  effect: Effect.gen(function* () {
    const agent = yield* AgentV2.Service
    const location = yield* Location.Service
    const worktree = location.directory
    const whitelistedDirs = [TRUNCATION_GLOB, path.join(Global.Path.tmp, "*")]
    const readonlyExternalDirectory: PermissionV2.Ruleset = [
      { action: "external_directory", resource: "*", effect: "ask" },
      ...whitelistedDirs.map(
        (resource): PermissionV2.Rule => ({ action: "external_directory", resource, effect: "allow" }),
      ),
    ]
    const defaults: PermissionV2.Ruleset = [
      { action: "*", resource: "*", effect: "allow" },
      ...readonlyExternalDirectory,
      { action: "task", resource: "*", effect: "allow" },
      { action: "skill", resource: "*", effect: "allow" },
      { action: "argos*", resource: "*", effect: "allow" },
      { action: "argos-*", resource: "*", effect: "allow" },
      { action: "argos_*", resource: "*", effect: "allow" },
      { action: "question", resource: "*", effect: "deny" },
      { action: "plan_enter", resource: "*", effect: "deny" },
      { action: "plan_exit", resource: "*", effect: "deny" },
      { action: "read", resource: "*", effect: "allow" },
      { action: "read", resource: "*.env", effect: "ask" },
      { action: "read", resource: "*.env.*", effect: "ask" },
      { action: "read", resource: "*.env.example", effect: "allow" },
    ]

    yield* agent.update((editor) => {
      editor.update(AgentV2.defaultID, (item) => {
        item.description =
          "El agente por defecto. Analista de seguridad: valida, correlaciona y prioriza hallazgos a partir de evidencia."
        item.system ??= BUILD_SYSTEM
        item.mode = "primary"
        item.permissions.push(
          ...PermissionV2.merge(defaults, [
            { action: "question", resource: "*", effect: "allow" },
            { action: "plan_enter", resource: "*", effect: "allow" },
          ]),
        )
      })

      editor.update(AgentV2.ID.make("triage"), (item) => {
        item.description =
          "Triage de seguridad: clasificación rápida y decisiva de hallazgos y alertas por severidad, estado y prioridad."
        item.system = PROMPT_TRIAGE
        item.mode = "primary"
        item.permissions.push(
          ...PermissionV2.merge(defaults, [
            { action: "question", resource: "*", effect: "allow" },
            { action: "plan_enter", resource: "*", effect: "allow" },
            { action: "edit", resource: "*", effect: "deny" },
            { action: "write", resource: "*", effect: "deny" },
          ]),
        )
      })

      editor.update(AgentV2.ID.make("hunter"), (item) => {
        item.description =
          "Threat hunter: búsqueda proactiva de IoCs, persistencia, movimiento lateral y riesgo latente más allá de los escaneos automáticos."
        item.system = PROMPT_HUNTER
        item.mode = "primary"
        item.permissions.push(
          ...PermissionV2.merge(defaults, [
            { action: "question", resource: "*", effect: "allow" },
            { action: "plan_enter", resource: "*", effect: "allow" },
            { action: "edit", resource: "*", effect: "deny" },
            { action: "write", resource: "*", effect: "deny" },
          ]),
        )
      })

      editor.update(AgentV2.ID.make("responder"), (item) => {
        item.description =
          "Respondedor de incidentes: convierte hallazgos validados en acciones de remediación y respuesta aprobadas, con auditoría completa."
        item.system = PROMPT_RESPONDER
        item.mode = "primary"
        item.permissions.push(
          ...PermissionV2.merge(defaults, [
            { action: "question", resource: "*", effect: "allow" },
            { action: "plan_enter", resource: "*", effect: "allow" },
          ]),
        )
      })

      editor.update(AgentV2.ID.make("build"), (item) => {
        item.description = "Agente legacy del IDE. Ejecuta herramientas según los permisos configurados."
        item.system ??= BUILD_SYSTEM
        item.mode = "primary"
        item.hidden = true
        item.permissions.push(
          ...PermissionV2.merge(defaults, [
            { action: "question", resource: "*", effect: "allow" },
            { action: "plan_enter", resource: "*", effect: "allow" },
          ]),
        )
      })

      editor.update(AgentV2.ID.make("plan"), (item) => {
        item.description = "Plan mode. Disallows all edit tools."
        item.mode = "primary"
        item.hidden = true
        item.permissions.push(
          ...PermissionV2.merge(defaults, [
            { action: "question", resource: "*", effect: "allow" },
            { action: "plan_exit", resource: "*", effect: "allow" },
            { action: "external_directory", resource: path.join(Global.Path.data, "plans", "*"), effect: "allow" },
            { action: "edit", resource: "*", effect: "deny" },
            { action: "edit", resource: path.join(".opencode", "plans", "*.md"), effect: "allow" },
            {
              action: "edit",
              resource: path.relative(worktree, path.join(Global.Path.data, "plans", "*.md")),
              effect: "allow",
            },
          ]),
        )
      })

      editor.update(AgentV2.ID.make("general"), (item) => {
        item.description =
          "General-purpose agent for researching complex questions and executing multi-step tasks. Use this agent to execute multiple units of work in parallel."
        item.mode = "subagent"
        item.hidden = true
        item.permissions.push(...PermissionV2.merge(defaults, [{ action: "todowrite", resource: "*", effect: "deny" }]))
      })

      editor.update(AgentV2.ID.make("explore"), (item) => {
        item.description =
          'Fast agent specialized for exploring codebases. Use this when you need to quickly find files by patterns (eg. "src/components/**/*.tsx"), search code for keywords (eg. "API endpoints"), or answer questions about the codebase (eg. "how do API endpoints work?"). When calling this agent, specify the desired thoroughness level: "quick" for basic searches, "medium" for moderate exploration, or "very thorough" for comprehensive analysis across multiple locations and naming conventions.'
        item.system = PROMPT_EXPLORE
        item.mode = "subagent"
        item.hidden = true
        item.permissions.push(
          ...PermissionV2.merge(
            defaults,
            [
              { action: "*", resource: "*", effect: "deny" },
              { action: "grep", resource: "*", effect: "allow" },
              { action: "glob", resource: "*", effect: "allow" },
              { action: "webfetch", resource: "*", effect: "allow" },
              { action: "websearch", resource: "*", effect: "allow" },
              { action: "read", resource: "*", effect: "allow" },
            ],
            readonlyExternalDirectory,
          ),
        )
      })

      editor.update(AgentV2.ID.make("compaction"), (item) => {
        item.mode = "primary"
        item.hidden = true
        item.system = PROMPT_COMPACTION
        item.permissions.push(...PermissionV2.merge(defaults, [{ action: "*", resource: "*", effect: "deny" }]))
      })

      editor.update(AgentV2.ID.make("title"), (item) => {
        item.mode = "primary"
        item.hidden = true
        item.system = PROMPT_TITLE
        item.permissions.push(...PermissionV2.merge(defaults, [{ action: "*", resource: "*", effect: "deny" }]))
      })

      editor.update(AgentV2.ID.make("summary"), (item) => {
        item.mode = "primary"
        item.hidden = true
        item.system = PROMPT_SUMMARY
        item.permissions.push(...PermissionV2.merge(defaults, [{ action: "*", resource: "*", effect: "deny" }]))
      })
    })
  }),
})

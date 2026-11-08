import * as InstanceState from "@/effect/instance-state"
import { Project } from "@/project/project"
import { ProjectV2 } from "@argos/core/project"
import type { FindingTable } from "@argos/core/security/sql"
import { dispatchFindingsWebhook } from "@argos/core/security/webhook"
import { Effect } from "effect"
import { HttpApiBuilder } from "effect/unstable/httpapi"
import { InstanceHttpApi } from "../api"
import { ProjectNotFoundError } from "../errors"
import { markInstanceForReload } from "../lifecycle"

export const projectHandlers = HttpApiBuilder.group(InstanceHttpApi, "project", (handlers) =>
  Effect.gen(function* () {
    const svc = yield* Project.Service
    const project = yield* ProjectV2.Service

    const list = Effect.fn("ProjectHttpApi.list")(function* () {
      return yield* svc.list()
    })

    const current = Effect.fn("ProjectHttpApi.current")(function* () {
      return (yield* InstanceState.context).project
    })

    const initGit = Effect.fn("ProjectHttpApi.initGit")(function* () {
      const ctx = yield* InstanceState.context
      const next = yield* svc.initGit({ directory: ctx.directory, project: ctx.project })
      if (next.id === ctx.project.id && next.vcs === ctx.project.vcs && next.worktree === ctx.project.worktree)
        return next
      yield* markInstanceForReload(ctx, {
        directory: ctx.directory,
        worktree: ctx.directory,
        project: next,
      })
      return next
    })

    const update = Effect.fn("ProjectHttpApi.update")(function* (ctx: {
      params: { projectID: ProjectV2.ID }
      payload: any
      query: { directory?: string; workspace?: string }
    }) {
      const directory = ctx.payload.directory ?? ctx.query.directory
      return yield* svc.update({ ...ctx.payload, directory, projectID: ctx.params.projectID } as any).pipe(
        Effect.catchTag("Project.NotFoundError", (error) =>
          Effect.fail(
            new ProjectNotFoundError({
              projectID: error.projectID,
              message: `Project not found: ${error.projectID}`,
            }),
          ),
        ),
      )
    })

    const directories = Effect.fn("ProjectHttpApi.directories")((ctx: { params: { projectID: ProjectV2.ID } }) =>
      project.directories({ projectID: ctx.params.projectID }),
    )

    const webhookTest = Effect.fn("ProjectHttpApi.webhookTest")(function* (ctx: {
      params: { projectID: ProjectV2.ID }
      payload: { url: string; secret?: string; format?: "generic" | "jira" | "slack" }
    }) {
      const now = Date.now()
      const testFinding: typeof FindingTable.$inferSelect = {
        id: "test-finding",
        session_id: "test-session",
        project_id: ctx.params.projectID,
        fingerprint: "test-finding",
        title: "Argos — hallazgo de prueba",
        severity: "info",
        status: "open",
        source: "memory",
        source_tool: null,
        agent: null,
        target: null,
        cwe: null,
        vector: null,
        evidence: { note: "Este es un envío de prueba desde la configuración de webhook de Argos." },
        remediation: null,
        tags: ["test"],
        raw: null,
        attack_techniques: null,
        iocs: null,
        cvss_input: null,
        enrichment: null,
        enriched_at: null,
        poc: null,
        confidence: "possible",
        case_id: null,
        rule_id: null,
        owasp: null,
        references: null,
        validation_status: "detected",
        validation_evidence: null,
        validated_at: null,
        time_created: now,
        time_updated: now,
      }
      const result = yield* dispatchFindingsWebhook([testFinding], {
        url: ctx.payload.url,
        secret: ctx.payload.secret,
        format: ctx.payload.format,
      })
      return { ok: result.ok, statusCode: result.statusCode, responseBody: result.responseBody }
    })

    return handlers
      .handle("list", list)
      .handle("current", current)
      .handle("initGit", initGit)
      .handle("update", update)
      .handle("directories", directories)
      .handle("webhookTest", webhookTest)
  }),
)

import { exportAll, exportSessions, type ExportFormat } from "@argos/core/security/export"
import { Effect } from "effect"
import { HttpApiBuilder } from "effect/unstable/httpapi"
import { InstanceHttpApi } from "../api"
import type { ReportMetaPayload } from "../groups/report"

export const reportHandlers = HttpApiBuilder.group(InstanceHttpApi, "report", (handlers) =>
  Effect.gen(function* () {
    const exportReport = Effect.fn("ReportHttpApi.export")(function* (ctx: {
      params: { sessionID: string }
      payload: { format: ExportFormat; meta?: typeof ReportMetaPayload.Type; sessionIDs?: readonly string[] }
    }) {
      const sessionIDs = (ctx.payload.sessionIDs ?? []).filter(Boolean)
      const artifact =
        sessionIDs.length > 0
          ? yield* exportSessions([...sessionIDs], ctx.payload.format, { meta: ctx.payload.meta })
          : yield* exportAll(ctx.params.sessionID, ctx.payload.format, { meta: ctx.payload.meta })
      const bytes = artifact.bytes ?? new TextEncoder().encode(artifact.text ?? "")
      return {
        format: artifact.format,
        filename: artifact.filename,
        mimeType: artifact.mimeType,
        contentBase64: Buffer.from(bytes).toString("base64"),
        sha256: artifact.sha256,
        contentHash: artifact.contentHash,
      }
    })

    return handlers.handle("export", exportReport)
  }),
)

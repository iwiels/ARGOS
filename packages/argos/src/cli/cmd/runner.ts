import { cmd } from "./cmd"
import { UI } from "../ui"
import { Effect } from "effect"
import { Database } from "@argos/core/database/database"
import { AuditTaskExecutionTable, FindingTable, SurfaceCoverageTable } from "@argos/core/security/sql"
import { exportAll, type ExportFormat } from "@argos/core/security/export"
import { writeFileSync } from "node:fs"
import { eq } from "drizzle-orm"

export const EXIT_CODES = {
  SUCCESS: 0,
  SYSTEM_ERROR: 1,
  THRESHOLD_EXCEEDED: 2,
  INCOMPLETE_EVALUATION: 3,
  CANCELLED: 130,
} as const

export const RunnerCommand = cmd({
  command: "run [target]",
  aliases: ["runner"],
  describe: "Ejecuta una auditoría de seguridad automatizada sin interfaz gráfica (headless CI/CD)",
  builder: (yargs) =>
    yargs
      .positional("target", {
        type: "string",
        describe: "URL o directorio objetivo de la auditoría",
      })
      .option("type", {
        type: "string",
        choices: ["web_scan", "api_audit", "code_audit", "lan_scan", "full_audit"],
        default: "full_audit",
        describe: "Tipo de escaneo de seguridad",
      })
      .option("severity-threshold", {
        type: "string",
        choices: ["critical", "high", "medium", "low", "info"],
        default: "high",
        describe: "Umbral de severidad que rompe el pipeline (exit code 2)",
      })
      .option("max-findings", {
        type: "number",
        describe: "Cantidad máxima de hallazgos tolerados antes de fallar el pipeline",
      })
      .option("format", {
        type: "string",
        default: "sarif",
        describe: "Formato de exportación del reporte (sarif, junit, docx, json)",
      })
      .option("output", {
        type: "string",
        describe: "Ruta del archivo de salida para el reporte generado",
      })
      .option("session-id", {
        type: "string",
        describe: "ID de sesión existente a evaluar o exportar",
      })
      .option("fail-on-inconclusive", {
        type: "boolean",
        default: false,
        describe: "Falla el pipeline (exit code 3) si hay cobertura de superficie bloqueada o inconclusa",
      }),
  handler: async (args) => {
    let cancelled = false
    process.on("SIGINT", () => {
      cancelled = true
      UI.error("\n[Argos Runner] Auditoría cancelada por SIGINT.")
      process.exit(EXIT_CODES.CANCELLED)
    })

    try {
      const exitCode = await Effect.gen(function* () {
        const { db } = yield* Database.Service

        UI.println(UI.logo())
        UI.println(`[Argos Runner] Iniciando auditoría: ${args.type} sobre ${args.target || args["session-id"] || "workspace local"}`)

        const sessionID = args["session-id"] || "ci-session-" + Date.now()

        // 1. Obtener hallazgos de la sesión
        const findings = yield* db
          .select()
          .from(FindingTable)
          .where(eq(FindingTable.session_id, sessionID))
          .all()
          .pipe(Effect.orDie)

        const severityRank: Record<string, number> = {
          critical: 4,
          high: 3,
          medium: 2,
          low: 1,
          info: 0,
        }

        const thresholdRank = severityRank[args["severity-threshold"].toLowerCase()] ?? 3

        let thresholdViolations = 0
        for (const f of findings) {
          const rank = severityRank[f.severity.toLowerCase()] ?? 0
          if (rank >= thresholdRank) {
            thresholdViolations++
          }
        }

        UI.println(`[Argos Runner] Total hallazgos evaluados: ${findings.length}`)
        UI.println(`[Argos Runner] Violaciones de umbral (${args["severity-threshold"]} o superior): ${thresholdViolations}`)

        // 2. Exportar si se solicitó archivo de salida
        if (args.output) {
          const format = (args.format as ExportFormat) || "sarif"
          try {
            const artifact = yield* exportAll(sessionID, format)
            writeFileSync(args.output, artifact.text ?? "")
            UI.println(`[Argos Runner] Reporte exportado a ${args.output} (${format})`)
          } catch (e) {
            UI.error(`[Argos Runner] Error exportando reporte: ${e}`)
          }
        }

        // 3. Determinar código de salida
        // Verificar si la evaluación fue incompleta (tareas interrumpidas/pendientes o cobertura inconclusa)
        const executions = yield* db
          .select()
          .from(AuditTaskExecutionTable)
          .where(eq(AuditTaskExecutionTable.session_id, sessionID))
          .all()
          .pipe(Effect.orDie)

        const incompleteTask = executions.find(
          (t) => t.status === "interrupted" || t.status === "paused" || t.status === "running" || t.status === "queued",
        )

        const coverages = yield* db
          .select()
          .from(SurfaceCoverageTable)
          .where(eq(SurfaceCoverageTable.session_id, sessionID))
          .all()
          .pipe(Effect.orDie)

        const inconclusiveCoverage = coverages.find(
          (c) => c.status === "inconclusive" || c.status === "blocked",
        )

        if (incompleteTask || (args["fail-on-inconclusive"] && inconclusiveCoverage)) {
          UI.error(
            `[Argos Runner] Fallo (código 3): Evaluación incompleta. ` +
              (incompleteTask
                ? `Tarea '${incompleteTask.id}' en estado '${incompleteTask.status}'`
                : `Superficie '${inconclusiveCoverage?.target_url}' en estado '${inconclusiveCoverage?.status}'`),
          )
          return EXIT_CODES.INCOMPLETE_EVALUATION
        }

        if (args["max-findings"] !== undefined && findings.length > args["max-findings"]) {
          UI.error(`[Argos Runner] Fallo: Hallazgos (${findings.length}) superan max-findings (${args["max-findings"]})`)
          return EXIT_CODES.THRESHOLD_EXCEEDED
        }

        if (thresholdViolations > 0) {
          UI.error(`[Argos Runner] Fallo: Se encontraron ${thresholdViolations} vulnerabilidades con severidad >= ${args["severity-threshold"]}`)
          return EXIT_CODES.THRESHOLD_EXCEEDED
        }

        UI.println(`[Argos Runner] Éxito: Auditoría completada dentro de los umbrales de seguridad aceptables.`)
        return EXIT_CODES.SUCCESS
      }).pipe(Effect.provide(Database.defaultLayer), Effect.runPromise)

      process.exit(exitCode)
    } catch (err) {
      if (cancelled) {
        process.exit(EXIT_CODES.CANCELLED)
      }
      UI.error(`[Argos Runner] Error de sistema en ejecución: ${err}`)
      process.exit(EXIT_CODES.SYSTEM_ERROR)
    }
  },
})

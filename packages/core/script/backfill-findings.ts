/**
 * Backfill de findings: re-ingesta los `argos_memory_save` históricos que
 * los agentes guardaron SIN `kind: "finding"` (comportamiento real previo al
 * fix del contrato tolerante en security/ingest.ts).
 *
 * Uso:  bun run script/backfill-findings.ts [--dry-run]
 *
 * 1. Escanea la tabla `part` en busca de tool parts `argos_memory_save`
 *    completados que cumplan el criterio de hallazgo (isFindingInput).
 * 2. Los re-ingesta en `security_finding` (dedup por fingerprint por sesión).
 * 3. Recomputa el estado de compliance de los proyectos afectados.
 *
 * Con `--dry-run` solo reporta cuántos hallazgos se re-ingestarían sin
 * escribir en la BD.
 */
import { eq } from "drizzle-orm"
import { Effect, Layer } from "effect"
import { Database } from "../src/database/database"
import { Compliance } from "../src/compliance/service"
import { ingestToolPart, isFindingInput } from "../src/security/ingest"
import { FindingTable } from "../src/security/sql"
import { PartTable } from "../src/session/sql"

const MEMORY_SAVE_TOOLS = new Set(["argos_memory_save"])
const DRY_RUN = process.argv.includes("--dry-run")
// Ruta de la DB a procesar. Por defecto usa la del canal de instalación;
// se puede apuntar a otra (p.ej. la DB del canal "latest") con
// `OPENCODE_DB=...` o un arg posicional `--db <path>`. Uso sugerido:
//   bun run script/backfill-findings.ts --dry-run
//   bun run script/backfill-findings.ts
//   OPENCODE_DB='C:/Users/<user>/.local/share/opencode/opencode.db' bun run script/backfill-findings.ts
const dbArg = process.argv[process.argv.indexOf("--db") + 1]
const dbPath = dbArg ?? process.env.OPENCODE_DB

const program = Effect.gen(function* () {
  const { db } = yield* Database.Service
  const parts = yield* db
    .select({ id: PartTable.id, session_id: PartTable.session_id, data: PartTable.data })
    .from(PartTable)
    .all()
    .pipe(Effect.orDie)

  let ingested = 0
  let skipped = 0
  const before = yield* db.select({ total: FindingTable.id }).from(FindingTable).all().pipe(Effect.orDie)

  for (const part of parts) {
    const data = part.data as Record<string, unknown>
    if (data.type !== "tool" || typeof data.tool !== "string" || !MEMORY_SAVE_TOOLS.has(data.tool)) continue
    const state = data.state as { status?: string; input?: Record<string, unknown> } | undefined
    if (!state || state.status !== "completed" || !state.input) continue
    if (!isFindingInput(state.input)) {
      skipped++
      continue
    }
    if (DRY_RUN) {
      ingested++
      continue
    }
    const candidate = {
      sessionID: part.session_id,
      type: data.type,
      tool: data.tool,
      state,
    }
    yield* ingestToolPart(db, candidate as never)
    ingested++
  }

  const after = yield* db.select({ total: FindingTable.id }).from(FindingTable).all().pipe(Effect.orDie)

  console.log(`memory_save parts escaneados: ${parts.length}`)
  console.log(`hallazgos re-ingestados: ${ingested}`)
  console.log(`parts no-hallazgo (kind reservado o sin title+severity): ${skipped}`)
  console.log(`security_finding: ${before.length} → ${after.length}`)

  if (DRY_RUN || ingested === 0) return

  const compliance = yield* Compliance.Service
  yield* compliance.sweepAll()
  console.log("compliance recomputado para los proyectos con hallazgos")
})

const dbLayer = dbPath ? Database.layerFromPath(dbPath) : Database.defaultLayer
const env = Layer.mergeAll(dbLayer, Compliance.defaultLayer.pipe(Layer.provide(dbLayer)))
Effect.runPromise(Effect.provide(program, env))
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("FAIL:", error)
    process.exit(1)
  })

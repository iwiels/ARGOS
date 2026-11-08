import { Effect } from "effect"
import type { DatabaseMigration } from "../migration"

export default {
  id: "20261021000000_finding_fingerprint_v2",
  up(tx) {
    return Effect.gen(function* () {
      // El fingerprint v2 es taxonómico (cwe + target + vector), así que la
      // búsqueda por taxonomía es el acceso caliente del ingest y de la
      // reconciliación de agentes.
      //
      // Los fingerprints YA persistidos NO se recalculan: la fila histórica
      // (v1, identidad por título) se reconoce por taxonomía y se actualiza
      // en el sitio, así que no aparece duplicada ni colisiona con el
      // índice único de (session_id, fingerprint).
      yield* tx.run(
        `CREATE INDEX IF NOT EXISTS \`security_finding_session_cwe_target_idx\` ON \`security_finding\` (\`session_id\`, \`cwe\`, \`target\`);`,
      )
    })
  },
} satisfies DatabaseMigration.Migration

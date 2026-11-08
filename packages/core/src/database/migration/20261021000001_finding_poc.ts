import { Effect } from "effect"
import type { DatabaseMigration } from "../migration"

/**
 * Proof of concept del hallazgo.
 *
 * La columna guarda la petición que reproduce el vector y el matcher que
 * decide si dejó de reproducirse: es lo que permite re-verificar el hallazgo
 * con evidencia en lugar de con una suposición.
 */
export default {
  id: "20261021000001_finding_poc",
  up(tx) {
    return Effect.gen(function* () {
      yield* tx.run(`ALTER TABLE \`security_finding\` ADD \`poc\` text;`)
    })
  },
} satisfies DatabaseMigration.Migration

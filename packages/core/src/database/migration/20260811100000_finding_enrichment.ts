import { Effect } from "effect"
import type { DatabaseMigration } from "../migration"

export default {
  id: "20260811100000_finding_enrichment",
  up(tx) {
    return Effect.gen(function* () {
      // El driver ejecuta solo la primera sentencia de un string multi-sentencia.
      yield* tx.run("ALTER TABLE `security_finding` ADD COLUMN `attack_techniques` text")
      yield* tx.run("ALTER TABLE `security_finding` ADD COLUMN `iocs` text")
      yield* tx.run("ALTER TABLE `security_finding` ADD COLUMN `enrichment` text")
      yield* tx.run("ALTER TABLE `security_finding` ADD COLUMN `enriched_at` integer")
    })
  },
} satisfies DatabaseMigration.Migration

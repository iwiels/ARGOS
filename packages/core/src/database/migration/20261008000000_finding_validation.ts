import { Effect } from "effect"
import type { DatabaseMigration } from "../migration"

export default {
  id: "20261008000000_finding_validation",
  up(tx) {
    return Effect.gen(function* () {
      yield* tx.run(`ALTER TABLE \`security_finding\` ADD \`validation_status\` text DEFAULT 'detected';`)
      yield* tx.run(`ALTER TABLE \`security_finding\` ADD \`validation_evidence\` text;`)
      yield* tx.run(`ALTER TABLE \`security_finding\` ADD \`validated_at\` integer;`)
    })
  },
} satisfies DatabaseMigration.Migration

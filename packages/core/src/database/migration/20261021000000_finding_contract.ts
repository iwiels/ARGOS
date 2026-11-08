import { Effect } from "effect"
import type { DatabaseMigration } from "../migration"

export default {
  id: "20261021000000_finding_contract",
  up(tx) {
    return Effect.gen(function* () {
      yield* tx.run(`ALTER TABLE \`security_finding\` ADD \`confidence\` text DEFAULT 'possible';`)
      yield* tx.run(`ALTER TABLE \`security_finding\` ADD \`rule_id\` text;`)
      yield* tx.run(`ALTER TABLE \`security_finding\` ADD \`owasp\` text;`)
      yield* tx.run(`ALTER TABLE \`security_finding\` ADD \`references\` text;`)
      // Las filas anteriores a la contract no declaran confianza: "possible"
      // es el valor menos comprometedor del vocabulario cerrado.
      yield* tx.run(`UPDATE \`security_finding\` SET \`confidence\` = 'possible' WHERE \`confidence\` IS NULL;`)
      yield* tx.run(
        `CREATE INDEX IF NOT EXISTS \`security_finding_session_cwe_idx\` ON \`security_finding\` (\`session_id\`, \`cwe\`);`,
      )
    })
  },
} satisfies DatabaseMigration.Migration

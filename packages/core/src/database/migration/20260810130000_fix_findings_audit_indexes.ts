import { Effect } from "effect"
import type { DatabaseMigration } from "../migration"

// Reparación idempotente: versiones previas de las migraciones security_findings
// y audit_log no creaban los índices/triggers (el driver solo ejecutaba la primera
// sentencia de un string multi-sentencia). Con IF NOT EXISTS esto es seguro de
// correr en cualquier estado de base de datos.
export default {
  id: "20260810130000_fix_findings_audit_indexes",
  up(tx) {
    return Effect.gen(function* () {
      yield* tx.run(`
        CREATE UNIQUE INDEX IF NOT EXISTS \`security_finding_session_fingerprint_idx\`
          ON \`security_finding\` (\`session_id\`, \`fingerprint\`)
      `)
      yield* tx.run("CREATE INDEX IF NOT EXISTS `security_finding_project_idx` ON `security_finding` (`project_id`)")
      yield* tx.run(
        "CREATE INDEX IF NOT EXISTS `security_finding_session_severity_idx` ON `security_finding` (`session_id`, `severity`)",
      )
      yield* tx.run(
        "CREATE INDEX IF NOT EXISTS `security_finding_session_updated_idx` ON `security_finding` (`session_id`, `time_updated`)",
      )
      yield* tx.run("CREATE INDEX IF NOT EXISTS `audit_log_session_idx` ON `audit_log` (`session_id`)")
      yield* tx.run("CREATE INDEX IF NOT EXISTS `audit_log_time_idx` ON `audit_log` (`time_created`)")
      yield* tx.run(`
        CREATE TRIGGER IF NOT EXISTS \`audit_log_immutable_update\` BEFORE UPDATE ON \`audit_log\`
        BEGIN
          SELECT RAISE(ABORT, 'audit_log is immutable: UPDATE not allowed');
        END
      `)
      yield* tx.run(`
        CREATE TRIGGER IF NOT EXISTS \`audit_log_immutable_delete\` BEFORE DELETE ON \`audit_log\`
        BEGIN
          SELECT RAISE(ABORT, 'audit_log is immutable: DELETE not allowed');
        END
      `)
    })
  },
} satisfies DatabaseMigration.Migration

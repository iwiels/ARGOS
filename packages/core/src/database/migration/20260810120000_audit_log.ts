import { Effect } from "effect"
import type { DatabaseMigration } from "../migration"

export default {
  id: "20260810120000_audit_log",
  up(tx) {
    return Effect.gen(function* () {
      // El driver ejecuta solo la primera sentencia de un string multi-sentencia:
      // cada statement debe ir en su propio run.
      yield* tx.run(`
        CREATE TABLE \`audit_log\` (
          \`id\` text PRIMARY KEY NOT NULL,
          \`seq\` integer NOT NULL UNIQUE,
          \`project_id\` text,
          \`session_id\` text,
          \`event_type\` text NOT NULL,
          \`action\` text NOT NULL,
          \`agent\` text,
          \`target\` text,
          \`summary\` text NOT NULL,
          \`payload\` text NOT NULL DEFAULT '{}',
          \`prev_hash\` text NOT NULL,
          \`hash\` text NOT NULL,
          \`time_created\` integer NOT NULL
        )
      `)
      yield* tx.run("CREATE INDEX `audit_log_session_idx` ON `audit_log` (`session_id`)")
      yield* tx.run("CREATE INDEX `audit_log_time_idx` ON `audit_log` (`time_created`)")
      // Inmutabilidad: la cadena de hash solo tiene sentido si la tabla no se puede
      // modificar ni borrar desde la aplicación. Cualquier escritura directa a SQLite
      // queda detectada por Audit.verify() al romper la cadena.
      yield* tx.run(`
        CREATE TRIGGER \`audit_log_immutable_update\` BEFORE UPDATE ON \`audit_log\`
        BEGIN
          SELECT RAISE(ABORT, 'audit_log is immutable: UPDATE not allowed');
        END
      `)
      yield* tx.run(`
        CREATE TRIGGER \`audit_log_immutable_delete\` BEFORE DELETE ON \`audit_log\`
        BEGIN
          SELECT RAISE(ABORT, 'audit_log is immutable: DELETE not allowed');
        END
      `)
    })
  },
} satisfies DatabaseMigration.Migration

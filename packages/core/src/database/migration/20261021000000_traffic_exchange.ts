import { Effect } from "effect"
import type { DatabaseMigration } from "../migration"

/**
 * Índice de lectura del tráfico HTTP de la sesión.
 *
 * La fuente de verdad es el store en disco que escribe el binario Go
 * (`<memoryDir>/traffic/<sessionID>/*.json`); esta tabla es el caché que la
 * UI consulta. El reconciliador de `packages/core/src/security/traffic.ts` la
 * puebla desde el store.
 */
export default {
  id: "20261021000000_traffic_exchange",
  up(tx) {
    return Effect.gen(function* () {
      yield* tx.run(`
        CREATE TABLE IF NOT EXISTS \`traffic_exchange\` (
          \`id\` text PRIMARY KEY NOT NULL,
          \`session_id\` text NOT NULL REFERENCES \`session\`(\`id\`) ON DELETE cascade,
          \`project_id\` text NOT NULL REFERENCES \`project\`(\`id\`) ON DELETE cascade,
          \`timestamp\` integer NOT NULL,
          \`method\` text NOT NULL,
          \`url\` text NOT NULL,
          \`host\` text,
          \`status\` integer NOT NULL,
          \`duration_ms\` integer DEFAULT 0 NOT NULL,
          \`source_tool\` text,
          \`target\` text,
          \`scope_allowed\` integer DEFAULT false NOT NULL,
          \`request_headers\` text,
          \`response_headers\` text,
          \`request_body\` text,
          \`response_body\` text,
          \`request_body_sha256\` text,
          \`response_body_sha256\` text,
          \`request_body_size\` integer DEFAULT 0 NOT NULL,
          \`response_body_size\` integer DEFAULT 0 NOT NULL,
          \`time_created\` integer NOT NULL,
          FOREIGN KEY (\`session_id\`) REFERENCES \`session\`(\`id\`) ON DELETE CASCADE,
          FOREIGN KEY (\`project_id\`) REFERENCES \`project\`(\`id\`) ON DELETE CASCADE
        );
      `)
      yield* tx.run(
        `CREATE INDEX IF NOT EXISTS \`traffic_exchange_session_idx\` ON \`traffic_exchange\` (\`session_id\`);`,
      )
      yield* tx.run(
        `CREATE INDEX IF NOT EXISTS \`traffic_exchange_session_time_idx\` ON \`traffic_exchange\` (\`session_id\`, \`timestamp\`);`,
      )
      yield* tx.run(
        `CREATE INDEX IF NOT EXISTS \`traffic_exchange_session_status_idx\` ON \`traffic_exchange\` (\`session_id\`, \`status\`);`,
      )
    })
  },
} satisfies DatabaseMigration.Migration

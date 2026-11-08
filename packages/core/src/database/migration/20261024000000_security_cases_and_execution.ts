import { Effect } from "effect"
import type { DatabaseMigration } from "../migration"

export default {
  id: "20261024000000_security_cases_and_execution",
  up(tx) {
    return Effect.gen(function* () {
      yield* tx.run(`
        CREATE TABLE IF NOT EXISTS \`security_case\` (
          \`id\` text PRIMARY KEY NOT NULL,
          \`project_id\` text NOT NULL,
          \`fingerprint\` text NOT NULL,
          \`context_type\` text DEFAULT 'endpoint_param' NOT NULL,
          \`title\` text NOT NULL,
          \`severity\` text NOT NULL,
          \`status\` text DEFAULT 'open' NOT NULL,
          \`cwe\` text,
          \`target\` text,
          \`vector\` text,
          \`first_seen_at\` integer NOT NULL,
          \`last_seen_at\` integer NOT NULL,
          \`remediated_at\` integer,
          \`merged_into_id\` text,
          \`merge_reason\` text,
          \`sla_due_at\` integer,
          \`sla_status\` text,
          \`accepted_risk_expires_at\` integer,
          \`accepted_risk_reason\` text,
          \`time_created\` integer NOT NULL,
          \`time_updated\` integer NOT NULL,
          CONSTRAINT \`fk_security_case_project\` FOREIGN KEY (\`project_id\`) REFERENCES \`project\`(\`id\`) ON DELETE CASCADE
        );
      `)
      yield* tx.run(
        `CREATE UNIQUE INDEX IF NOT EXISTS \`security_case_project_fingerprint_idx\` ON \`security_case\` (\`project_id\`, \`fingerprint\`);`,
      )
      yield* tx.run(
        `CREATE INDEX IF NOT EXISTS \`security_case_project_status_idx\` ON \`security_case\` (\`project_id\`, \`status\`);`,
      )
      yield* tx.run(
        `CREATE INDEX IF NOT EXISTS \`security_case_project_severity_idx\` ON \`security_case\` (\`project_id\`, \`severity\`);`,
      )

      yield* tx.run(`
        CREATE TABLE IF NOT EXISTS \`security_case_observation\` (
          \`id\` text PRIMARY KEY NOT NULL,
          \`case_id\` text NOT NULL,
          \`finding_id\` text,
          \`session_id\` text NOT NULL,
          \`project_id\` text NOT NULL,
          \`run_id\` text,
          \`source\` text NOT NULL,
          \`source_tool\` text,
          \`rule_id\` text,
          \`observed_at\` integer NOT NULL,
          \`evidence\` text NOT NULL,
          \`raw\` text,
          \`confidence\` text DEFAULT 'possible' NOT NULL,
          CONSTRAINT \`fk_finding_observation_case\` FOREIGN KEY (\`case_id\`) REFERENCES \`security_case\`(\`id\`) ON DELETE CASCADE,
          CONSTRAINT \`fk_finding_observation_session\` FOREIGN KEY (\`session_id\`) REFERENCES \`session\`(\`id\`) ON DELETE CASCADE,
          CONSTRAINT \`fk_finding_observation_project\` FOREIGN KEY (\`project_id\`) REFERENCES \`project\`(\`id\`) ON DELETE CASCADE
        );
      `)
      yield* tx.run(
        `CREATE INDEX IF NOT EXISTS \`security_observation_case_idx\` ON \`security_case_observation\` (\`case_id\`);`,
      )
      yield* tx.run(
        `CREATE INDEX IF NOT EXISTS \`security_observation_session_idx\` ON \`security_case_observation\` (\`session_id\`);`,
      )
      yield* tx.run(
        `CREATE INDEX IF NOT EXISTS \`security_observation_project_idx\` ON \`security_case_observation\` (\`project_id\`);`,
      )

      yield* tx.run(`
        CREATE TABLE IF NOT EXISTS \`security_case_history\` (
          \`id\` text PRIMARY KEY NOT NULL,
          \`case_id\` text NOT NULL,
          \`project_id\` text NOT NULL,
          \`previous_status\` text,
          \`new_status\` text NOT NULL,
          \`action\` text NOT NULL,
          \`reason\` text,
          \`actor\` text DEFAULT 'human' NOT NULL,
          \`time_created\` integer NOT NULL,
          CONSTRAINT \`fk_case_history_case\` FOREIGN KEY (\`case_id\`) REFERENCES \`security_case\`(\`id\`) ON DELETE CASCADE,
          CONSTRAINT \`fk_case_history_project\` FOREIGN KEY (\`project_id\`) REFERENCES \`project\`(\`id\`) ON DELETE CASCADE
        );
      `)
      yield* tx.run(
        `CREATE INDEX IF NOT EXISTS \`security_case_history_case_idx\` ON \`security_case_history\` (\`case_id\`);`,
      )
      yield* tx.run(
        `CREATE INDEX IF NOT EXISTS \`security_case_history_project_idx\` ON \`security_case_history\` (\`project_id\`);`,
      )

      yield* tx.run(`
        CREATE TABLE IF NOT EXISTS \`audit_task_execution\` (
          \`id\` text PRIMARY KEY NOT NULL,
          \`session_id\` text NOT NULL,
          \`project_id\` text NOT NULL,
          \`type\` text NOT NULL,
          \`status\` text DEFAULT 'queued' NOT NULL,
          \`target\` text,
          \`progress\` integer DEFAULT 0,
          \`current_step\` text,
          \`checkpoint_id\` text,
          \`error\` text,
          \`metadata\` text,
          \`time_created\` integer NOT NULL,
          \`time_updated\` integer NOT NULL,
          CONSTRAINT \`fk_audit_task_session\` FOREIGN KEY (\`session_id\`) REFERENCES \`session\`(\`id\`) ON DELETE CASCADE,
          CONSTRAINT \`fk_audit_task_project\` FOREIGN KEY (\`project_id\`) REFERENCES \`project\`(\`id\`) ON DELETE CASCADE
        );
      `)
      yield* tx.run(
        `CREATE INDEX IF NOT EXISTS \`audit_task_session_idx\` ON \`audit_task_execution\` (\`session_id\`);`,
      )
      yield* tx.run(
        `CREATE INDEX IF NOT EXISTS \`audit_task_status_idx\` ON \`audit_task_execution\` (\`status\`);`,
      )

      yield* tx.run(`
        CREATE TABLE IF NOT EXISTS \`audit_checkpoint\` (
          \`id\` text PRIMARY KEY NOT NULL,
          \`task_id\` text NOT NULL,
          \`session_id\` text NOT NULL,
          \`step_name\` text NOT NULL,
          \`step_index\` integer NOT NULL,
          \`completed_steps\` text NOT NULL,
          \`state_snapshot\` text NOT NULL,
          \`time_created\` integer NOT NULL,
          CONSTRAINT \`fk_audit_checkpoint_task\` FOREIGN KEY (\`task_id\`) REFERENCES \`audit_task_execution\`(\`id\`) ON DELETE CASCADE,
          CONSTRAINT \`fk_audit_checkpoint_session\` FOREIGN KEY (\`session_id\`) REFERENCES \`session\`(\`id\`) ON DELETE CASCADE
        );
      `)
      yield* tx.run(
        `CREATE INDEX IF NOT EXISTS \`audit_checkpoint_task_idx\` ON \`audit_checkpoint\` (\`task_id\`);`,
      )

      yield* tx.run(`
        CREATE TABLE IF NOT EXISTS \`audit_durable_budget\` (
          \`id\` text PRIMARY KEY NOT NULL,
          \`session_id\` text NOT NULL,
          \`project_id\` text NOT NULL,
          \`turns_count\` integer DEFAULT 0 NOT NULL,
          \`tokens_input\` integer DEFAULT 0 NOT NULL,
          \`tokens_output\` integer DEFAULT 0 NOT NULL,
          \`total_cost_usd\` text DEFAULT '0.00' NOT NULL,
          \`external_api_calls\` integer DEFAULT 0 NOT NULL,
          \`tool_calls\` integer DEFAULT 0 NOT NULL,
          \`time_updated\` integer NOT NULL,
          CONSTRAINT \`fk_audit_budget_session\` FOREIGN KEY (\`session_id\`) REFERENCES \`session\`(\`id\`) ON DELETE CASCADE,
          CONSTRAINT \`fk_audit_budget_project\` FOREIGN KEY (\`project_id\`) REFERENCES \`project\`(\`id\`) ON DELETE CASCADE
        );
      `)
      yield* tx.run(
        `CREATE UNIQUE INDEX IF NOT EXISTS \`audit_durable_budget_session_idx\` ON \`audit_durable_budget\` (\`session_id\`);`,
      )

      yield* tx.run(`
        CREATE TABLE IF NOT EXISTS \`security_auth_profile\` (
          \`id\` text PRIMARY KEY NOT NULL,
          \`project_id\` text NOT NULL,
          \`role_name\` text NOT NULL,
          \`auth_type\` text NOT NULL,
          \`credentials\` text NOT NULL,
          \`preflight_url\` text,
          \`preflight_status\` text DEFAULT 'untested',
          \`last_preflight_at\` integer,
          \`time_created\` integer NOT NULL,
          \`time_updated\` integer NOT NULL,
          CONSTRAINT \`fk_auth_profile_project\` FOREIGN KEY (\`project_id\`) REFERENCES \`project\`(\`id\`) ON DELETE CASCADE
        );
      `)
      yield* tx.run(
        `CREATE INDEX IF NOT EXISTS \`security_auth_profile_project_idx\` ON \`security_auth_profile\` (\`project_id\`);`,
      )

      yield* tx.run(`
        CREATE TABLE IF NOT EXISTS \`security_surface_coverage\` (
          \`id\` text PRIMARY KEY NOT NULL,
          \`session_id\` text NOT NULL,
          \`project_id\` text NOT NULL,
          \`target_url\` text NOT NULL,
          \`method\` text NOT NULL,
          \`role\` text DEFAULT 'anonymous' NOT NULL,
          \`status\` text NOT NULL,
          \`tools_executed\` text,
          \`findings_count\` integer DEFAULT 0 NOT NULL,
          \`reason\` text,
          \`time_updated\` integer NOT NULL,
          CONSTRAINT \`fk_surface_coverage_session\` FOREIGN KEY (\`session_id\`) REFERENCES \`session\`(\`id\`) ON DELETE CASCADE,
          CONSTRAINT \`fk_surface_coverage_project\` FOREIGN KEY (\`project_id\`) REFERENCES \`project\`(\`id\`) ON DELETE CASCADE
        );
      `)
      yield* tx.run(
        `CREATE INDEX IF NOT EXISTS \`security_surface_coverage_session_idx\` ON \`security_surface_coverage\` (\`session_id\`);`,
      )

      yield* tx.run(`
        CREATE TABLE IF NOT EXISTS \`connector_outbox\` (
          \`id\` text PRIMARY KEY NOT NULL,
          \`project_id\` text NOT NULL,
          \`session_id\` text,
          \`target_system\` text NOT NULL,
          \`event_type\` text NOT NULL,
          \`idempotency_key\` text NOT NULL UNIQUE,
          \`payload\` text NOT NULL,
          \`status\` text DEFAULT 'pending' NOT NULL,
          \`attempts\` integer DEFAULT 0 NOT NULL,
          \`max_attempts\` integer DEFAULT 5 NOT NULL,
          \`next_retry_at\` integer,
          \`last_error\` text,
          \`time_created\` integer NOT NULL,
          \`time_delivered\` integer,
          CONSTRAINT \`fk_connector_outbox_project\` FOREIGN KEY (\`project_id\`) REFERENCES \`project\`(\`id\`) ON DELETE CASCADE
        );
      `)
      yield* tx.run(
        `CREATE INDEX IF NOT EXISTS \`connector_outbox_status_retry_idx\` ON \`connector_outbox\` (\`status\`, \`next_retry_at\`);`,
      )

      yield* tx.run(`
        CREATE TABLE IF NOT EXISTS \`audit_schedule\` (
          \`id\` text PRIMARY KEY NOT NULL,
          \`project_id\` text NOT NULL,
          \`name\` text NOT NULL,
          \`target\` text NOT NULL,
          \`scan_type\` text DEFAULT 'web_scan' NOT NULL,
          \`cron_expression\` text DEFAULT '0 0 * * *' NOT NULL,
          \`timezone\` text DEFAULT 'UTC' NOT NULL,
          \`next_run_at\` integer NOT NULL,
          \`last_run_at\` integer,
          \`last_status\` text DEFAULT 'pending',
          \`missed_occurrences\` integer DEFAULT 0 NOT NULL,
          \`enabled\` integer DEFAULT 1 NOT NULL,
          \`time_created\` integer NOT NULL,
          \`time_updated\` integer NOT NULL,
          CONSTRAINT \`fk_audit_schedule_project\` FOREIGN KEY (\`project_id\`) REFERENCES \`project\`(\`id\`) ON DELETE CASCADE
        );
      `)
      yield* tx.run(
        `CREATE INDEX IF NOT EXISTS \`audit_schedule_project_idx\` ON \`audit_schedule\` (\`project_id\`);`,
      )
      yield* tx.run(
        `CREATE INDEX IF NOT EXISTS \`audit_schedule_next_run_idx\` ON \`audit_schedule\` (\`next_run_at\`, \`enabled\`);`,
      )

      yield* tx.run(`
        CREATE VIRTUAL TABLE IF NOT EXISTS \`security_knowledge_fts\` USING fts5(
          \`session_id\`,
          \`project_id\`,
          \`title\`,
          \`cwe\`,
          \`target\`,
          \`content\`
        );
      `).pipe(Effect.catch(() => Effect.void))
    })
  },
} satisfies DatabaseMigration.Migration

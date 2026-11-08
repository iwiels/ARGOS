CREATE TABLE `audit_log` (
	`id` text PRIMARY KEY,
	`seq` integer NOT NULL UNIQUE,
	`project_id` text,
	`session_id` text,
	`event_type` text NOT NULL,
	`action` text NOT NULL,
	`agent` text,
	`target` text,
	`summary` text NOT NULL,
	`payload` text DEFAULT '{}' NOT NULL,
	`prev_hash` text NOT NULL,
	`hash` text NOT NULL,
	`time_created` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `compliance_catalog` (
	`framework` text NOT NULL,
	`control_id` text NOT NULL,
	`title` text NOT NULL,
	`parent_id` text,
	`level` text NOT NULL,
	`sort_id` text,
	`attributes` text DEFAULT '{}' NOT NULL,
	`source` text,
	`time_updated` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `compliance_control_history` (
	`id` integer PRIMARY KEY AUTOINCREMENT,
	`project_id` text NOT NULL,
	`framework` text NOT NULL,
	`control_id` text NOT NULL,
	`status_from` text NOT NULL,
	`status_to` text NOT NULL,
	`time_recorded` integer NOT NULL,
	CONSTRAINT `fk_compliance_control_history_project_id_project_id_fk` FOREIGN KEY (`project_id`) REFERENCES `project`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `compliance_mapping` (
	`source_framework` text NOT NULL,
	`source_control_id` text NOT NULL,
	`target_framework` text NOT NULL,
	`target_control_id` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `compliance_control_status` (
	`project_id` text NOT NULL,
	`framework` text NOT NULL,
	`control_id` text NOT NULL,
	`status` text NOT NULL,
	`evidence` text DEFAULT '[]' NOT NULL,
	`time_updated` integer NOT NULL,
	CONSTRAINT `fk_compliance_control_status_project_id_project_id_fk` FOREIGN KEY (`project_id`) REFERENCES `project`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `session_pseudonym` (
	`id` text PRIMARY KEY,
	`session_id` text NOT NULL,
	`entity_type` text NOT NULL,
	`token` text NOT NULL,
	`real_value` text NOT NULL,
	`time_created` integer NOT NULL,
	CONSTRAINT `fk_session_pseudonym_session_id_session_id_fk` FOREIGN KEY (`session_id`) REFERENCES `session`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `security_finding` (
	`id` text PRIMARY KEY,
	`session_id` text NOT NULL,
	`project_id` text NOT NULL,
	`fingerprint` text NOT NULL,
	`title` text NOT NULL,
	`severity` text NOT NULL,
	`status` text DEFAULT 'open' NOT NULL,
	`source` text NOT NULL,
	`source_tool` text,
	`agent` text,
	`target` text,
	`cwe` text,
	`vector` text,
	`evidence` text NOT NULL,
	`remediation` text,
	`tags` text NOT NULL,
	`raw` text,
	`attack_techniques` text,
	`iocs` text,
	`enrichment` text,
	`enriched_at` integer,
	`time_created` integer NOT NULL,
	`time_updated` integer NOT NULL,
	CONSTRAINT `fk_security_finding_session_id_session_id_fk` FOREIGN KEY (`session_id`) REFERENCES `session`(`id`) ON DELETE CASCADE,
	CONSTRAINT `fk_security_finding_project_id_project_id_fk` FOREIGN KEY (`project_id`) REFERENCES `project`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
ALTER TABLE `session` ADD `scope_cidrs` text;--> statement-breakpoint
ALTER TABLE `session` ADD `scope_domains` text;--> statement-breakpoint
ALTER TABLE `session` ADD `scope_excluded` text;--> statement-breakpoint
ALTER TABLE `session` ADD `scope_max_rps` integer;--> statement-breakpoint
ALTER TABLE `session` ADD `scope_safe_mode` integer;--> statement-breakpoint
PRAGMA foreign_keys=OFF;--> statement-breakpoint
CREATE TABLE `__new_session_context_epoch` (
	`session_id` text PRIMARY KEY,
	`baseline` text NOT NULL,
	`agent` text DEFAULT 'analyst' NOT NULL,
	`snapshot` text NOT NULL,
	`baseline_seq` integer NOT NULL,
	`replacement_seq` integer,
	`revision` integer DEFAULT 0 NOT NULL,
	CONSTRAINT `fk_session_context_epoch_session_id_session_id_fk` FOREIGN KEY (`session_id`) REFERENCES `session`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
INSERT INTO `__new_session_context_epoch`(`session_id`, `baseline`, `agent`, `snapshot`, `baseline_seq`, `replacement_seq`, `revision`) SELECT `session_id`, `baseline`, `agent`, `snapshot`, `baseline_seq`, `replacement_seq`, `revision` FROM `session_context_epoch`;--> statement-breakpoint
DROP TABLE `session_context_epoch`;--> statement-breakpoint
ALTER TABLE `__new_session_context_epoch` RENAME TO `session_context_epoch`;--> statement-breakpoint
PRAGMA foreign_keys=ON;--> statement-breakpoint
CREATE INDEX `audit_log_session_idx` ON `audit_log` (`session_id`);--> statement-breakpoint
CREATE INDEX `audit_log_time_idx` ON `audit_log` (`time_created`);--> statement-breakpoint
CREATE INDEX `compliance_catalog_parent_idx` ON `compliance_catalog` (`framework`,`parent_id`);--> statement-breakpoint
CREATE INDEX `compliance_catalog_level_idx` ON `compliance_catalog` (`framework`,`level`);--> statement-breakpoint
CREATE INDEX `compliance_history_project_idx` ON `compliance_control_history` (`project_id`,`framework`,`control_id`);--> statement-breakpoint
CREATE INDEX `compliance_mapping_source_idx` ON `compliance_mapping` (`source_framework`,`source_control_id`);--> statement-breakpoint
CREATE INDEX `compliance_status_project_idx` ON `compliance_control_status` (`project_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `session_pseudonym_session_token_idx` ON `session_pseudonym` (`session_id`,`token`);--> statement-breakpoint
CREATE UNIQUE INDEX `session_pseudonym_session_real_idx` ON `session_pseudonym` (`session_id`,`entity_type`,`real_value`);--> statement-breakpoint
CREATE INDEX `session_pseudonym_session_idx` ON `session_pseudonym` (`session_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `security_finding_session_fingerprint_idx` ON `security_finding` (`session_id`,`fingerprint`);--> statement-breakpoint
CREATE INDEX `security_finding_project_idx` ON `security_finding` (`project_id`);--> statement-breakpoint
CREATE INDEX `security_finding_session_severity_idx` ON `security_finding` (`session_id`,`severity`);--> statement-breakpoint
CREATE INDEX `security_finding_session_updated_idx` ON `security_finding` (`session_id`,`time_updated`);
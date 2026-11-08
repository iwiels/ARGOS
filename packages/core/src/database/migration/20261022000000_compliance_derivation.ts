import { Effect } from "effect"
import type { DatabaseMigration } from "../migration"

/**
 * Evidencia auditable de compliance (ARG-042).
 *
 * `derivation` guarda la evidencia por regla (qué regla derivó el control y
 * qué hallazgos la activaron) y `confidence` la confianza agregada del control.
 * Los controles previos quedan con `derivation = []` y `confidence = high`
 * (sin hallazgos mapeados → no hay derivación que auditar).
 */
export default {
  id: "20261022000000_compliance_derivation",
  up(tx) {
    return Effect.gen(function* () {
      yield* tx.run(
        `ALTER TABLE \`compliance_control_status\` ADD \`derivation\` text NOT NULL DEFAULT '[]';`,
      )
      yield* tx.run(
        `ALTER TABLE \`compliance_control_status\` ADD \`confidence\` text NOT NULL DEFAULT 'high';`,
      )
    })
  },
} satisfies DatabaseMigration.Migration

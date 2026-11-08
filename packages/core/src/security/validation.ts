import { eq } from "drizzle-orm"
import { Effect } from "effect"
import type { Database } from "../database/database"
import { FindingTable } from "./sql"

export type FindingRow = typeof FindingTable.$inferSelect

export interface ValidationResult {
  confirmed: boolean
  evidence?: Record<string, unknown>
  reason?: string
}

export interface ValidateFindingOptions {
  findingId: string
  verifier: (finding: FindingRow) => Promise<ValidationResult> | ValidationResult
}

export function validateFinding(
  db: Database.Interface["db"],
  options: ValidateFindingOptions,
): Effect.Effect<FindingRow, Error> {
  return Effect.gen(function* () {
    const findings = yield* db
      .select()
      .from(FindingTable)
      .where(eq(FindingTable.id, options.findingId))
      .run()
      .pipe(Effect.orDie)

    if (findings.length === 0) {
      return yield* Effect.fail(new Error(`Finding with ID ${options.findingId} not found`))
    }

    const finding = findings[0]

    yield* db
      .update(FindingTable)
      .set({
        validation_status: "validating",
        time_updated: Date.now(),
      })
      .where(eq(FindingTable.id, options.findingId))
      .run()
      .pipe(Effect.orDie)

    const verification = yield* Effect.tryPromise({
      try: async () => await options.verifier(finding),
      catch: (err) => new Error(`Verifier failed: ${err instanceof Error ? err.message : String(err)}`),
    }).pipe(
      Effect.catch((err) =>
        db
          .update(FindingTable)
          .set({
            validation_status: "rejected",
            validation_evidence: { error: err.message },
            time_updated: Date.now(),
          })
          .where(eq(FindingTable.id, options.findingId))
          .run()
          .pipe(
            Effect.orDie,
            Effect.flatMap(() => Effect.fail(err)),
          ),
      ),
    )

    const now = Date.now()
    const validationStatus = verification.confirmed ? "confirmed" : "rejected"
    const lifecycleStatus = verification.confirmed ? "validated" : "false-positive"
    const evidence = verification.evidence ?? (verification.reason ? { reason: verification.reason } : {})

    yield* db
      .update(FindingTable)
      .set({
        validation_status: validationStatus,
        status: lifecycleStatus,
        validation_evidence: evidence,
        validated_at: now,
        time_updated: now,
      })
      .where(eq(FindingTable.id, options.findingId))
      .run()
      .pipe(Effect.orDie)

    const updated = yield* db
      .select()
      .from(FindingTable)
      .where(eq(FindingTable.id, options.findingId))
      .run()
      .pipe(Effect.orDie)

    return updated[0]
  })
}

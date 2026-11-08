import { describe, expect } from "bun:test"
import { eq } from "drizzle-orm"
import { Effect } from "effect"
import { Database } from "../src/database/database"
import { Project } from "../src/project"
import { ProjectTable } from "../src/project/sql"
import { AbsolutePath } from "../src/schema"
import { FindingObservationTable } from "../src/security/sql"
import { listFindingObservations, recordFindingObservation } from "../src/security/finding-observation"
import { SessionV2 } from "../src/session"
import { SessionTable } from "../src/session/sql"
import { testEffect } from "./lib/effect"

const sessionID = SessionV2.ID.make("ses_finding_observations")
const otherSessionID = SessionV2.ID.make("ses_finding_observations_other")
const it = testEffect(Database.layerFromPath(":memory:"))

const seed = Effect.gen(function* () {
  const { db } = yield* Database.Service
  yield* db.insert(ProjectTable).values({
    id: Project.ID.global,
    worktree: AbsolutePath.make("/project"),
    sandboxes: [],
  }).run().pipe(Effect.orDie)
  for (const id of [sessionID, otherSessionID]) {
    yield* db.insert(SessionTable).values({
      id,
      project_id: Project.ID.global,
      slug: id,
      directory: "/project",
      title: "observations",
      version: "test",
    }).run().pipe(Effect.orDie)
  }
  for (const [id, owner, findingID, observedAt] of [
    ["obs-old", sessionID, "finding-a", 100],
    ["obs-new", sessionID, "finding-a", 200],
    ["obs-other-finding", sessionID, "finding-b", 300],
    ["obs-other-session", otherSessionID, "finding-a", 400],
  ] as const) {
    yield* db.insert(FindingObservationTable).values({
      id,
      project_id: Project.ID.global,
      session_id: owner,
      finding_id: findingID,
      source_event_id: id,
      fingerprint: id,
      source: "tool",
      source_tool: "web.scan",
      observed_at: observedAt,
      snapshot: JSON.stringify({ id }),
    }).run().pipe(Effect.orDie)
  }
})

describe("finding observation history", () => {
  it.effect("deduplicates a repeated observation when its source tool is absent", () => Effect.gen(function* () {
    yield* seed
    const { db } = yield* Database.Service
    const observation = {
      projectID: Project.ID.global,
      sessionID,
      findingID: "finding-null-source-tool",
      sourceEventID: "import:batch-null-tool",
      fingerprint: "finding-fingerprint-null-tool",
      source: "import",
      sourceTool: null,
      observedAt: 500,
      snapshot: JSON.stringify({ title: "Imported finding" }),
    }

    yield* recordFindingObservation(db, observation)
    yield* recordFindingObservation(db, observation)

    const rows = yield* db
      .select()
      .from(FindingObservationTable)
      .where(eq(FindingObservationTable.session_id, sessionID))
      .all()
    expect(rows.filter((row) => row.source_event_id === observation.sourceEventID)).toHaveLength(1)
  }))

  it.effect("paginates by finding, returns a consistent total, and never crosses sessions", () => Effect.gen(function* () {
    yield* seed
    const { db } = yield* Database.Service
    const page = yield* listFindingObservations(db, { sessionID, findingID: "finding-a", limit: 1, offset: 1 })
    expect(page.total).toBe(2)
    expect(page.records.map((row) => row.id)).toEqual(["obs-old"])

    const other = yield* listFindingObservations(db, { sessionID: otherSessionID, findingID: "finding-a" })
    expect(other.total).toBe(1)
    expect(other.records.map((row) => row.id)).toEqual(["obs-other-session"])
  }))

  it.effect("keeps the count when a page has zero capacity", () => Effect.gen(function* () {
    yield* seed
    const { db } = yield* Database.Service
    const page = yield* listFindingObservations(db, { sessionID, limit: 0 })
    expect(page.total).toBe(3)
    expect(page.records).toEqual([])
  }))

  it.effect("deletes observations when their session is deleted", () => Effect.gen(function* () {
    yield* seed
    const { db } = yield* Database.Service
    yield* db.delete(SessionTable).where(eq(SessionTable.id, sessionID)).run().pipe(Effect.orDie)
    const remaining = yield* db
      .select()
      .from(FindingObservationTable)
      .where(eq(FindingObservationTable.session_id, sessionID))
      .all()
      .pipe(Effect.orDie)
    expect(remaining).toEqual([])
  }))
})

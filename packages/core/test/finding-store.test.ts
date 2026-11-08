import { describe, expect } from "bun:test"
import { Effect } from "effect"
import { Database } from "../src/database/database"
import { Project } from "../src/project"
import { ProjectTable } from "../src/project/sql"
import { AbsolutePath } from "../src/schema"
import { toSecurityFindingDTO } from "../src/security/finding-dto"
import { recordFeedback } from "../src/security/finding-feedback"
import { getFindingRecord, listFindingRecords } from "../src/security/finding-store"
import { FindingTable } from "../src/security/sql"
import { SessionV2 } from "../src/session"
import { SessionTable } from "../src/session/sql"
import { testEffect } from "./lib/effect"

const sessionID = SessionV2.ID.make("ses_finding_store")
const otherSessionID = SessionV2.ID.make("ses_finding_store_other")
const it = testEffect(Database.layerFromPath(":memory:"))

const seed = Effect.gen(function* () {
  const { db } = yield* Database.Service
  yield* db.insert(ProjectTable).values({
    id: Project.ID.global, worktree: AbsolutePath.make("/project"), sandboxes: [],
  }).run().pipe(Effect.orDie)
  for (const id of [sessionID, otherSessionID]) {
    yield* db.insert(SessionTable).values({
      id, project_id: Project.ID.global, slug: id, directory: "/project", title: "findings", version: "test",
    }).run().pipe(Effect.orDie)
  }
  for (const [id, owner, severity, updated] of [
    ["finding-visible", sessionID, "high", 30],
    ["finding-suppressed", sessionID, "high", 20],
    ["finding-low", sessionID, "low", 10],
    ["finding-other", otherSessionID, "high", 40],
  ] as const) {
    yield* db.insert(FindingTable).values({
      id, session_id: owner, project_id: Project.ID.global, fingerprint: id, title: id,
      severity, status: "open", source: "agent-reviewed", evidence: { status: 200 }, tags: ["web"],
      time_created: 1, time_updated: updated,
    }).run().pipe(Effect.orDie)
  }
  for (const [id, source] of [["legacy-memory", "memory"], ["scanner-tool", "tool"], ["legacy-web-scan", "web.scan"]] as const) {
    yield* db.insert(FindingTable).values({
      id, session_id: sessionID, project_id: Project.ID.global, fingerprint: id, title: id,
      severity: "high", status: "open", source, evidence: { status: 200 }, tags: ["web"],
      time_created: 1, time_updated: 50,
    }).run().pipe(Effect.orDie)
  }
  yield* recordFeedback(db, { sessionID, findingID: "finding-suppressed", verdict: "false-positive", reason: "Reviewed" })
})

describe("shared finding repository", () => {
  it.effect("preserves persisted feedback while supporting both list policies", () => Effect.gen(function* () {
    yield* seed
    const { db } = yield* Database.Service
    const legacy = yield* listFindingRecords(db, { sessionID, limit: 200, offset: 0, includeSuppressed: true })
    const canonical = (record: (typeof legacy.records)[number]) => toSecurityFindingDTO(record.row, record.feedback)
    expect(legacy.total).toBe(3)
    expect(legacy.records.map((record) => record.row.id)).toEqual(["finding-visible", "finding-suppressed", "finding-low"])
    expect(canonical(legacy.records[1]).feedback).toEqual({ verdict: "false-positive", reason: "Reviewed", actor: "human" })
    const visible = yield* listFindingRecords(db, { sessionID, limit: 50, offset: 0 })
    expect(visible.total).toBe(2)
    expect(visible.records.map((record) => record.row.id)).toEqual(["finding-visible", "finding-low"])
  }))

  it.effect("uses the same suppression and filters for count and pagination", () => Effect.gen(function* () {
    yield* seed
    const { db } = yield* Database.Service
    const page = yield* listFindingRecords(db, { sessionID, limit: 1, offset: 1, severity: "high", status: "open", includeSuppressed: true })
    expect(page.total).toBe(2)
    expect(page.records.map((record) => record.row.id)).toEqual(["finding-suppressed"])
    const empty = yield* listFindingRecords(db, { sessionID, limit: 0, offset: 0, includeSuppressed: true })
    expect(empty.total).toBe(3)
    expect(empty.records).toEqual([])
  }))

  it.effect("single finding lookup preserves feedback and cannot cross session boundaries", () => Effect.gen(function* () {
    yield* seed
    const { db } = yield* Database.Service
    const record = yield* getFindingRecord(db, sessionID, "finding-suppressed")
    expect(record?.feedback?.reason).toBe("Reviewed")
    expect(yield* getFindingRecord(db, otherSessionID, "finding-suppressed")).toBeUndefined()
    expect(yield* getFindingRecord(db, sessionID, "missing")).toBeUndefined()
  }))

  it.effect("keeps explicit imports visible while excluding unreviewed legacy provenance", () => Effect.gen(function* () {
    yield* seed
    const { db } = yield* Database.Service
    yield* db.insert(FindingTable).values({
      id: "finding-imported", session_id: sessionID, project_id: Project.ID.global, fingerprint: "finding-imported",
      title: "Imported report finding", severity: "medium", status: "open", source: "import",
      evidence: { text: "Explicitly imported report evidence" }, tags: [], time_created: 1, time_updated: 60,
    }).run().pipe(Effect.orDie)
    const listed = yield* listFindingRecords(db, { sessionID, limit: 50, offset: 0, includeSuppressed: true })
    expect(listed.records.map((record) => record.row.id)).toContain("finding-imported")
    expect(listed.records.map((record) => record.row.id)).not.toContain("legacy-memory")
    expect(listed.records.map((record) => record.row.id)).not.toContain("legacy-web-scan")
    expect(listed.records.map((record) => record.row.id)).not.toContain("scanner-tool")
  }))
})

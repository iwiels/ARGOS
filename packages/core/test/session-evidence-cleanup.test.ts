import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { describe, expect, test } from "bun:test"
import { deleteSessionSecurityEvidence } from "@argos/core/security/session-evidence"

const sessionID = "ses_delete_evidence"

describe("session evidence cleanup", () => {
  test("removes only the selected session's traffic and finding records", async () => {
    const memoryDir = await mkdtemp(path.join(tmpdir(), "argos-session-evidence-"))
    const trafficDir = path.join(memoryDir, "traffic")
    const findingsDir = path.join(memoryDir, "findings")
    const selectedTraffic = path.join(trafficDir, sessionID)
    const retainedTraffic = path.join(trafficDir, "ses_retained")

    try {
      await mkdir(selectedTraffic, { recursive: true })
      await mkdir(retainedTraffic, { recursive: true })
      await mkdir(findingsDir, { recursive: true })
      await writeFile(path.join(selectedTraffic, "exchange.json"), "{}")
      await writeFile(path.join(retainedTraffic, "exchange.json"), "{}")
      await writeFile(path.join(findingsDir, "selected.json"), JSON.stringify({ argos_session_id: sessionID }))
      await writeFile(path.join(findingsDir, "selected-second.json"), JSON.stringify({ argos_session_id: sessionID }))
      await writeFile(path.join(findingsDir, "retained.json"), JSON.stringify({ argos_session_id: "ses_retained" }))
      await writeFile(path.join(findingsDir, "unassociated.json"), JSON.stringify({ title: "shared record" }))
      await writeFile(path.join(findingsDir, "malformed.json"), "{")

      await deleteSessionSecurityEvidence(sessionID, memoryDir)

      await expect(readdir(selectedTraffic)).rejects.toMatchObject({ code: "ENOENT" })
      await expect(readFile(path.join(retainedTraffic, "exchange.json"), "utf8")).resolves.toBe("{}")
      await expect(readdir(findingsDir)).resolves.toEqual(["malformed.json", "retained.json", "unassociated.json"])
    } finally {
      await rm(memoryDir, { recursive: true, force: true })
    }
  })

  test("refuses session IDs that could alias another session's store path", async () => {
    const memoryDir = await mkdtemp(path.join(tmpdir(), "argos-session-evidence-id-"))
    try {
      await expect(deleteSessionSecurityEvidence("ses/../other", memoryDir)).rejects.toThrow("invalid session id")
    } finally {
      await rm(memoryDir, { recursive: true, force: true })
    }
  })
})

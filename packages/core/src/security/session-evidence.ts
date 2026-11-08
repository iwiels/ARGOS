import { lstat, readdir, readFile, rm } from "node:fs/promises"
import path from "node:path"
import { defaultAgentMemoryDir } from "./agent-findings-reconcile"
import { trafficSessionDir } from "./traffic"

const missing = (error: unknown) =>
  typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT"

const assertDirectory = async (dir: string) => {
  let stat
  try {
    stat = await lstat(dir)
  } catch (error) {
    if (missing(error)) return false
    throw error
  }
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error(`session evidence path is not a directory: ${dir}`)
  return true
}

const removeTraffic = async (memoryDir: string, sessionID: string) => {
  const root = path.join(memoryDir, "traffic")
  if (!(await assertDirectory(root))) return
  const dir = trafficSessionDir(memoryDir, sessionID)
  let stat
  try {
    stat = await lstat(dir)
  } catch (error) {
    if (missing(error)) return
    throw error
  }
  if (stat.isSymbolicLink()) {
    await rm(dir)
    return
  }
  if (!stat.isDirectory()) throw new Error(`session traffic evidence is not a directory: ${dir}`)
  await rm(dir, { recursive: true })
}

const removeFindingRecords = async (memoryDir: string, sessionID: string) => {
  const dir = path.join(memoryDir, "findings")
  if (!(await assertDirectory(dir))) return
  const entries = await readdir(dir, { withFileTypes: true })
  for (const entry of entries) {
    if (!entry.isFile() || !entry.name.endsWith(".json")) continue
    const file = path.join(dir, entry.name)
    const stat = await lstat(file)
    if (!stat.isFile() || stat.isSymbolicLink()) continue
    let record: unknown
    try {
      record = JSON.parse(await readFile(file, "utf8"))
    } catch {
      continue
    }
    if (typeof record !== "object" || record === null || Array.isArray(record)) continue
    const data = record as Record<string, unknown>
    const canonical = typeof data.argos_session_id === "string" ? data.argos_session_id.trim() : ""
    if (canonical !== sessionID) continue
    await rm(file)
  }
}

export async function deleteSessionSecurityEvidence(
  sessionID: string,
  memoryDir: string = defaultAgentMemoryDir(),
) {
  if (!/^ses[A-Za-z0-9._-]+$/.test(sessionID)) throw new Error("invalid session id for evidence cleanup")
  await removeTraffic(memoryDir, sessionID)
  await removeFindingRecords(memoryDir, sessionID)
}

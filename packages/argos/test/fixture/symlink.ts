import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import path from "node:path"

export const supportsSymlinks = (() => {
  if (process.platform !== "win32") return true
  const directory = mkdtempSync(path.join(tmpdir(), "argos-symlink-capability-"))
  try {
    const target = path.join(directory, "target")
    writeFileSync(target, "fixture")
    symlinkSync(target, path.join(directory, "link"), "file")
    return true
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && ["EPERM", "EACCES", "ENOTSUP"].includes(String(error.code))) return false
    throw error
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
})()

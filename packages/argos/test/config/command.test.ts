import { expect, test } from "bun:test"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { ConfigCommand } from "@/config/command"

test("loads only the declared audit profile from command frontmatter", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "argos-command-profile-"))
  try {
    const commands = path.join(directory, "command")
    await fs.mkdir(commands)
    await fs.writeFile(
      path.join(commands, "auditoria-web.md"),
      `---\ndescription: Web audit\nagent: security-web\nauditProfile: web\nsubtask: false\n---\n\nAudit the authorized target.\n`,
    )
    await fs.writeFile(path.join(commands, "chat.md"), `---\ndescription: Normal chat\n---\n\nSay hello.\n`)

    const result = await ConfigCommand.load(directory)
    expect(result["auditoria-web"]?.auditProfile).toBe("web")
    expect(result["auditoria-web"]?.subtask).toBe(false)
    expect(result.chat?.auditProfile).toBeUndefined()
  } finally {
    await fs.rm(directory, { recursive: true, force: true })
  }
})

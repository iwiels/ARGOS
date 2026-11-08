import { describe, expect } from "bun:test"
import { mkdtempSync } from "node:fs"
import { rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { Flag } from "@argos/core/flag/flag"
import { Database } from "@argos/core/database/database"
import { Effect, Layer } from "effect"
import { Shell } from "../src/shell/shell"
import { Server } from "../src/server/server"
import { resetDatabase } from "./fixture/db"
import { testEffect } from "./lib/effect"

const testStateLayer = Layer.effectDiscard(
  Effect.gen(function* () {
    const original = Flag.ARGOS_SERVER_PASSWORD
    Flag.ARGOS_SERVER_PASSWORD = undefined
    const originalDb = Flag.ARGOS_DB
    const tmpDir = mkdtempSync(join(tmpdir(), "argos-pty-probe-"))
    Flag.ARGOS_DB = join(tmpDir, "test.db")
    yield* Effect.promise(() => resetDatabase())
    yield* Effect.addFinalizer(() =>
      Effect.promise(async () => {
        await resetDatabase()
        Flag.ARGOS_SERVER_PASSWORD = original
        Flag.ARGOS_DB = originalDb
        await rm(tmpDir, { recursive: true, force: true }).catch(() => undefined)
      }),
    )
  }),
)

const it = testEffect(Database.defaultLayer.pipe(Layer.provide(testStateLayer)))

describe("PTY create over real HTTP", () => {
  it.live("creates a terminal session", () =>
    Effect.gen(function* () {
      const command = Shell.preferred()
      console.log("PROBE_SHELL:", JSON.stringify({ command, login: Shell.login(command) }))

      const listener = yield* Effect.promise(() => Server.listen({ hostname: "127.0.0.1", port: 0 }))
      try {
        const url = new URL(`/pty?directory=${encodeURIComponent(process.cwd())}`, listener.url)
        const res = yield* Effect.promise(() =>
          fetch(url, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ title: "Probe 1" }),
          }),
        )
        const text = yield* Effect.promise(() => res.text())
        console.log("PROBE_STATUS:", res.status)
        console.log("PROBE_BODY:", text.slice(0, 400))
        // Give the async stderr logger a moment to flush the real cause.
        yield* Effect.promise(() => new Promise((r) => setTimeout(r, 400)))
        expect(res.status).toBe(200)
      } finally {
        yield* Effect.promise(() => listener.stop(true))
      }
    }),
  )
})

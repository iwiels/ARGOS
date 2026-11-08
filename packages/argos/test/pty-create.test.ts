import { describe, expect } from "bun:test"
import { mkdtempSync } from "node:fs"
import { rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { Flag } from "@argos/core/flag/flag"
import { Database } from "@argos/core/database/database"
import { Effect, Layer } from "effect"
import { Server } from "../src/server/server"
import { resetDatabase } from "./fixture/db"
import { testEffect } from "./lib/effect"

// Regresión: `PtyPreparation.prepareCreate` importaba el Config de argos
// mientras que el efecto corre dentro de LocationServiceMap, que provee el
// Config de core. Ambos se registran bajo el mismo tag "@argos/Config", así
// que el lookup resolvía al de core y `config.get()` era undefined -> 500.
// El cliente traga ese 500 (ThrowOnError=false) y la terminal nunca aparecía.

const testStateLayer = Layer.effectDiscard(
  Effect.gen(function* () {
    const originalPassword = Flag.ARGOS_SERVER_PASSWORD
    Flag.ARGOS_SERVER_PASSWORD = undefined
    const originalDb = Flag.ARGOS_DB
    const tmpDir = mkdtempSync(join(tmpdir(), "argos-pty-create-"))
    Flag.ARGOS_DB = join(tmpDir, "test.db")

    yield* Effect.promise(() => resetDatabase())
    yield* Effect.addFinalizer(() =>
      Effect.promise(async () => {
        await resetDatabase()
        Flag.ARGOS_SERVER_PASSWORD = originalPassword
        Flag.ARGOS_DB = originalDb
        await rm(tmpDir, { recursive: true, force: true }).catch(() => undefined)
      }),
    )
  }),
)

const it = testEffect(Database.defaultLayer.pipe(Layer.provide(testStateLayer)))

describe("PTY create (real HTTP)", () => {
  it.live("spawns a live shell session", () =>
    Effect.gen(function* () {
      const listener = yield* Effect.promise(() => Server.listen({ hostname: "127.0.0.1", port: 0 }))
      try {
        const url = new URL(`/pty?directory=${encodeURIComponent(process.cwd())}`, listener.url)
        const response = yield* Effect.promise(() =>
          fetch(url, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ title: "Terminal 1" }),
          }),
        )

        const body = yield* Effect.promise(() => response.json() as Promise<Record<string, unknown>>)

        expect(response.status).toBe(200)
        expect(typeof body.id).toBe("string")
        expect(body.title).toBe("Terminal 1")
        expect(body.status).toBe("running")
        // Un pid real es la prueba de que el shell se levantó, no sólo que el
        // endpoint respondió.
        expect(typeof body.pid).toBe("number")
        expect(body.pid as number).toBeGreaterThan(0)
        expect(typeof body.command).toBe("string")
        expect((body.command as string).length).toBeGreaterThan(0)
      } finally {
        yield* Effect.promise(() => listener.stop(true))
      }
    }),
  )
})

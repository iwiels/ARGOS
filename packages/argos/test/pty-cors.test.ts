import { describe, expect } from "bun:test"
import { mkdtempSync } from "node:fs"
import { rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { Flag } from "@argos/core/flag/flag"
import { Database } from "@argos/core/database/database"
import { Effect, Layer } from "effect"
import { Server } from "../src/server/server"
import { PTY_CONNECT_TOKEN_HEADER } from "../src/server/shared/pty-ticket"
import { resetDatabase } from "./fixture/db"
import { testEffect } from "./lib/effect"

const testStateLayer = Layer.effectDiscard(
  Effect.gen(function* () {
    const originalPassword = Flag.ARGOS_SERVER_PASSWORD
    Flag.ARGOS_SERVER_PASSWORD = undefined
    const originalDb = Flag.ARGOS_DB
    const tmpDir = mkdtempSync(join(tmpdir(), "argos-pty-cors-"))
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

const preflight = (url: URL, requestHeaders?: string) =>
  fetch(url, {
    method: "OPTIONS",
    headers: {
      origin: "http://localhost:5173",
      "access-control-request-method": "POST",
      ...(requestHeaders ? { "access-control-request-headers": requestHeaders } : {}),
    },
  })

describe("PTY connect-token CORS preflight", () => {
  it.live("allows the ticket header from a dev-server origin", () =>
    Effect.gen(function* () {
      const listener = yield* Effect.promise(() => Server.listen({ hostname: "127.0.0.1", port: 0 }))
      try {
        const url = new URL("/pty/pty_probe/connect-token", listener.url)
        const res = yield* Effect.promise(() => preflight(url, PTY_CONNECT_TOKEN_HEADER))

        const allowHeaders = res.headers.get("access-control-allow-headers") ?? ""
        expect(res.status).toBeLessThan(400)
        expect(res.headers.get("access-control-allow-origin")).toBeTruthy()
        expect(allowHeaders.toLowerCase()).toContain(PTY_CONNECT_TOKEN_HEADER)
      } finally {
        yield* Effect.promise(() => listener.stop(true))
      }
    }),
  )

  it.live("answers preflights identically regardless of the requested headers", () =>
    Effect.gen(function* () {
      // El preflight se cachea 24h (maxAge). Si la respuesta dependiera del
      // header solicitado, una entrada cacheada podría negar `x-opencode-ticket`
      // durante todo un día y dejar la terminal sin conectar. Debe ser estable.
      const listener = yield* Effect.promise(() => Server.listen({ hostname: "127.0.0.1", port: 0 }))
      try {
        const url = new URL("/pty/pty_probe/connect-token", listener.url)

        const withTicket = yield* Effect.promise(() => preflight(url, PTY_CONNECT_TOKEN_HEADER))
        const withOther = yield* Effect.promise(() => preflight(url, "content-type"))
        const withNone = yield* Effect.promise(() => preflight(url))

        const allow = (r: Response) => (r.headers.get("access-control-allow-headers") ?? "").toLowerCase()

        expect(allow(withTicket)).toBe(allow(withOther))
        expect(allow(withTicket)).toBe(allow(withNone))
        // Y en los tres casos el header del ticket debe estar permitido.
        for (const response of [withTicket, withOther, withNone]) {
          expect(allow(response)).toContain(PTY_CONNECT_TOKEN_HEADER)
        }
      } finally {
        yield* Effect.promise(() => listener.stop(true))
      }
    }),
  )

  it.live("does not cache the preflight for so long that a fix cannot take effect", () =>
    Effect.gen(function* () {
      // Con 24h, un preflight equivocado sobrevive al arreglo: el navegador deja
      // de preguntar y sigue rechazando todo el día.
      const listener = yield* Effect.promise(() => Server.listen({ hostname: "127.0.0.1", port: 0 }))
      try {
        const url = new URL("/pty/pty_probe/connect-token", listener.url)
        const res = yield* Effect.promise(() => preflight(url, PTY_CONNECT_TOKEN_HEADER))
        const maxAge = Number(res.headers.get("access-control-max-age") ?? "0")

        expect(maxAge).toBeGreaterThan(0)
        expect(maxAge).toBeLessThanOrEqual(3600)
      } finally {
        yield* Effect.promise(() => listener.stop(true))
      }
    }),
  )
})

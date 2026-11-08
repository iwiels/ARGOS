import { afterEach, describe, expect } from "bun:test"
import { Effect, Layer } from "effect"
import { Database } from "@argos/core/database/database"
import { PermissionV2 } from "@argos/core/permission"
import { Project } from "@argos/core/project"
import { ProjectTable } from "@argos/core/project/sql"
import { SessionV2 } from "@argos/core/session"
import { SessionTable } from "@argos/core/session/sql"
import { AbsolutePath } from "@argos/core/schema"
import * as AuthSecretVault from "@argos/core/security/auth-secret-vault"
import * as ScopeService from "@argos/core/security/scope-service"
import { ToolRegistry } from "@argos/core/tool/registry"
import { WebBrowseTool } from "@argos/core/tool/web-browse"
import { testEffect } from "./lib/effect"
import { executeTool, toolIdentity } from "./lib/tool"

const SESSION_ID = SessionV2.ID.make("ses_web_browse_scope_test")

const database = Database.layerFromPath(":memory:")
const scope = ScopeService.layer.pipe(Layer.provide(database))
const assertions: PermissionV2.AssertInput[] = []
const permission = Layer.succeed(
  PermissionV2.Service,
  PermissionV2.Service.of({
    assert: (input) => Effect.sync(() => assertions.push(input)),
    ask: () => Effect.die("unused"),
    reply: () => Effect.die("unused"),
    get: () => Effect.die("unused"),
    forSession: () => Effect.die("unused"),
    list: () => Effect.die("unused"),
  }),
)
const registry = ToolRegistry.defaultLayer.pipe(Layer.provide(permission))
const authVault = Layer.succeed(
  AuthSecretVault.Service,
  AuthSecretVault.Service.of({
    get: () => Effect.succeed(null),
    put: () => Effect.void,
    delete: () => Effect.void,
  }),
)
const browse = WebBrowseTool.layerWithScopeService.pipe(
  Layer.provide(registry),
  Layer.provide(permission),
  Layer.provide(scope),
  Layer.provide(authVault),
)
const it = testEffect(Layer.mergeAll(database, scope, permission, registry, browse))

const seedSession = Effect.gen(function* () {
  const { db } = yield* Database.Service
  yield* db
    .insert(ProjectTable)
    .values({ id: Project.ID.global, worktree: AbsolutePath.make("/project"), sandboxes: [] })
    .onConflictDoNothing()
    .run()
    .pipe(Effect.orDie)
  yield* db
    .insert(SessionTable)
    .values({
      id: SESSION_ID,
      project_id: Project.ID.global,
      slug: SESSION_ID,
      directory: "/project",
      title: "web browse scope test",
      version: "test",
      scope_domains: ["*.allowed.test"],
    })
    .onConflictDoNothing()
    .run()
    .pipe(Effect.orDie)
})

type BrowserLog = {
  launches: number
  navigations: string[]
  aborted: string[]
  continued: string[]
  subrequests: string[]
}

/** Fake browser: no necesita Chromium instalado y registra lo que se le pide. */
const fakeBrowser = (log: BrowserLog) => {
  const makePage = () => {
    const handlers: Array<(route: any) => Promise<void>> = []
    return {
      async route(_pattern: string, handler: (route: any) => Promise<void>) {
        handlers.push(handler)
      },
      async goto(url: string) {
        log.navigations.push(url)
        // Cada subrequest de la página pasa por el guard de scope.
        for (const target of log.subrequests) {
          const route = {
            request: () => ({ url: () => target }),
            abort: async () => {
              log.aborted.push(target)
            },
            continue: async () => {
              log.continued.push(target)
            },
          }
          for (const handler of handlers) await handler(route)
        }
        return { status: () => 200 }
      },
      async title() {
        return "Fake page"
      },
      async $$eval() {
        return []
      },
      setDefaultTimeout() {},
    }
  }
  return {
    async newContext() {
      return {
        async newPage() {
          return makePage()
        },
        async storageState() {
          return {}
        },
        async close() {},
      }
    },
    async close() {},
  }
}

const call = (input: { action: "navigate"; url: string }) => ({
  sessionID: SESSION_ID,
  ...toolIdentity,
  call: { type: "tool-call" as const, id: "call-web-browse-scope", name: "web.browse", input },
})

const run = (url: string) =>
  Effect.gen(function* () {
    const registry = yield* ToolRegistry.Service
    const result = yield* executeTool(registry, call({ action: "navigate", url }))
    expect(result.type).toBe("text")
    return JSON.parse((result as { value: string }).value) as {
      action: string
      url: string
      success: boolean
      error?: string
    }
  })

afterEach(() => {
  WebBrowseTool.setBrowserLauncher(async () => {
    throw new Error("the browser must not be launched in this test")
  })
})

describe("web.browse — gate de scope", () => {
  it.effect(
    "una URL fuera de scope no navega: success=false con el motivo del bloqueo",
    () =>
      Effect.gen(function* () {
        yield* seedSession
        const log: BrowserLog = { launches: 0, navigations: [], aborted: [], continued: [], subrequests: [] }
        WebBrowseTool.setBrowserLauncher(async () => {
          log.launches++
          return fakeBrowser(log) as any
        })

        const output = yield* run("https://attacker.example.net/")

        expect(output.success).toBe(false)
        expect(output.error).toBeDefined()
        expect(output.error?.toUpperCase()).toContain("SCOPE ENFORCEMENT")
        expect(output.url).toBe("https://attacker.example.net/")
        // El navegador ni siquiera se lanza: el gate es previo.
        expect(log.launches).toBe(0)
        expect(log.navigations).toEqual([])
      }),
    { timeout: 15000 },
  )

  it.effect(
    "una URL dentro de scope navega y las subrequests fuera de scope se abortan",
    () =>
      Effect.gen(function* () {
        yield* seedSession
        const log: BrowserLog = {
          launches: 0,
          navigations: [],
          aborted: [],
          continued: [],
          subrequests: [
            "https://app.allowed.test/app.js",
            "https://exfil.example.net/beacon?d=1",
            "file:///etc/passwd",
          ],
        }
        WebBrowseTool.setBrowserLauncher(async () => {
          log.launches++
          return fakeBrowser(log) as any
        })

        const output = yield* run("https://app.allowed.test/")

        expect(output.success).toBe(true)
        expect(log.launches).toBe(1)
        expect(log.navigations).toEqual(["https://app.allowed.test/"])
        // Sólo la subrequest autorizada pasa; el beacon y el file:// se cortan.
        expect(log.continued).toEqual(["https://app.allowed.test/app.js"])
        expect(log.aborted).toEqual(["https://exfil.example.net/beacon?d=1", "file:///etc/passwd"])
      }),
    { timeout: 15000 },
  )

  it.effect(
    "un redirect a un host fuera de scope se aborta en vuelo",
    () =>
      Effect.gen(function* () {
        yield* seedSession
        const log: BrowserLog = {
          launches: 0,
          navigations: [],
          aborted: [],
          continued: [],
          subrequests: ["https://redirected.example.net/login"],
        }
        WebBrowseTool.setBrowserLauncher(async () => {
          log.launches++
          return fakeBrowser(log) as any
        })

        const output = yield* run("https://app.allowed.test/")

        expect(output.success).toBe(true)
        expect(log.aborted).toEqual(["https://redirected.example.net/login"])
        expect(log.continued).toEqual([])
      }),
    { timeout: 15000 },
  )
})

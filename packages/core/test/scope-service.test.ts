import { describe, expect } from "bun:test"
import { eq, sql } from "drizzle-orm"
import { Effect, Layer } from "effect"
import { Database } from "@argos/core/database/database"
import { EventV2 } from "@argos/core/event"
import { Location } from "@argos/core/location"
import { Project, ProjectV2 } from "@argos/core/project"
import { ProjectTable } from "@argos/core/project/sql"
import { AbsolutePath } from "@argos/core/schema"
import { SessionV2 } from "@argos/core/session"
import { SessionExecution } from "@argos/core/session/execution"
import { SessionProjector } from "@argos/core/session/projector"
import { SessionSchema } from "@argos/core/session/schema"
import { SessionStore } from "@argos/core/session/store"
import { SessionTable } from "@argos/core/session/sql"
import * as ScopeService from "@argos/core/security/scope-service"
import {
  evaluateScopeTarget,
  extractTargetHost,
  isPrivateAddress,
  matchCidr,
  matchesDomainPattern,
} from "@argos/core/security/scope-eval"
import { testEffect } from "./lib/effect"

const database = Database.layerFromPath(":memory:")
const events = EventV2.layer.pipe(Layer.provide(database))
const projects = Layer.succeed(
  ProjectV2.Service,
  ProjectV2.Service.of({
    resolve: (directory) => Effect.succeed({ id: ProjectV2.ID.global, directory }),
    directories: () => Effect.succeed([]),
    commit: () => Effect.void,
  }),
)
const projector = SessionProjector.layer.pipe(Layer.provide(events), Layer.provide(database))
const store = SessionStore.layer.pipe(Layer.provide(database))
const sessions = SessionV2.layer.pipe(
  Layer.provide(events),
  Layer.provide(database),
  Layer.provide(store),
  Layer.provide(projects),
  Layer.provide(SessionExecution.noopLayer),
)
const scope = ScopeService.layer.pipe(Layer.provide(database))
const it = testEffect(
  Layer.mergeAll(database, events, projects, projector, store, SessionExecution.noopLayer, sessions, scope),
)

const location = Location.Ref.make({ directory: AbsolutePath.make("/project") })

type ScopeColumns = {
  domains?: string[]
  cidrs?: string[]
  excluded?: string[]
}

const createSession = (title: string) =>
  Effect.gen(function* () {
    const session = yield* SessionV2.Service
    return yield* session.create({ location, title })
  })

const setSessionScope = (sessionID: SessionSchema.ID, value: ScopeColumns) =>
  Effect.gen(function* () {
    const { db } = yield* Database.Service
    yield* db
      .update(SessionTable)
      .set({
        scope_domains: value.domains ?? null,
        scope_cidrs: value.cidrs ?? null,
        scope_excluded: value.excluded ?? null,
      })
      .where(eq(SessionTable.id, sessionID))
      .run()
      .pipe(Effect.orDie)
  })

const setProjectScope = (value: {
  domains?: string[]
  cidrs?: string[]
  excluded?: string[]
} | null) =>
  Effect.gen(function* () {
    const { db } = yield* Database.Service
    yield* db
      .insert(ProjectTable)
      .values({
        id: Project.ID.global,
        worktree: AbsolutePath.make("/project"),
        sandboxes: [],
        scope: value ?? undefined,
      })
      .onConflictDoUpdate({
        target: ProjectTable.id,
        set: value === null ? { scope: sql`null` } : { scope: value },
      })
      .run()
      .pipe(Effect.orDie)
  })

describe("Scope evaluation primitives (scope-eval)", () => {
  describe("matchesDomainPattern", () => {
    it.effect("matches wildcard domains but not lookalikes", () =>
      Effect.sync(() => {
        expect(matchesDomainPattern("a.example.com", "*.example.com")).toBe(true)
        expect(matchesDomainPattern("deep.nested.example.com", "*.example.com")).toBe(true)
        expect(matchesDomainPattern("example.com", "*.example.com")).toBe(true)
        expect(matchesDomainPattern("notexample.com", "*.example.com")).toBe(false)
        expect(matchesDomainPattern("example.com.evil.net", "*.example.com")).toBe(false)
      }),
    )
  })

  describe("matchCidr", () => {
    it.effect("evaluates /0, /24, /32, direct IPs and invalid CIDRs", () =>
      Effect.sync(() => {
        // /0 matchea cualquier IPv4
        expect(matchCidr("8.8.8.8", "0.0.0.0/0")).toBe(true)
        expect(matchCidr("10.1.2.3", "0.0.0.0/0")).toBe(true)
        // /24
        expect(matchCidr("192.168.1.50", "192.168.1.0/24")).toBe(true)
        expect(matchCidr("192.168.2.50", "192.168.1.0/24")).toBe(false)
        // /32
        expect(matchCidr("10.0.0.5", "10.0.0.5/32")).toBe(true)
        expect(matchCidr("10.0.0.6", "10.0.0.5/32")).toBe(false)
        // IP directa
        expect(matchCidr("10.0.0.1", "10.0.0.1")).toBe(true)
        expect(matchCidr("10.0.0.2", "10.0.0.1")).toBe(false)
        // CIDR inválido
        expect(matchCidr("10.0.0.1", "10.0.0.0/33")).toBe(false)
        expect(matchCidr("10.0.0.1", "not-a-cidr")).toBe(false)
      }),
    )
  })

  describe("extractTargetHost", () => {
    it.effect("normalizes URLs, bare hosts and paths", () =>
      Effect.sync(() => {
        expect(extractTargetHost("https://App.Example.com/login")).toEqual({
          host: "app.example.com",
          path: "/login",
        })
        expect(extractTargetHost("api.partner.io")).toEqual({ host: "api.partner.io", path: "/" })
      }),
    )
  })

  describe("isPrivateAddress", () => {
    it.effect("detects RFC1918, loopback, link-local, metadata, ULA and multicast", () =>
      Effect.sync(() => {
        // RFC1918
        expect(isPrivateAddress("10.0.0.1")).toBe(true)
        expect(isPrivateAddress("172.16.0.1")).toBe(true)
        expect(isPrivateAddress("172.31.255.254")).toBe(true)
        expect(isPrivateAddress("192.168.1.1")).toBe(true)
        // Loopback
        expect(isPrivateAddress("127.0.0.1")).toBe(true)
        expect(isPrivateAddress("127.255.255.254")).toBe(true)
        expect(isPrivateAddress("::1")).toBe(true)
        // Link-local / metadata de nube
        expect(isPrivateAddress("169.254.169.254")).toBe(true)
        expect(isPrivateAddress("169.254.0.1")).toBe(true)
        // Unspecified
        expect(isPrivateAddress("0.0.0.0")).toBe(true)
        expect(isPrivateAddress("::")).toBe(true)
        // Multicast
        expect(isPrivateAddress("224.0.0.1")).toBe(true)
        expect(isPrivateAddress("ff02::1")).toBe(true)
        // IPv6 ULA
        expect(isPrivateAddress("fc00::1")).toBe(true)
        expect(isPrivateAddress("fd12:3456::1")).toBe(true)
        // IPv4 mapeado en IPv6
        expect(isPrivateAddress("::ffff:127.0.0.1")).toBe(true)
        expect(isPrivateAddress("::ffff:169.254.169.254")).toBe(true)
      }),
    )

    it.effect("does not flag public addresses nor hostnames", () =>
      Effect.sync(() => {
        expect(isPrivateAddress("8.8.8.8")).toBe(false)
        expect(isPrivateAddress("1.1.1.1")).toBe(false)
        expect(isPrivateAddress("172.32.0.1")).toBe(false)
        expect(isPrivateAddress("2001:4860:4860::8888")).toBe(false)
        expect(isPrivateAddress("::ffff:8.8.8.8")).toBe(false)
        expect(isPrivateAddress("example.com")).toBe(false)
        expect(isPrivateAddress("localhost")).toBe(false)
      }),
    )
  })

  describe("evaluateScopeTarget", () => {
    it.effect("applies path exclusions over authorized domains", () =>
      Effect.sync(() => {
        const scope = {
          domains: ["*.example.com"],
          excluded: ["/logout", "/api/v1/billing/*"],
        }
        expect(evaluateScopeTarget("https://app.example.com/login", scope).allowed).toBe(true)

        const logout = evaluateScopeTarget("https://app.example.com/logout", scope)
        expect(logout.allowed).toBe(false)
        expect(logout.reason).toContain("explicitly excluded")

        const billing = evaluateScopeTarget("https://app.example.com/api/v1/billing/charge", scope)
        expect(billing.allowed).toBe(false)
        expect(billing.reason).toContain("explicitly excluded")
      }),
    )

    it.effect("fails closed when no scope is declared", () =>
      Effect.sync(() => {
        expect(evaluateScopeTarget("https://anything.example.org").allowed).toBe(false)
        expect(evaluateScopeTarget("https://anything.example.org", {}).allowed).toBe(false)
        expect(evaluateScopeTarget("https://anything.example.org").reason).toContain("No authorized scope is configured")
      }),
    )
  })
})

describe("ScopeService", () => {
  describe("forSession", () => {
    it.effect("prefers the session scope over the project scope", () =>
      Effect.gen(function* () {
        yield* setProjectScope({ domains: ["project.example.com"], cidrs: ["10.0.0.0/8"] })
        const created = yield* createSession("Session scope wins")
        yield* setSessionScope(created.id, { domains: ["session.example.com"] })

        const service = yield* ScopeService.Service
        const policy = yield* service.forSession(created.id)

        expect(policy?.domains).toEqual(["session.example.com"])
        expect(policy?.cidrs).toBeUndefined()
      }),
    )

    it.effect("inherits the project scope when the session has none", () =>
      Effect.gen(function* () {
        yield* setProjectScope({ domains: ["project.example.com"], cidrs: ["10.0.0.0/8"] })
        const created = yield* createSession("Inherits project scope")

        const service = yield* ScopeService.Service
        const policy = yield* service.forSession(created.id)

        expect(policy?.domains).toEqual(["project.example.com"])
        expect(policy?.cidrs).toEqual(["10.0.0.0/8"])
      }),
    )

    it.effect("returns undefined when neither the session nor the project declare a scope", () =>
      Effect.gen(function* () {
        yield* setProjectScope(null)
        const created = yield* createSession("No scope at all")

        const service = yield* ScopeService.Service
        const policy = yield* service.forSession(created.id)

        expect(policy).toBeUndefined()
      }),
    )
  })

  describe("assertNoPrivateByDefault", () => {
    it.effect("rejects the cloud metadata endpoint when the scope does not authorize it", () =>
      Effect.gen(function* () {
        const service = yield* ScopeService.Service
        const error = yield* service
          .assertNoPrivateByDefault("http://169.254.169.254/latest/meta-data/", {
            domains: ["*.example.com"],
          })
          .pipe(Effect.flip)

        expect(error).toBeInstanceOf(ScopeService.ScopeViolationError)
        expect(error._tag).toBe("ScopeViolationError")
        expect(error.reason.startsWith("SCOPE ENFORCEMENT:")).toBe(true)
        expect(error.reason).toContain("private address")
      }),
    )

    it.effect("rejects RFC1918 and loopback targets when the scope does not authorize them", () =>
      Effect.gen(function* () {
        const service = yield* ScopeService.Service

        const rfc1918 = yield* service
          .assertNoPrivateByDefault("http://192.168.10.5/", { domains: ["*.example.com"] })
          .pipe(Effect.flip)
        expect(rfc1918._tag).toBe("ScopeViolationError")

        const loopback = yield* service
          .assertNoPrivateByDefault("http://127.0.0.1:8080/", { domains: ["*.example.com"] })
          .pipe(Effect.flip)
        expect(loopback._tag).toBe("ScopeViolationError")
      }),
    )

    it.effect("allows loopback when the scope declares it explicitly", () =>
      Effect.gen(function* () {
        const service = yield* ScopeService.Service

        yield* service.assertNoPrivateByDefault("http://127.0.0.1:8080/", { cidrs: ["127.0.0.0/8"] })
        yield* service.assertNoPrivateByDefault("http://169.254.169.254/", { cidrs: ["169.254.0.0/16"] })
      }),
    )

    it.effect("does not let a domain entry authorize a private address", () =>
      Effect.gen(function* () {
        const service = yield* ScopeService.Service
        const error = yield* service
          .assertNoPrivateByDefault("http://127.0.0.1:8080/", { domains: ["127.0.0.1"] })
          .pipe(Effect.flip)

        expect(error._tag).toBe("ScopeViolationError")
      }),
    )

    it.effect("blocks private addresses when no scope is declared", () =>
      Effect.gen(function* () {
        const service = yield* ScopeService.Service
        const error = yield* service.assertNoPrivateByDefault("http://169.254.169.254/latest/meta-data/").pipe(Effect.flip)
        expect(error._tag).toBe("ScopeViolationError")
      }),
    )

    it.effect("does not flag public addresses", () =>
      Effect.gen(function* () {
        const service = yield* ScopeService.Service
        yield* service.assertNoPrivateByDefault("https://8.8.8.8/", { domains: ["*.example.com"] })
      }),
    )
  })

  describe("assertTarget", () => {
    it.effect("blocks every target until the session or its project defines an allowlist", () =>
      Effect.gen(function* () {
        yield* setProjectScope(null)
        const created = yield* createSession("No scope blocks network access")
        const service = yield* ScopeService.Service
        const error = yield* service.assertTarget(created.id, "https://example.com").pipe(Effect.flip)

        expect(error._tag).toBe("ScopeViolationError")
        expect(error.reason).toContain("No authorized scope is configured")
      }),
    )

    it.effect("fails with ScopeViolationError when the target is out of scope", () =>
      Effect.gen(function* () {
        const created = yield* createSession("Out of scope target")
        yield* setSessionScope(created.id, { domains: ["*.corp.local"] })

        const service = yield* ScopeService.Service
        const error = yield* service.assertTarget(created.id, "https://unauthorized.target.com").pipe(Effect.flip)

        expect(error).toBeInstanceOf(ScopeService.ScopeViolationError)
        expect(error._tag).toBe("ScopeViolationError")
        expect(error.reason.startsWith("SCOPE ENFORCEMENT:")).toBe(true)
        expect(error.reason).toContain("out of authorized scope")
      }),
    )

    it.effect("fails with ScopeViolationError when the target is a private address", () =>
      Effect.gen(function* () {
        const created = yield* createSession("Private target")
        yield* setSessionScope(created.id, { domains: ["169.254.169.254"] })

        const service = yield* ScopeService.Service
        const error = yield* service.assertTarget(created.id, "http://169.254.169.254/latest/meta-data/").pipe(
          Effect.flip,
        )

        expect(error._tag).toBe("ScopeViolationError")
        expect(error.reason.startsWith("SCOPE ENFORCEMENT:")).toBe(true)
        expect(error.reason).toContain("private address")
      }),
    )

    it.effect("passes for in-scope targets", () =>
      Effect.gen(function* () {
        const created = yield* createSession("In scope target")
        yield* setSessionScope(created.id, { domains: ["*.corp.local"], excluded: ["admin.corp.local"] })

        const service = yield* ScopeService.Service
        yield* service.assertTarget(created.id, "https://app.corp.local/login")
      }),
    )
  })
})

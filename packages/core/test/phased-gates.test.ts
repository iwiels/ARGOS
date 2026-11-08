import { describe, expect } from "bun:test"
import { Effect, Layer } from "effect"
import { Database } from "@argos/core/database/database"
import { EventV2 } from "@argos/core/event"
import { Location } from "@argos/core/location"
import { Project, ProjectV2 } from "@argos/core/project"
import { ProjectTable } from "@argos/core/project/sql"
import { AbsolutePath } from "@argos/core/schema"
import { SessionV2 } from "@argos/core/session"
import { SessionTable } from "@argos/core/session/sql"
import { SessionSchema } from "@argos/core/session/schema"
import { SessionProjector } from "@argos/core/session/projector"
import { SessionStore } from "@argos/core/session/store"
import { SessionExecution } from "@argos/core/session/execution"
import {
  classifyToolPhase,
  evaluatePhasedGate,
  enforcePhasedGate,
  evaluateScopeTarget,
  PhasedGateBlockedError,
} from "@argos/core/security/gates"
import * as ScopeService from "@argos/core/security/scope-service"
import { ingestToolPart } from "@argos/core/security/ingest"
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
  Layer.mergeAll(
    database,
    events,
    projects,
    projector,
    store,
    SessionExecution.noopLayer,
    sessions,
    scope,
  ),
)

const location = Location.Ref.make({ directory: AbsolutePath.make("/project") })

/**
 * El bypass de las compuertas por fases sólo se activa con `NODE_ENV=test` o
 * con `ARGOS_ALLOW_PHASED_GATE_BYPASS=1`. Para ejercitar la compuerta real hay
 * que correr fuera de ese modo.
 */
const withPhasedGatesActive = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
  Effect.gen(function* () {
    const previous = process.env.NODE_ENV
    process.env.NODE_ENV = "production"
    try {
      return yield* effect
    } finally {
      if (previous === undefined) delete process.env.NODE_ENV
      else process.env.NODE_ENV = previous
    }
  })

describe("Phased Gates (Deterministic Stage Enforcement)", () => {
  describe("classifyToolPhase", () => {
    it.effect("classifies reconnaissance tools as ola1_recon", () =>
      Effect.sync(() => {
        expect(classifyToolPhase("web.probe")).toBe("ola1_recon")
        expect(classifyToolPhase("web.subdomains")).toBe("ola1_recon")
        expect(classifyToolPhase("web.crawl")).toBe("ola1_recon")
        expect(classifyToolPhase("web.tech")).toBe("ola1_recon")
        expect(classifyToolPhase("lan.discovery")).toBe("ola1_recon")
        expect(classifyToolPhase("argos_memory_save")).toBe("ola1_recon")
      }),
    )

    it.effect("classifies deep scan and exploitation tools as ola2_exploit", () =>
      Effect.sync(() => {
        expect(classifyToolPhase("web.sqli")).toBe("ola2_exploit")
        expect(classifyToolPhase("web.scan")).toBe("ola2_exploit")
        expect(classifyToolPhase("web.fuzz")).toBe("ola2_exploit")
        expect(classifyToolPhase("web.xss")).toBe("ola2_exploit")
        expect(classifyToolPhase("lan.port_scan")).toBe("ola2_exploit")
      }),
    )

    it.effect("classifies unlisted tools as general", () =>
      Effect.sync(() => {
        expect(classifyToolPhase("custom_utility")).toBe("general")
      }),
    )
  })

  describe("evaluatePhasedGate & enforcePhasedGate", () => {
    it.effect("allows Ola 1 reconnaissance tools unconditionally on empty sessions", () =>
      withPhasedGatesActive(
        Effect.gen(function* () {
          const { db } = yield* Database.Service
          const session = yield* SessionV2.Service
          const created = yield* session.create({ location, title: "Empty Audit" })

          const result = yield* evaluatePhasedGate({
            db,
            sessionID: created.id,
            toolName: "web.probe",
          })

          expect(result.allowed).toBe(true)
          expect(result.phase).toBe("ola1_recon")
          expect(result.reconAssetsCount).toBe(0)
        }),
      ),
    )

    it.effect("blocks Ola 2 exploitation tools when no reconnaissance assets exist", () =>
      withPhasedGatesActive(
        Effect.gen(function* () {
          const { db } = yield* Database.Service
          const session = yield* SessionV2.Service
          const created = yield* session.create({ location, title: "Empty Audit 2" })

          const result = yield* evaluatePhasedGate({
            db,
            sessionID: created.id,
            toolName: "web.sqli",
          })

          expect(result.allowed).toBe(false)
          expect(result.phase).toBe("ola2_exploit")
          expect(result.reconAssetsCount).toBe(0)
          expect(result.reason).toContain("Ola 1 (Reconnaissance")

          // enforcePhasedGate debe fallar con PhasedGateBlockedError
          const error = yield* enforcePhasedGate({
            db,
            sessionID: created.id,
            toolName: "web.sqli",
          }).pipe(
            Effect.flip,
            Effect.map((e) => e._tag),
          )

          expect(error).toBe("PhasedGateBlockedError")
        }),
      ),
    )

    it.effect("unblocks Ola 2 exploitation tools once Ola 1 reconnaissance assets are recorded", () =>
      withPhasedGatesActive(
        Effect.gen(function* () {
          const { db } = yield* Database.Service
          yield* db
            .insert(ProjectTable)
            .values({ id: Project.ID.global, worktree: AbsolutePath.make("/project"), sandboxes: [] })
            .onConflictDoNothing()
            .run()
            .pipe(Effect.orDie)

          const sessionID = SessionSchema.ID.make("ses_gate_active_test")
          yield* db
            .insert(SessionTable)
            .values({
              id: sessionID,
              project_id: Project.ID.global,
              slug: "gate-test",
              directory: "/project",
              title: "gate test",
              version: "test",
            })
            .onConflictDoNothing()
            .run()
            .pipe(Effect.orDie)

          // 1. Verificar que inicialmente esté bloqueado
          const preResult = yield* evaluatePhasedGate({
            db,
            sessionID,
            toolName: "web.scan",
          })
          expect(preResult.allowed).toBe(false)

          // 2. Simular hallazgo/activo descubierto en Ola 1 e ingestarlo
          yield* ingestToolPart(db, {
            sessionID,
            type: "tool",
            tool: "argos_memory_save",
            state: {
              status: "completed",
              input: {
                kind: "finding",
                title: "Live Host Discovered: api.example.com",
                severity: "info",
                target: "https://api.example.com",
                source_tool: "web.probe",
                evidence: "The in-scope host resolved and returned an HTTP response during reconnaissance.",
                agent_assessment: "I confirmed this host belongs to the authorized target scope and is reachable.",
                impact: "The host adds an application endpoint to the verified audit surface.",
              },
            },
          })

          // 3. Verificar que ahora la compuerta de Ola 2 se abre con 1 activo confirmado
          const postResult = yield* evaluatePhasedGate({
            db,
            sessionID,
            toolName: "web.scan",
          })
          expect(postResult.allowed).toBe(true)
          expect(postResult.phase).toBe("ola2_exploit")
          expect(postResult.reconAssetsCount).toBe(1)

          // enforcePhasedGate pasa sin error
          yield* enforcePhasedGate({
            db,
            sessionID,
            toolName: "web.scan",
          })
        }),
      ),
    )
  })

  describe("evaluateScopeTarget & Phased Gate Scope Enforcement", () => {
    it.effect("allows in-scope wildcards and exact domains", () =>
      Effect.sync(() => {
        const scope = {
          domains: ["*.target.corp", "api.partner.io", "https://portal.company.com/"],
          cidrs: ["192.168.1.0/24", "10.10.10.50/32", "172.16.0.0/12", "192.168.2.128/25", "10.0.0.1"],
          excluded: ["billing.target.corp", "/logout", "/api/v1/billing/*", "192.168.1.99/32"],
        }
        expect(evaluateScopeTarget("https://app.target.corp/login", scope).allowed).toBe(true)
        expect(evaluateScopeTarget("https://target.corp", scope).allowed).toBe(true)
        expect(evaluateScopeTarget("api.partner.io", scope).allowed).toBe(true)
        expect(evaluateScopeTarget("portal.company.com", scope).allowed).toBe(true)
        // CIDR subnet evaluation
        expect(evaluateScopeTarget("192.168.1.50", scope).allowed).toBe(true)
        expect(evaluateScopeTarget("10.10.10.50", scope).allowed).toBe(true)
        expect(evaluateScopeTarget("172.20.100.5", scope).allowed).toBe(true) // within /12
        expect(evaluateScopeTarget("192.168.2.200", scope).allowed).toBe(true) // within /25 (128-255)
        expect(evaluateScopeTarget("10.0.0.1", scope).allowed).toBe(true) // direct IP
      }),
    )

    it.effect("blocks targets that are out of authorized scope", () =>
      Effect.sync(() => {
        const scope = {
          domains: ["*.target.corp"],
          cidrs: ["192.168.1.0/24", "192.168.2.128/25"],
        }
        const result = evaluateScopeTarget("https://evil.external.com", scope)
        expect(result.allowed).toBe(false)
        expect(result.reason).toContain("out of authorized scope")

        // 192.168.2.50 is outside /25 (128-255)
        const outOfCidr = evaluateScopeTarget("192.168.2.50", scope)
        expect(outOfCidr.allowed).toBe(false)
      }),
    )

    it.effect("strictly blocks excluded hosts and paths even within authorized domains", () =>
      Effect.sync(() => {
        const scope = {
          domains: ["*.target.corp"],
          cidrs: ["192.168.1.0/24"],
          excluded: ["billing.target.corp", "/logout", "/api/v1/billing/*", "192.168.1.99/32"],
        }
        const hostBlocked = evaluateScopeTarget("https://billing.target.corp/dashboard", scope)
        expect(hostBlocked.allowed).toBe(false)
        expect(hostBlocked.reason).toContain("explicitly excluded")

        const pathBlocked = evaluateScopeTarget("https://app.target.corp/logout", scope)
        expect(pathBlocked.allowed).toBe(false)
        expect(pathBlocked.reason).toContain("explicitly excluded")

        const wildcardPathBlocked = evaluateScopeTarget("https://app.target.corp/api/v1/billing/charge", scope)
        expect(wildcardPathBlocked.allowed).toBe(false)
        expect(wildcardPathBlocked.reason).toContain("explicitly excluded")

        // CIDR exclusion
        const cidrExclusionBlocked = evaluateScopeTarget("192.168.1.99", scope)
        expect(cidrExclusionBlocked.allowed).toBe(false)
        expect(cidrExclusionBlocked.reason).toContain("explicitly excluded")
      }),
    )

    it.effect("evaluatePhasedGate blocks tools targeting out-of-scope destinations", () =>
      withPhasedGatesActive(
        Effect.gen(function* () {
          const session = yield* SessionV2.Service
          const { db } = yield* Database.Service

          const created = yield* session.create({
            location,
            title: "Scope Protected Session",
          })

          // Configurar scope en la sesión
          const { eq } = yield* Effect.promise(() => import("drizzle-orm"))
          yield* db
            .update(SessionTable)
            .set({
              scope_domains: ["*.corp.local"],
              scope_excluded: ["admin.corp.local"],
            })
            .where(eq(SessionTable.id, created.id))
            .run()
            .pipe(Effect.orDie)

          // Objetivo fuera de scope: debe bloquearse
          const blockedResult = yield* evaluatePhasedGate({
            db,
            sessionID: created.id,
            toolName: "web.probe",
            target: "https://unauthorized.target.com",
          })
          expect(blockedResult.allowed).toBe(false)
          expect(blockedResult.reason).toContain("out of authorized scope")

          // Objetivo excluido: debe bloquearse
          const excludedResult = yield* evaluatePhasedGate({
            db,
            sessionID: created.id,
            toolName: "web.probe",
            target: "https://admin.corp.local",
          })
          expect(excludedResult.allowed).toBe(false)
          expect(excludedResult.reason).toContain("explicitly excluded")

          // Objetivo en scope: debe permitirse
          const allowedResult = yield* evaluatePhasedGate({
            db,
            sessionID: created.id,
            toolName: "web.probe",
            target: "https://app.corp.local",
          })
          expect(allowedResult.allowed).toBe(true)
        }),
      ),
    )
  })

  describe("phased gate bypass", () => {
    it.effect("is disabled by default outside of test environments", () =>
      Effect.gen(function* () {
        const { db } = yield* Database.Service
        const session = yield* SessionV2.Service
        const created = yield* session.create({ location, title: "Bypass Disabled" })

        const previous = process.env.NODE_ENV
        process.env.NODE_ENV = "production"
        delete process.env.ARGOS_PHASED_GATES_DISABLED
        delete process.env.ARGOS_ALLOW_PHASED_GATE_BYPASS
        try {
          const result = yield* evaluatePhasedGate({
            db,
            sessionID: created.id,
            toolName: "web.sqli",
          })
          expect(result.allowed).toBe(false)
          expect(result.reconAssetsCount).toBe(0)
        } finally {
          if (previous === undefined) delete process.env.NODE_ENV
          else process.env.NODE_ENV = previous
        }
      }),
    )

    it.effect("ignores the legacy ARGOS_PHASED_GATES_DISABLED switch outside of test environments", () =>
      Effect.gen(function* () {
        const { db } = yield* Database.Service
        const session = yield* SessionV2.Service
        const created = yield* session.create({ location, title: "Legacy Bypass Ignored" })

        const previous = process.env.NODE_ENV
        const previousLegacy = process.env.ARGOS_PHASED_GATES_DISABLED
        process.env.NODE_ENV = "production"
        process.env.ARGOS_PHASED_GATES_DISABLED = "1"
        try {
          const result = yield* evaluatePhasedGate({
            db,
            sessionID: created.id,
            toolName: "web.sqli",
          })
          expect(result.allowed).toBe(false)
        } finally {
          if (previous === undefined) delete process.env.NODE_ENV
          else process.env.NODE_ENV = previous
          if (previousLegacy === undefined) delete process.env.ARGOS_PHASED_GATES_DISABLED
          else process.env.ARGOS_PHASED_GATES_DISABLED = previousLegacy
        }
      }),
    )

    it.effect("honours ARGOS_ALLOW_PHASED_GATE_BYPASS outside of test environments", () =>
      Effect.gen(function* () {
        const { db } = yield* Database.Service
        const session = yield* SessionV2.Service
        const created = yield* session.create({ location, title: "Explicit Bypass" })

        const previous = process.env.NODE_ENV
        const previousFlag = process.env.ARGOS_ALLOW_PHASED_GATE_BYPASS
        process.env.NODE_ENV = "production"
        process.env.ARGOS_ALLOW_PHASED_GATE_BYPASS = "1"
        try {
          const result = yield* evaluatePhasedGate({
            db,
            sessionID: created.id,
            toolName: "web.sqli",
          })
          expect(result.allowed).toBe(true)
          expect(result.reconAssetsCount).toBe(999)
        } finally {
          if (previous === undefined) delete process.env.NODE_ENV
          else process.env.NODE_ENV = previous
          if (previousFlag === undefined) delete process.env.ARGOS_ALLOW_PHASED_GATE_BYPASS
          else process.env.ARGOS_ALLOW_PHASED_GATE_BYPASS = previousFlag
        }
      }),
    )
  })
})

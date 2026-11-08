import { describe, expect } from "bun:test"
import { Effect } from "effect"
import { Database } from "../src/database/database"
import { AbsolutePath } from "../src/schema"
import { ProjectTable } from "../src/project/sql"
import { SessionTable } from "../src/session/sql"
import { ExecutionService } from "../src/security/execution"
import { DurableBudgetService } from "../src/security/durable-budget"
import { AuthProfileService } from "../src/security/auth-profile"
import { SurfaceNormalizer } from "../src/security/surface"
import { SurfaceCoverageService } from "../src/security/coverage"
import { RemediationPatchService } from "../src/security/remediation-patch"
import { testEffect } from "./lib/effect"

const database = Database.layerFromPath(":memory:")
const it = testEffect(database)

describe("Autonomous, Configurable & Verifiable Auditing (Etapa 3)", () => {
  it.effect("executes tasks, persists checkpoints, and resumes without re-running completed steps", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service

      const projectID = "proj-stage3-test"
      const sessionID = "sess-stage3-test"

      yield* db
        .insert(ProjectTable)
        .values({
          id: projectID as any,
          name: "Stage 3 Project",
          worktree: AbsolutePath.make("/project"),
          sandboxes: [],
          time_created: Date.now(),
          time_updated: Date.now(),
        })
        .run()
        .pipe(Effect.orDie)

      yield* db
        .insert(SessionTable)
        .values({
          id: sessionID as any,
          project_id: projectID as any,
          slug: sessionID,
          directory: "/project" as any,
          title: "Stage 3 Session",
          version: "1.0",
          time_created: Date.now(),
          time_updated: Date.now(),
        })
        .run()
        .pipe(Effect.orDie)

      // 1. Crear e iniciar tarea
      const { taskID } = yield* ExecutionService.createTask(db, {
        sessionID,
        projectID,
        type: "web_scan",
        target: "https://api.target.com",
      })

      yield* ExecutionService.startTask(db, taskID)

      // 2. Guardar checkpoints
      yield* ExecutionService.saveCheckpoint(db, {
        taskID,
        sessionID,
        stepName: "recon_ports",
        stepIndex: 1,
        completedSteps: ["init", "recon_ports"],
        stateSnapshot: { openPorts: [80, 443] },
        progress: 25,
      })

      yield* ExecutionService.saveCheckpoint(db, {
        taskID,
        sessionID,
        stepName: "crawl_endpoints",
        stepIndex: 2,
        completedSteps: ["init", "recon_ports", "crawl_endpoints"],
        stateSnapshot: { endpoints: ["/api/v1/users", "/api/v1/auth"] },
        progress: 50,
      })

      // 3. Pausar y reanudar
      yield* ExecutionService.pauseTask(db, taskID)
      const pausedTask = yield* ExecutionService.getTask(db, taskID)
      expect(pausedTask?.status).toBe("paused")

      // Verify listResumableTasks discovers the paused execution upon reopening
      const resumableList = yield* ExecutionService.listResumableTasks(db, { sessionID })
      expect(resumableList).toHaveLength(1)
      expect(resumableList[0].id).toBe(taskID)

      const resumeInfo = yield* ExecutionService.resumeTask(db, taskID)
      expect(resumeInfo.status).toBe("running")
      expect(resumeInfo.resumeStep).toBe("crawl_endpoints")
      expect(resumeInfo.completedSteps).toContain("crawl_endpoints")
      expect((resumeInfo.stateSnapshot as any).endpoints).toHaveLength(2)

      // 4. Completar
      yield* ExecutionService.completeTask(db, taskID)
      const finishedTask = yield* ExecutionService.getTask(db, taskID)
      expect(finishedTask?.status).toBe("completed")
      expect(finishedTask?.progress).toBe(100)

      // 5. Test crash resumption fallback on an interrupted task with no checkpoints
      const { taskID: crashedTaskID } = yield* ExecutionService.createTask(db, {
        sessionID,
        projectID,
        type: "api_audit",
        target: "https://api.target.com/v2",
      })
      yield* ExecutionService.interruptTask(db, crashedTaskID, "Host SIGKILL before first checkpoint")
      const crashedResume = yield* ExecutionService.resumeTask(db, crashedTaskID)
      expect(crashedResume.status).toBe("running")
      expect(crashedResume.resumeStep).toBe("start")
      expect(crashedResume.completedSteps).toEqual([])
    }),
  )

  it.effect("tracks durable token and model costs and enforces hard budget limits", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      const projectID = "proj-budget-test"
      const sessionID = "sess-budget-test"

      yield* db
        .insert(ProjectTable)
        .values({
          id: projectID as any,
          name: "Budget Project",
          worktree: AbsolutePath.make("/project"),
          sandboxes: [],
          time_created: Date.now(),
          time_updated: Date.now(),
        })
        .run()
        .pipe(Effect.orDie)

      yield* db
        .insert(SessionTable)
        .values({
          id: sessionID as any,
          project_id: projectID as any,
          slug: sessionID,
          directory: "/project" as any,
          title: "Budget Session",
          version: "1.0",
          time_created: Date.now(),
          time_updated: Date.now(),
        })
        .run()
        .pipe(Effect.orDie)

      // Registrar 2 turnos con tokens
      yield* DurableBudgetService.recordUsage(db, {
        sessionID,
        projectID,
        model: "claude-3-5-sonnet",
        inputTokens: 10_000,
        outputTokens: 2_000,
        toolCalls: 5,
        externalApiCalls: 2,
      })

      yield* DurableBudgetService.recordUsage(db, {
        sessionID,
        projectID,
        model: "claude-3-5-sonnet",
        inputTokens: 20_000,
        outputTokens: 4_000,
        toolCalls: 3,
        externalApiCalls: 1,
      })

      const usage = yield* DurableBudgetService.getUsage(db, sessionID)
      expect(usage.turnsCount).toBe(2)
      expect(usage.tokensInput).toBe(30_000)
      expect(usage.tokensOutput).toBe(6_000)
      expect(usage.toolCalls).toBe(8)
      expect(usage.externalApiCalls).toBe(3)
      expect(usage.totalCostUsd).toBeGreaterThan(0)

      // Exceder límite intencionalmente
      const limitCheck = yield* DurableBudgetService.assertWithinLimits(db, sessionID, {
        maxTurns: 1,
      }).pipe(
        Effect.map(() => false),
        Effect.catch(() => Effect.succeed(true)),
      )
      expect(limitCheck).toBe(true)
    }),
  )

  it.effect("stores role-based auth profiles and executes preflight validation", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      const projectID = "proj-auth-test"

      yield* db
        .insert(ProjectTable)
        .values({
          id: projectID as any,
          name: "Auth Project",
          worktree: AbsolutePath.make("/project"),
          sandboxes: [],
          time_created: Date.now(),
          time_updated: Date.now(),
        })
        .run()
        .pipe(Effect.orDie)

      // Guardar perfil admin con Bearer token
      const res = yield* AuthProfileService.saveProfile(db, {
        projectID,
        roleName: "admin",
        authType: "bearer",
        credentials: { token: "secret-token-xyz" },
        preflightUrl: "https://api.example.com/me",
      })

      expect(res.roleName).toBe("admin")

      const profiles = yield* AuthProfileService.listProfiles(db, projectID)
      expect(profiles).toHaveLength(1)
      expect(profiles[0].auth_type).toBe("bearer")

      const headers = AuthProfileService.getAuthHeaders(profiles[0])
      expect(headers["Authorization"]).toBe("Bearer secret-token-xyz")

      // Preflight mock
      const mockFetch = async () => new Response("OK", { status: 200 })
      const preflight = yield* AuthProfileService.performPreflight(db, profiles[0].id, mockFetch as any)
      expect(preflight.valid).toBe(true)
    }),
  )

  it.effect("tracks attack surface coverage and generates ledger metrics", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      const projectID = "proj-cov-test"
      const sessionID = "sess-cov-test"

      yield* db
        .insert(ProjectTable)
        .values({
          id: projectID as any,
          name: "Coverage Project",
          worktree: AbsolutePath.make("/project"),
          sandboxes: [],
          time_created: Date.now(),
          time_updated: Date.now(),
        })
        .run()
        .pipe(Effect.orDie)

      yield* db
        .insert(SessionTable)
        .values({
          id: sessionID as any,
          project_id: projectID as any,
          slug: sessionID,
          directory: "/project" as any,
          title: "Coverage Session",
          version: "1.0",
          time_created: Date.now(),
          time_updated: Date.now(),
        })
        .run()
        .pipe(Effect.orDie)

      yield* SurfaceCoverageService.recordCoverage(db, {
        sessionID,
        projectID,
        targetUrl: "https://api.target.com/users",
        method: "GET",
        role: "admin",
        status: "executed",
        toolsExecuted: ["nuclei", "zap"],
        findingsCount: 2,
      })

      yield* SurfaceCoverageService.recordCoverage(db, {
        sessionID,
        projectID,
        targetUrl: "https://api.target.com/login",
        method: "POST",
        role: "anonymous",
        status: "no_findings",
        toolsExecuted: ["nuclei"],
        findingsCount: 0,
      })

      yield* SurfaceCoverageService.recordCoverage(db, {
        sessionID,
        projectID,
        targetUrl: "https://api.target.com/internal/metrics",
        method: "GET",
        role: "anonymous",
        status: "blocked",
        reason: "403 Forbidden without credentials",
      })

      const summary = yield* SurfaceCoverageService.getCoverageSummary(db, sessionID)
      expect(summary.totalEndpoints).toBe(3)
      expect(summary.executedCount).toBe(2)
      expect(summary.counts.executed).toBe(1)
      expect(summary.counts.no_findings).toBe(1)
      expect(summary.counts.blocked).toBe(1)
      expect(summary.coverageRate).toBe(66.7)
      expect(summary.totalFindings).toBe(2)
    }),
  )

  it.effect("normalizes OpenAPI 3.x and Postman collections into unified attack surfaces", () =>
    Effect.gen(function* () {
      // OpenAPI spec
      const openApiSpec = {
        openapi: "3.0.0",
        paths: {
          "/api/v1/auth/login": {
            post: {
              summary: "User Login",
              tags: ["auth"],
              parameters: [{ name: "remember", in: "query", schema: { type: "boolean" } }],
              requestBody: {
                content: {
                  "application/json": { schema: { type: "object" } },
                },
              },
            },
          },
          "/api/v1/users": {
            get: {
              summary: "List Users",
              security: [{ bearerAuth: ["read:users"] }],
              parameters: [{ name: "page", in: "query" }],
            },
          },
        },
      }

      const endpoints = SurfaceNormalizer.normalize(openApiSpec)
      expect(endpoints).toHaveLength(2)

      const loginEp = endpoints.find((e) => e.path === "/api/v1/auth/login")
      expect(loginEp?.method).toBe("POST")
      expect(loginEp?.requestBody?.contentType).toBe("application/json")
      expect(loginEp?.authRequired).toBe(false)

      const usersEp = endpoints.find((e) => e.path === "/api/v1/users")
      expect(usersEp?.method).toBe("GET")
      expect(usersEp?.authRequired).toBe(true)
      expect(usersEp?.securityRoles).toContain("read:users")
    }),
  )

  it.effect("generates isolated unified git patches without mutating repo files", () =>
    Effect.gen(function* () {
      const original = `function authenticate(user, pass) {
  const query = "SELECT * FROM users WHERE name = '" + user + "' AND pass = '" + pass + "'";
  return db.query(query);
}`
      const fixed = `function authenticate(user, pass) {
  const query = "SELECT * FROM users WHERE name = ? AND pass = ?";
  return db.query(query, [user, pass]);
}`

      const patchResult = RemediationPatchService.generatePatch({
        filePath: "src/auth.js",
        originalContent: original,
        remediatedContent: fixed,
        findingID: "FIND-001",
        cwe: "CWE-89",
        title: "SQL Injection",
      })

      expect(patchResult.hasChanges).toBe(true)
      expect(patchResult.filePath).toBe("src/auth.js")
      expect(patchResult.additions).toBeGreaterThan(0)
      expect(patchResult.deletions).toBeGreaterThan(0)
      expect(patchResult.patch).toContain("--- a/src/auth.js")
      expect(patchResult.patch).toContain("+++ b/src/auth.js")
      expect(patchResult.patch).toContain("-  const query = \"SELECT * FROM users WHERE name = '\" + user + \"' AND pass = '\" + pass + \"'\";")
      expect(patchResult.patch).toContain("+  const query = \"SELECT * FROM users WHERE name = ? AND pass = ?\";")
    }),
  )
})

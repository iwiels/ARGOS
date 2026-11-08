import { describe, expect } from "bun:test"
import { Effect } from "effect"
import { Database } from "../src/database/database"
import { AbsolutePath } from "../src/schema"
import { ProjectTable } from "../src/project/sql"
import { SessionTable } from "../src/session/sql"
import { CaseService, calculateSlaDueAt, determineSlaStatus } from "../src/security/case-service"
import { DocxExporter } from "../src/security/export/docx"
import { AuditSnapshotService } from "../src/security/export/snapshot"
import { ConnectorOutboxService } from "../src/security/outbox"
import { KnowledgeBaseService } from "../src/security/knowledge"
import { Cvss4Calculator } from "../src/security/cvss4"
import { CodeReachabilityService } from "../src/security/reachability"
import { AuditScheduleService } from "../src/security/schedule"
import { testEffect } from "./lib/effect"
import type { ReportDocument } from "../src/security/export/model"

const database = Database.layerFromPath(":memory:")
const it = testEffect(database)

describe("Vulnerability Management, Automation & CI/CD (Etapa 4)", () => {
  it.effect("calculates SLAs, targets due dates, and manages accepted risk lifecycle", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      const projectID = "proj-sla-test"
      const sessionID = "sess-sla-test"

      yield* db
        .insert(ProjectTable)
        .values({
          id: projectID as any,
          name: "SLA Project",
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
          title: "SLA Session",
          version: "1.0",
          time_created: Date.now(),
          time_updated: Date.now(),
        })
        .run()
        .pipe(Effect.orDie)

      // 1. Verificar tiempos de SLA según severidad
      const now = Date.now()
      const criticalDue = calculateSlaDueAt(now, "critical")
      expect(criticalDue - now).toBe(7 * 24 * 60 * 60 * 1000)

      const highDue = calculateSlaDueAt(now, "high")
      expect(highDue - now).toBe(15 * 24 * 60 * 60 * 1000)

      // 2. Registrar caso y verificar SLA calculado
      const obs = yield* CaseService.recordObservation(db, {
        sessionID,
        projectID,
        title: "Remote Code Execution in /upload",
        severity: "critical",
        cwe: "CWE-94",
        target: "https://api.target.com/upload",
        evidence: { uploaded: "shell.php" },
      })

      expect(obs.isNewCase).toBe(true)

      // 3. Aceptar riesgo con expiración justificada
      const riskResult = yield* CaseService.acceptRisk(db, {
        caseID: obs.caseID,
        reason: "Compensating WAF rule deployed (WAF-RULE-442)",
        actor: "lead_auditor",
        expiresInDays: 30,
      })

      expect(riskResult.caseID).toBe(obs.caseID)
      expect(riskResult.expiresAt).toBeGreaterThan(now)

      // 4. Determinar estado de SLA para caso con riesgo aceptado
      const slaStatus = determineSlaStatus({
        status: "accepted_risk",
        first_seen_at: now,
        severity: "critical",
        accepted_risk_expires_at: riskResult.expiresAt,
      })
      expect(slaStatus).toBe("within_sla")
    }),
  )

  it.effect("generates canonical JSON snapshots and valid WordprocessingML reports", () =>
    Effect.gen(function* () {
      const mockReport: ReportDocument = {
        meta: {
          title: "Auditoría de Seguridad Argos",
          clientName: "Acme Financial Corp",
          target: "https://banking.acme.com",
          scope: "https://banking.acme.com/*",
          classification: "TLP:AMBER",
          leadAuditor: "Argos Senior Auditor",
          methodology: "OWASP ASVS 4.0 / WSTG",
          sessionID: "sess-report-test",
          generatedAt: new Date("2026-10-25T12:00:00Z"),
        },
        summary: {
          totalFindings: 2,
          counts: { critical: 1, high: 1, medium: 0, low: 0, info: 0 },
          averageCvss: 8.9,
          highestCvss: 9.8,
          globalRisk: "critical",
          targets: [],
          topVulnerabilities: [],
        },
        findings: [
          {
            id: "F-001",
            title: "SQL Injection in User Authentication",
            severity: "critical",
            status: "open",
            cwe: "CWE-89",
            target: "https://banking.acme.com/api/v1/auth",
            vector: "username",
            evidence: "1' OR '1'='1 returned 200 OK with Bearer sec_tok_admin_987654321 and api_key=fake-key",
            remediation: "Migrar a sentencias parametrizadas y ORM seguro.",
          },
          {
            id: "F-002",
            title: "Broken Object Level Authorization (BOLA)",
            severity: "high",
            status: "open",
            cwe: "CWE-639",
            target: "https://banking.acme.com/api/v1/accounts/123",
            vector: "account_id",
            evidence: "User A can read balance of User B by modifying ID parameter",
            remediation: "Validar pertenencia del recurso a nivel de controlador.",
          },
        ],
      }

      // 1. Snapshot canónico determinista y verificación
      const snapshot = AuditSnapshotService.createSnapshot(mockReport)
      expect(snapshot.snapshotHash).toBeDefined()
      expect(snapshot.snapshotHash.length).toBe(64)
      expect(AuditSnapshotService.verifySnapshot(snapshot)).toBe(true)
      // Uniform secret redaction verified in canonical snapshot
      expect(snapshot.findings[0].evidence).toContain("[REDACTED]")
      expect(snapshot.findings[0].evidence).not.toContain("sec_tok_admin_987654321")
      expect(snapshot.findings[0].evidence).not.toContain("fake-key")

      // 2. Exportación a DOCX XML
      const docxXml = DocxExporter.exportDocxXml(mockReport)
      expect(docxXml).toContain("<?xml version=\"1.0\"")
      expect(docxXml).toContain("<w:document")
      expect(docxXml).toContain("Auditoría de Seguridad Argos")
      expect(docxXml).toContain("SQL Injection in User Authentication")
      expect(docxXml).toContain("CRITICAL")
      expect(docxXml).toContain("Acme Financial Corp")
      // Uniform secret redaction verified in DOCX export
      expect(docxXml).toContain("[REDACTED]")
      expect(docxXml).not.toContain("sec_tok_admin_987654321")
      expect(docxXml).not.toContain("fake-key")
    }),
  )

  it.effect("enqueues connector notifications with idempotency and executes backoff", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      const projectID = "proj-outbox-test"

      yield* db
        .insert(ProjectTable)
        .values({
          id: projectID as any,
          name: "Outbox Project",
          worktree: AbsolutePath.make("/project"),
          sandboxes: [],
          time_created: Date.now(),
          time_updated: Date.now(),
        })
        .run()
        .pipe(Effect.orDie)

      // 1. Encolar con idempotencia
      const first = yield* ConnectorOutboxService.enqueue(db, {
        projectID,
        targetSystem: "jira",
        eventType: "finding.created",
        idempotencyKey: "unique-finding-key-101",
        payload: { issueKey: "SEC-101", summary: "SQLi in /login" },
      })
      expect(first.deduplicated).toBe(false)

      // Segundo encolamiento idéntico se deduplica
      const second = yield* ConnectorOutboxService.enqueue(db, {
        projectID,
        targetSystem: "jira",
        eventType: "finding.created",
        idempotencyKey: "unique-finding-key-101",
        payload: { issueKey: "SEC-101", summary: "SQLi in /login" },
      })
      expect(second.deduplicated).toBe(true)

      // 2. Recuperar pendientes y despachar con éxito
      const pending = yield* ConnectorOutboxService.fetchPending(db, 10)
      expect(pending).toHaveLength(1)

      const dispatchResult = yield* ConnectorOutboxService.dispatch(db, async (item) => {
        expect(item.idempotency_key).toBe("unique-finding-key-101")
        return true
      })
      expect(dispatchResult.deliveredCount).toBe(1)

      // Comprobar que ya no hay pendientes
      const pendingAfter = yield* ConnectorOutboxService.fetchPending(db, 10)
      expect(pendingAfter).toHaveLength(0)
    }),
  )

  it.effect("indexes findings and queries local full-text search knowledge base", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      const projectID = "proj-fts-test"
      const sessionID = "sess-fts-test"

      yield* KnowledgeBaseService.index(db, {
        sessionID,
        projectID,
        title: "Cross-Site Scripting via reflected parameter",
        cwe: "CWE-79",
        target: "https://example.com/search",
        content: "Reflected payload <script>alert(1)</script> was returned unencoded in search response",
      })

      yield* KnowledgeBaseService.index(db, {
        sessionID,
        projectID,
        title: "Server-Side Request Forgery via webhook parameter",
        cwe: "CWE-918",
        target: "https://example.com/webhook",
        content: "Internal 169.254.169.254 AWS metadata endpoint reachable through webhook callback",
      })

      const xssResults = yield* KnowledgeBaseService.search(db, "unencoded search")
      expect(xssResults.length).toBeGreaterThan(0)
      expect(xssResults[0].title).toContain("Cross-Site Scripting")

      const ssrfResults = yield* KnowledgeBaseService.search(db, "metadata callback")
      expect(ssrfResults.length).toBeGreaterThan(0)
      expect(ssrfResults[0].title).toContain("Server-Side Request Forgery")
    }),
  )

  it.effect("persists audit schedules with timezones, detects missed occurrences upon open, and triggers run-now", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      const projectID = "proj-sched-test"
      const now = 1761400000000 // Fixed epoch ms

      yield* db
        .insert(ProjectTable)
        .values({
          id: projectID as any,
          name: "Schedule Project",
          worktree: AbsolutePath.make("/project"),
          sandboxes: [],
          time_created: now,
          time_updated: now,
        })
        .run()
        .pipe(Effect.orDie)

      // 1. Crear horario recurrente con zona horaria
      const sched = yield* AuditScheduleService.createSchedule(db, {
        projectID,
        name: "Nightly API Security Audit",
        target: "https://api.example.com",
        scanType: "api_audit",
        cronExpression: "0 2 * * *",
        timezone: "America/New_York",
        firstRunAt: now - 3600 * 1000, // Programado hace 1 hora (estaba Argos cerrado)
      })

      expect(sched.scheduleID).toBeDefined()
      expect(sched.timezone).toBe("America/New_York")

      // 2. Al abrir Argos (checkDueSchedules), detecta que la ocurrencia venció
      const dueCheck = yield* AuditScheduleService.checkDueSchedules(db, now)
      expect(dueCheck).toHaveLength(1)
      expect(dueCheck[0].scheduleID).toBe(sched.scheduleID)
      expect(dueCheck[0].missed).toBe(true)
      expect(dueCheck[0].missedOccurrences).toBe(1)
      expect(dueCheck[0].offerRunNow).toBe(true)

      // 3. El operador pulsa "Ejecutar ahora"
      const runResult = yield* AuditScheduleService.runNow(db, sched.scheduleID, { now })
      expect(runResult.status).toBe("queued")
      expect(runResult.taskID).toBeDefined()

      // 4. Verificar que el horario se actualizó a 'running' y se reiniciaron las ocurrencias omitidas
      const schedules = yield* AuditScheduleService.listSchedules(db, projectID)
      expect(schedules).toHaveLength(1)
      expect(schedules[0].last_status).toBe("running")
      expect(schedules[0].missed_occurrences).toBe(0)
    }),
  )
})

describe("Expanded Coverage: CVSS 4.0 & AST Code Reachability (Etapa 5)", () => {
  it.effect("computes CVSS 4.0 base scores and parses canonical vector strings", () =>
    Effect.gen(function* () {
      // Vector canónico CVSS 4.0 Crítico
      const criticalVectorStr = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
      const parsed = Cvss4Calculator.parseVector(criticalVectorStr)
      expect(parsed).not.toBeNull()
      expect(parsed?.attackVector).toBe("N")
      expect(parsed?.vulnConfidentiality).toBe("H")

      const result = Cvss4Calculator.calculate(parsed!)
      expect(result.score).toBeGreaterThanOrEqual(9.0)
      expect(result.severity).toBe("critical")
      expect(result.vectorString).toBe(criticalVectorStr)

      // Vector con impacto cero = 0.0 None
      const zeroVectorStr = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"
      const zeroParsed = Cvss4Calculator.parseVector(zeroVectorStr)
      const zeroResult = Cvss4Calculator.calculate(zeroParsed!)
      expect(zeroResult.score).toBe(0.0)
      expect(zeroResult.severity).toBe("none")
    }),
  )

  it.effect("extracts AST route symbols and correlates reachability across TS, Go and Python", () =>
    Effect.gen(function* () {
      // 1. TypeScript Express routes
      const tsContent = `
import express from 'express';
const app = express();

app.get('/api/v1/users', listUsers);
app.post('/api/v1/auth/login', handleLogin);
app.delete('/api/v1/users/:id', deleteUser);
`
      const tsRoutes = CodeReachabilityService.extractRoutes("src/routes.ts", tsContent)
      expect(tsRoutes).toHaveLength(3)
      expect(tsRoutes[0].method).toBe("GET")
      expect(tsRoutes[0].path).toBe("/api/v1/users")
      expect(tsRoutes[0].handlerSymbol).toBe("listUsers")

      // 2. Go Gin routes
      const goContent = `
package server

import "github.com/gin-gonic/gin"

func Setup(r *gin.Engine) {
	r.GET("/health", HealthCheck)
	r.POST("/api/orders", CreateOrder)
}
`
      const goRoutes = CodeReachabilityService.extractRoutes("cmd/server/main.go", goContent)
      expect(goRoutes).toHaveLength(2)
      expect(goRoutes[1].method).toBe("POST")
      expect(goRoutes[1].path).toBe("/api/orders")
      expect(goRoutes[1].handlerSymbol).toBe("CreateOrder")

      // 3. Python FastAPI routes
      const pyContent = `
from fastapi import FastAPI
app = FastAPI()

@app.get("/items/{item_id}")
def read_item(item_id: int):
    return {"item_id": item_id}

@app.post("/items")
def create_item(item: dict):
    return item
`
      const pyRoutes = CodeReachabilityService.extractRoutes("app/main.py", pyContent)
      expect(pyRoutes).toHaveLength(2)
      expect(pyRoutes[0].method).toBe("GET")
      expect(pyRoutes[0].path).toBe("/items/{item_id}")
      expect(pyRoutes[0].handlerSymbol).toBe("read_item")

      // 4. Correlación de alcanzabilidad
      const allRoutes = [...tsRoutes, ...goRoutes, ...pyRoutes]

      // Coincidencia exacta
      const matchExact = CodeReachabilityService.correlateEndpoint("/api/v1/users", "GET", allRoutes)
      expect(matchExact.isReachable).toBe(true)
      expect(matchExact.confidence).toBe("exact")
      expect(matchExact.sourceLocation?.file).toBe("src/routes.ts")
      expect(matchExact.sourceLocation?.symbol).toBe("listUsers")

      // Coincidencia parametrizada Express :id
      const matchParamExpress = CodeReachabilityService.correlateEndpoint("/api/v1/users/42", "DELETE", allRoutes)
      expect(matchParamExpress.isReachable).toBe(true)
      expect(matchParamExpress.confidence).toBe("pattern")
      expect(matchParamExpress.sourceLocation?.symbol).toBe("deleteUser")

      // Coincidencia parametrizada FastAPI {item_id}
      const matchParamPy = CodeReachabilityService.correlateEndpoint("/items/99", "GET", allRoutes)
      expect(matchParamPy.isReachable).toBe(true)
      expect(matchParamPy.confidence).toBe("pattern")
      expect(matchParamPy.sourceLocation?.symbol).toBe("read_item")

      // Sin coincidencia (alcanzabilidad falsa/externa)
      const matchNone = CodeReachabilityService.correlateEndpoint("/unknown/route", "GET", allRoutes)
      expect(matchNone.isReachable).toBe(false)
      expect(matchNone.confidence).toBe("unmatched")
    }),
  )
})

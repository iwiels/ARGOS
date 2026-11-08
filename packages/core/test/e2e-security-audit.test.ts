import { afterAll, describe, expect } from "bun:test"
import { eq } from "drizzle-orm"
import { Effect } from "effect"
import * as fs from "node:fs"
import * as os from "node:os"
import * as path from "node:path"
import { Database } from "@argos/core/database/database"
import { Project } from "@argos/core/project"
import { ProjectTable } from "@argos/core/project/sql"
import { SessionV2 } from "@argos/core/session"
import { SessionTable } from "@argos/core/session/sql"
import { FindingTable } from "@argos/core/security/sql"
import { calculateCvss, type CvssVector } from "@argos/core/security/cvss"
import { ingestToolPart } from "@argos/core/security/ingest"
import { validateFinding } from "@argos/core/security/validation"
import { updateFindingStatus } from "@argos/core/security/retest"
import { reconcileReportFindings } from "@argos/core/security/report-reconcile"
import { fromFindingRow, generateSarifLog } from "@argos/core/security/sarif"
import { AbsolutePath } from "@argos/core/schema"
import { testEffect } from "./lib/effect"

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "argos-e2e-audit-"))
const dbFile = path.join(tempDir, "audit-e2e.db")
const database = Database.layerFromPath(dbFile)
const it = testEffect(database)

const SESSION_ID = SessionV2.ID.make("ses_e2e_security_audit")

describe("End-to-End Security Audit Pipeline", () => {
  afterAll(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true })
    } catch {
      // ignore cleanup errors on Windows
    }
  })

  it.effect(
    "ejecuta ciclo integral: SQLite WAL -> Recon -> Vuln Scan -> Ingest -> Validation -> Retest -> Reconcile -> SARIF",
    () =>
      Effect.gen(function* () {
        const { db } = yield* Database.Service

        // 1. Verificación de Concurrencia: SQLite WAL
        const journalInfo = yield* db.run("PRAGMA journal_mode")
        const journalMode = (journalInfo as any)[0]?.journal_mode?.toLowerCase()
        expect(journalMode).toBe("wal")

        // Inicialización de Entorno (Project y Session)
        yield* db
          .insert(ProjectTable)
          .values({ id: Project.ID.global, worktree: AbsolutePath.make("/corp-network"), sandboxes: [] })
          .onConflictDoNothing()
          .run()
          .pipe(Effect.orDie)

        yield* db
          .insert(SessionTable)
          .values({
            id: SESSION_ID,
            project_id: Project.ID.global,
            slug: SESSION_ID,
            directory: "/corp-network",
            title: "Corporate Audit Session",
            version: "e2e-test",
          })
          .onConflictDoNothing()
          .run()
          .pipe(Effect.orDie)

        // 2. Simulación Ola 1: Reconocimiento de Superficie
        const targetUrl = "https://audit-target.corp:8443"
        const targetHost = "audit-target.corp"

        // 3. Simulación Ola 2: Vulnerability Detection con CVSS 3.1
        const rceVector: CvssVector = {
          attackVector: "N",
          attackComplexity: "L",
          privilegesRequired: "N",
          userInteraction: "N",
          scope: "U",
          confidentiality: "H",
          integrity: "H",
          availability: "H",
        }
        const cvssCalc = calculateCvss(rceVector)
        expect(cvssCalc.score).toBe(9.8)
        expect(cvssCalc.severity).toBe("critical")

        // 4. Ingesta de Hallazgos vía memory_save
        yield* ingestToolPart(db, {
          sessionID: SESSION_ID,
          type: "tool",
          tool: "argos_memory_save",
          state: {
            status: "completed",
            input: {
              kind: "finding",
              title: "Pre-Auth Remote Code Execution in Admin Endpoint",
              severity: cvssCalc.severity,
              target: `${targetUrl}/api/v1/system/exec`,
              vector: "POST /api/v1/system/exec - command injection via param cmd",
              cwe: "CWE-78",
              evidence: "A controlled command payload executed and returned the process identity in the response.",
              agent_assessment: "I repeated the request with a harmless command and confirmed server-side execution.",
              impact: "An unauthenticated remote user can execute commands on the application server.",
              remediation: "Sanitize command execution input and use non-shell process spawning APIs",
              tags: ["rce", "cwe-78", "owasp-a03"],
            },
          },
        })

        const initialFindings = yield* db
          .select()
          .from(FindingTable)
          .where(eq(FindingTable.session_id, SESSION_ID))
          .run()
          .pipe(Effect.orDie)

        expect(initialFindings.length).toBe(1)
        const rceFinding = initialFindings[0]
        expect(rceFinding.severity).toBe("critical")
        expect(rceFinding.status).toBe("open")
        expect(rceFinding.validation_status).toBe("detected")

        // 5. Validación XBOW: Confirmación y Reproducción
        const validated = yield* validateFinding(db, {
          findingId: rceFinding.id,
          verifier: async () => ({
            confirmed: true,
            evidence: { verified: true, proof: "uid=0(root)" },
          }),
        })
        expect(validated.validation_status).toBe("confirmed")
        expect(validated.status).toBe("validated")

        // Verificación de resiliencia: Validación con excepción nunca congela en "validating"
        yield* db
          .insert(FindingTable)
          .values({
            id: "find_flaky_err",
            session_id: SESSION_ID,
            project_id: Project.ID.global,
            fingerprint: "fp_flaky_err",
            title: "Flaky Network Flaw",
            severity: "medium",
            status: "open",
            source: "network.probe",
            target: `${targetUrl}/flaky`,
            evidence: {},
            tags: ["flaky"],
            time_created: Date.now(),
            time_updated: Date.now(),
          })
          .run()
          .pipe(Effect.orDie)

        const failResult = yield* validateFinding(db, {
          findingId: "find_flaky_err",
          verifier: async () => {
            throw new Error("Connection reset by peer during handshake")
          },
        }).pipe(Effect.exit)

        expect(failResult._tag).toBe("Failure")
        const flakyRow = yield* db
          .select()
          .from(FindingTable)
          .where(eq(FindingTable.id, "find_flaky_err"))
          .run()
          .pipe(Effect.orDie)
        expect(flakyRow[0].validation_status).toBe("rejected")

        // 6. Retest y Transición de Ciclo de Vida: "verified" no se degrada
        const retestSuccess = yield* updateFindingStatus(db, rceFinding.id, "verified", SESSION_ID)
        expect(retestSuccess).toBe(true)

        const retestedRow = yield* db
          .select()
          .from(FindingTable)
          .where(eq(FindingTable.id, rceFinding.id))
          .run()
          .pipe(Effect.orDie)
        expect(retestedRow[0].status).toBe("verified")

        // 7. Reconciliación con Reporte Markdown y Deduplicación por Fingerprint
        const reportMarkdown = `
# Consolidated Audit Report for ${targetHost}
**Target:** ${targetUrl}/api/v1/system/exec

## Hallazgos consolidados
| ID | Severidad | Titulo | CWE | CVE | Estado | Vector |
|---|---|---|---|---|---|---|
| F-01 | CRITICO | Pre-Auth Remote Code Execution in Admin Endpoint | CWE-78 | — | verified | POST /api/v1/system/exec - command injection via param cmd |
| F-02 | MEDIO | Deprecated TLS Protocol Version Negotiated | CWE-327 | — | open | ${targetUrl}:443 |
`

        const reconcileResult = yield* reconcileReportFindings(db, {
          sessionID: SESSION_ID,
          reportMarkdown,
        })

        expect(reconcileResult.total).toBe(2)
        expect(reconcileResult.skipped).toBe(1) // F-01 deduplicado por fingerprint exacto
        expect(reconcileResult.inserted).toBe(1) // F-02 nuevo insertado

        const allFindings = yield* db
          .select()
          .from(FindingTable)
          .where(eq(FindingTable.session_id, SESSION_ID))
          .run()
          .pipe(Effect.orDie)

        // rceFinding + find_flaky_err + F-02 = 3 hallazgos únicos
        expect(allFindings.length).toBe(3)

        // 8. Exportación OASIS SARIF v2.1.0 y Validación de Esquema
        const sarifLog = generateSarifLog(allFindings.map(fromFindingRow), {
          target: targetUrl,
        })

        expect(sarifLog.version).toBe("2.1.0")
        expect(sarifLog.$schema).toContain("sarif-schema-2.1.0.json")
        expect(sarifLog.runs.length).toBe(1)
        expect(sarifLog.runs[0].tool.driver.name).toBe("Argos Security Operations Engine")
        expect(sarifLog.runs[0].results.length).toBe(3)

        const criticalSarif = sarifLog.runs[0].results.find((r) => r.level === "error")
        expect(criticalSarif).toBeDefined()
        expect(criticalSarif?.message.text).toContain("Pre-Auth Remote Code Execution")
      }),
  )
})

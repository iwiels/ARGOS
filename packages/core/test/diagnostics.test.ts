import { describe, expect, test } from "bun:test"
import { assertAuditReadiness, type SystemDiagnosticReport } from "../src/security/diagnostics"

describe("System Diagnostics & Prerequisite Assistant (Etapa 1)", () => {
  test("allows audit when all prerequisites are met", () => {
    const report: SystemDiagnosticReport = {
      timestamp: Date.now(),
      platform: "linux",
      arch: "amd64",
      wsl: { available: true },
      docker: {
        available: true,
        engineRunning: true,
        strictContainerRequired: true,
        workerImage: "ghcr.io/iwiels/argos-worker:1.2.0-glibc",
        workerImagePresent: true,
      },
      storage: {
        writable: true,
        freeSpaceSufficient: true,
        path: "/workspace",
      },
      browser: {
        playwrightAvailable: true,
        chromiumInstalled: true,
      },
      tools: [],
      readyForAudit: true,
      blockingIssues: [],
      remediationSteps: [],
    }

    expect(() => assertAuditReadiness(report)).not.toThrow()
  })

  test("blocks audit when Docker engine is not running (no silent fallback)", () => {
    const report: SystemDiagnosticReport = {
      timestamp: Date.now(),
      platform: "win32",
      arch: "amd64",
      wsl: { available: true },
      docker: {
        available: false,
        engineRunning: false,
        strictContainerRequired: true,
        workerImage: "ghcr.io/iwiels/argos-worker:1.2.0-glibc",
        workerImagePresent: false,
        error: "daemon not running",
      },
      storage: {
        writable: true,
        freeSpaceSufficient: true,
        path: "C:\\workspace",
      },
      browser: {
        playwrightAvailable: true,
        chromiumInstalled: true,
      },
      tools: [],
      readyForAudit: false,
      blockingIssues: ["Docker Engine is not running or accessible"],
      remediationSteps: ["Start Docker Desktop and enable WSL2 integration."],
    }

    expect(() => assertAuditReadiness(report)).toThrow(/Audit Execution Blocked: System prerequisites failed/)
  })
})

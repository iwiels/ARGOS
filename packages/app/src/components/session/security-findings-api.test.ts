import { describe, expect, test } from "bun:test"
import {
  loadFindingCaseOperations,
  importFindings,
  loadFindingCaseHistory,
  loadFindingsForSessions,
  loadSessionFindingCases,
  loadSessionFindings,
  previewFindingImport,
  setFindingFeedback,
  updateFindingCaseStatus,
  mergeFindingCases,
  reverseFindingCaseOperation,
  splitFindingCase,
} from "./security-findings-api"

describe("loadSessionFindings", () => {
  test("maps the persisted security_finding contract", async () => {
    const request = async () =>
      new Response(
        JSON.stringify({
          data: [
            {
              id: "finding-1",
              case_id: "case-1",
              fingerprint: "sha256-backend-fingerprint",
              session_id: "session-1",
              title: "Exposed endpoint",
              severity: "high",
              status: "open",
              source: "db",
              source_tool: "argos_memory_save",
              evidence: { status: 200 },
              tags: ["web"],
            },
          ],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      )

    await expect(loadSessionFindings(request, "session-1")).resolves.toEqual([
      expect.objectContaining({
        id: "finding-1",
        caseID: "case-1",
        fingerprint: "sha256-backend-fingerprint",
        session: "session-1",
        title: "Exposed endpoint",
        severity: "high",
        source: "db",
        sourceTool: "argos_memory_save",
        evidence: '{"status":200}',
        tags: ["web"],
      }),
    ])
  })

  test("keeps source_tool so the card can drop it from the extracted IoCs", async () => {
    // `code.review` tiene forma de dominio y quedó persistido como IoC en los
    // hallazgos enriquecidos antes del fix en el motor de extracción; la vista
    // lo filtra usando este campo, así que tiene que sobrevivir al mapeo.
    const request = async () =>
      new Response(
        JSON.stringify({
          data: [{ title: "Secreto en git", severity: "high", source_tool: "code.review" }],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      )

    await expect(loadSessionFindings(request, "session-1")).resolves.toEqual([
      expect.objectContaining({ sourceTool: "code.review" }),
    ])
  })

  test("returns undefined when the server does not expose the endpoint", async () => {
    const request = async () => new Response(null, { status: 404 })
    await expect(loadSessionFindings(request, "session-1")).resolves.toBeUndefined()
  })

  test("accepts a plain findings array response", async () => {
    const request = async () => new Response(JSON.stringify([{ title: "A", severity: "low" }]), { status: 200 })
    await expect(loadSessionFindings(request, "session-1")).resolves.toEqual([
      expect.objectContaining({ title: "A", severity: "low", session: "session-1" }),
    ])
  })

  test("loads every findings page exposed by the typed API", async () => {
    const paths: string[] = []
    const request = async (path: string) => {
      paths.push(path)
      const offset = new URL(path, "http://localhost").searchParams.get("offset")
      const data =
        offset === "0"
          ? Array.from({ length: 200 }, (_, index) => ({ title: `Finding ${index}`, severity: "low" }))
          : [{ title: "Finding 200", severity: "high" }]
      return new Response(JSON.stringify({ data, total: 201 }), {
        status: 200,
        headers: { "content-type": "application/json" },
      })
    }

    await expect(loadSessionFindings(request, "session-1")).resolves.toHaveLength(201)
    expect(paths).toEqual([
      "/session/session-1/findings?limit=200&offset=0",
      "/session/session-1/findings?limit=200&offset=200",
    ])
  })

  test("surfaces server errors instead of treating them as an empty finding list", async () => {
    const request = async () => new Response("unavailable", { status: 503 })
    await expect(loadSessionFindings(request, "session-1")).rejects.toThrow("HTTP 503")
  })

  test("loads independent sessions with bounded workers", async () => {
    let active = 0
    let peak = 0
    const request = async (_path: string) => {
      active += 1
      peak = Math.max(peak, active)
      await new Promise((resolve) => setTimeout(resolve, 5))
      active -= 1
      return new Response(JSON.stringify({ data: [] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      })
    }

    const result = await loadFindingsForSessions(request, ["a", "b", "c", "d", "e"], 2)
    expect(Object.keys(result)).toHaveLength(5)
    expect(peak).toBeLessThanOrEqual(2)
  })

  test("accepts the camelCase DTO emitted by the typed security API", async () => {
    const request = async () =>
      new Response(
        JSON.stringify({
          data: [
            {
              id: "finding-2",
              sessionID: "session-2",
              title: "Missing header",
              severity: "medium",
              status: "open",
              source: "memory",
              sourceTool: "argos_memory_save",
              evidence: { header: "x-frame-options" },
              tags: ["headers"],
            },
          ],
          total: 1,
          limit: 50,
          offset: 0,
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      )

    await expect(loadSessionFindings(request, "session-2")).resolves.toEqual([
      expect.objectContaining({
        id: "finding-2",
        session: "session-2",
        source: "memory",
        title: "Missing header",
        severity: "medium",
      }),
    ])
  })
})

describe("setFindingFeedback", () => {
  test("posts to the desktop route and requires a persisted feedback row", async () => {
    let requestedPath = ""
    const request = async (path: string) => {
      requestedPath = path
      return new Response(
        JSON.stringify({
          data: { findingID: "finding-1", verdict: "false-positive", actor: "human", reason: "Reviewed", updatedAt: 1 },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      )
    }

    await expect(setFindingFeedback(request, "session-1", "finding-1", "false-positive", "Reviewed")).resolves.toEqual({
      verdict: "false-positive",
      actor: "human",
      reason: "Reviewed",
    })
    expect(requestedPath).toBe("/session/session-1/findings/finding-1/feedback")
  })

  test("does not treat a missing feedback route as a successful save", async () => {
    const request = async () => new Response(null, { status: 404 })
    await expect(setFindingFeedback(request, "session-1", "finding-1", "false-positive")).rejects.toThrow("HTTP 404")
  })

  test("does not infer persistence from an empty successful response", async () => {
    const request = async () => new Response(null, { status: 204 })
    await expect(setFindingFeedback(request, "session-1", "finding-1", "false-positive")).rejects.toThrow(
      "persisted feedback record",
    )
  })
})

describe("finding import API", () => {
  const finding = {
    id: "imp_abc",
    source: "import",
    source_tool: "nuclei",
    rule_id: "nuclei:sample",
    title: "Sample vulnerability",
    severity: "high",
    status: "observed",
    confidence: "possible",
    evidence: { format: "nuclei-jsonl" },
    tags: [],
    references: [],
  }
  const data = {
    format: "nuclei-jsonl",
    parserVersion: 1,
    contentSha256: "a".repeat(64),
    findings: [finding],
    warnings: [],
  }

  test("previews without persisting and validates the response contract", async () => {
    let requestedPath = ""
    let requestBody: Record<string, unknown> = {}
    const request = async (path: string, init?: RequestInit) => {
      requestedPath = path
      if (typeof init?.body !== "string") throw new Error("Expected a JSON request body")
      requestBody = JSON.parse(init.body)
      return new Response(JSON.stringify({ data }), { status: 200, headers: { "content-type": "application/json" } })
    }
    const preview = await previewFindingImport(request, "session / 1", "nuclei-jsonl", "{}")
    expect(requestedPath).toBe("/api/session/session%20%2F%201/findings/import/preview")
    expect(requestBody).toEqual({ format: "nuclei-jsonl", content: "{}" })
    expect(preview.findings).toHaveLength(1)
  })

  test("confirms a saved import and rejects an empty success response", async () => {
    let requestedPath = ""
    const request = async (path: string) => {
      requestedPath = path
      return new Response(JSON.stringify({ data: { ...data, sourceEventID: "import:job-1:hash", importedCount: 1 } }), {
        status: 200,
        headers: { "content-type": "application/json" },
      })
    }
    const imported = await importFindings(request, "session-1", "nuclei-jsonl", "{}", "job-1")
    expect(requestedPath).toBe("/api/session/session-1/findings/import")
    expect(imported.importedCount).toBe(1)
    await expect(
      importFindings(
        async () => new Response(JSON.stringify({ data }), { status: 200 }),
        "session-1",
        "nuclei-jsonl",
        "{}",
      ),
    ).rejects.toThrow("Unable to confirm persisted finding import")
  })

  test("surfaces import errors instead of treating them as an empty preview", async () => {
    const request = async () =>
      new Response(JSON.stringify({ error: { message: "Invalid SARIF version" } }), { status: 400 })
    await expect(previewFindingImport(request, "session-1", "sarif-2.1", "{}")).rejects.toThrow("Invalid SARIF version")
  })
})

describe("finding case API", () => {
  const findingCase = {
    id: "case-1",
    status: "open",
    statusReason: null,
    owner: null,
    dueAt: null,
    acceptedRiskUntil: null,
    findingCount: 2,
    sessionCount: 3,
    createdAt: 10,
    updatedAt: 20,
  }

  test("loads project cases associated with a session", async () => {
    let requestedPath = ""
    const request = async (path: string) => {
      requestedPath = path
      return new Response(JSON.stringify({ data: [findingCase], total: 1, limit: 200, offset: 0 }), {
        status: 200,
        headers: { "content-type": "application/json" },
      })
    }
    await expect(loadSessionFindingCases(request, "session / 1")).resolves.toEqual([
      expect.objectContaining({ id: "case-1", findingCount: 2, sessionCount: 3 }),
    ])
    expect(requestedPath).toBe("/session/session%20%2F%201/finding-cases?limit=200&offset=0")
  })

  test("confirms the persisted status transition and rejects a missing response record", async () => {
    let requestBody: Record<string, unknown> = {}
    const request = async (_path: string, init?: RequestInit) => {
      requestBody = JSON.parse(String(init?.body))
      return new Response(JSON.stringify({ data: { ...findingCase, status: "in-progress", updatedAt: 21 } }), {
        status: 200,
        headers: { "content-type": "application/json" },
      })
    }
    await expect(
      updateFindingCaseStatus(request, "session-1", "case-1", {
        status: "in-progress",
        reason: "Assigned",
      }),
    ).resolves.toMatchObject({ id: "case-1", status: "in-progress", updatedAt: 21 })
    expect(requestBody).toEqual({ status: "in-progress", reason: "Assigned" })
    await expect(
      updateFindingCaseStatus(async () => new Response("{}", { status: 200 }), "session-1", "case-1", {
        status: "in-progress",
      }),
    ).rejects.toThrow("persisted finding case")
  })

  test("loads only bounded, validated case history", async () => {
    let requestedPath = ""
    const request = async (path: string) => {
      requestedPath = path
      return new Response(
        JSON.stringify({
          data: [
            {
              id: "transition-1",
              fromStatus: "open",
              toStatus: "in-progress",
              reason: "Assigned",
              actor: "human",
              sessionID: "session-1",
              createdAt: 30,
            },
          ],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      )
    }
    await expect(loadFindingCaseHistory(request, "session / 1", "case / 1")).resolves.toEqual([
      expect.objectContaining({ id: "transition-1", fromStatus: "open", toStatus: "in-progress" }),
    ])
    expect(requestedPath).toBe("/session/session%20%2F%201/finding-cases/case%20%2F%201/history?limit=100")
    await expect(
      loadFindingCaseHistory(
        async () =>
          new Response(JSON.stringify({ data: [{ id: "broken" }] }), {
            status: 200,
            headers: { "content-type": "application/json" },
          }),
        "session-1",
        "case-1",
      ),
    ).rejects.toThrow("history record")
  })

  test("loads and validates case operation history", async () => {
    let requestedPath = ""
    const request = async (path: string) => {
      requestedPath = path
      return new Response(
        JSON.stringify({
          data: [
            {
              id: "operation-1",
              kind: "merge",
              sourceCaseID: "case-1",
              targetCaseID: "case-2",
              reason: "Same endpoint",
              actor: "human",
              sessionID: "session-1",
              findingIDs: ["finding-1"],
              createdAt: 40,
              reversedAt: null,
              reversedReason: null,
              reversedBy: null,
            },
          ],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      )
    }
    await expect(loadFindingCaseOperations(request, "session / 1", "case / 2")).resolves.toMatchObject([
      { id: "operation-1", kind: "merge", sourceCaseID: "case-1", targetCaseID: "case-2" },
    ])
    expect(requestedPath).toBe("/session/session%20%2F%201/finding-cases/case%20%2F%202/operations?limit=100")
    await expect(
      loadFindingCaseOperations(
        async () => new Response(JSON.stringify({ data: [{ id: "broken" }] }), { status: 200 }),
        "session-1",
        "case-1",
      ),
    ).rejects.toThrow("operation record")
  })

  test("confirms case merge, split and reversal were persisted", async () => {
    const operation = {
      id: "operation-1",
      kind: "merge",
      sourceCaseID: "case-1",
      targetCaseID: "case-2",
      reason: "Same endpoint",
      actor: "human",
      sessionID: "session-1",
      findingIDs: ["finding-1"],
      createdAt: 40,
      reversedAt: null,
      reversedReason: null,
      reversedBy: null,
    }
    let requestPath = ""
    let requestBody: Record<string, unknown> = {}
    const request = async (path: string, init?: RequestInit) => {
      requestPath = path
      requestBody = JSON.parse(String(init?.body))
      const data = path.endsWith("/split")
        ? {
            caseID: "case-3",
            operation: { ...operation, kind: "split", sourceCaseID: "case-2", targetCaseID: "case-3" },
          }
        : path.endsWith("/reverse")
          ? { ...operation, reversedAt: 50, reversedReason: "Incorrect merge", reversedBy: "human" }
          : operation
      return new Response(JSON.stringify({ data }), { status: 200, headers: { "content-type": "application/json" } })
    }
    await expect(
      mergeFindingCases(request, "session-1", "case-1", { targetCaseID: "case-2", reason: "Same endpoint" }),
    ).resolves.toMatchObject({ id: "operation-1", kind: "merge" })
    expect(requestPath).toBe("/session/session-1/finding-cases/case-1/merge")
    expect(requestBody).toEqual({ targetCaseID: "case-2", reason: "Same endpoint" })
    await expect(
      splitFindingCase(request, "session-1", "case-2", { findingIDs: ["finding-1"], reason: "Separate issue" }),
    ).resolves.toMatchObject({ caseID: "case-3", operation: { kind: "split" } })
    expect(requestBody).toEqual({ findingIDs: ["finding-1"], reason: "Separate issue" })
    await expect(
      reverseFindingCaseOperation(request, "session-1", "case-2", "operation-1", "Incorrect merge"),
    ).resolves.toMatchObject({ id: "operation-1", kind: "merge" })
    expect(requestPath).toBe("/session/session-1/finding-cases/case-2/operations/operation-1/reverse")
    expect(requestBody).toEqual({ reason: "Incorrect merge" })
  })
})

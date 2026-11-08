import * as http from "node:http"
import { describe, expect } from "bun:test"
import { eq } from "drizzle-orm"
import { Effect, Layer } from "effect"
import { Database } from "@argos/core/database/database"
import { Project } from "@argos/core/project"
import { ProjectTable } from "@argos/core/project/sql"
import { SessionV2 } from "@argos/core/session"
import { SessionTable } from "@argos/core/session/sql"
import { digestBody, type PocRecord } from "@argos/core/security/poc"
import { ingestToolFindings } from "@argos/core/security/ingest"
import { FindingTable } from "@argos/core/security/sql"
import { retestFinding, updateFindingStatus, type RetestHttpExecutor } from "@argos/core/security/retest"
import * as ScopeService from "@argos/core/security/scope-service"
import { AbsolutePath } from "@argos/core/schema"
import { testEffect } from "./lib/effect"

const SESSION_ID = SessionV2.ID.make("ses_retest_test")
/** Sesión con scope declarado: sirve para probar que el gate de scope corta el re-test. */
const SCOPED_SESSION_ID = SessionV2.ID.make("ses_retest_scope_test")

const database = Database.layerFromPath(":memory:")
const scope = ScopeService.layer.pipe(Layer.provide(database))
const it = testEffect(Layer.mergeAll(database, scope))

async function startServer(handler: (req: http.IncomingMessage, res: http.ServerResponse) => void) {
  const server = http.createServer(handler)
  const port = await new Promise<number>((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address()
      resolve(typeof addr === "object" && addr ? addr.port : 0)
    })
  })
  return { server, port }
}

const fixtureExecutor: RetestHttpExecutor = async (request) => {
  if (new URL(request.url).hostname !== "127.0.0.1") throw new Error("Fixture executor only accepts loopback")
  expect(request.redirect).toBe("manual")
  expect(request.timeoutMs).toBeGreaterThan(0)
  expect(request.timeoutMs).toBeLessThanOrEqual(10_000)
  expect(request.maxResponseBytes).toBe(1 << 20)
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), request.timeoutMs)
  const started = Date.now()
  try {
    const response = await fetch(request.url, {
      method: request.method,
      headers: request.headers,
      body: request.body,
      redirect: "manual",
      signal: controller.signal,
    })
    const reader = response.body?.getReader()
    const decoder = new TextDecoder()
    let body = ""
    let bytes = 0
    if (reader) {
      try {
        for (;;) {
          const { done, value } = await reader.read()
          if (done) break
          const chunk = value.subarray(0, request.maxResponseBytes - bytes)
          bytes += chunk.byteLength
          body += decoder.decode(chunk, { stream: true })
          if (bytes >= request.maxResponseBytes) break
        }
        body += decoder.decode()
      } finally {
        await reader.cancel()
      }
    }
    return {
      status: response.status,
      headers: Object.fromEntries(response.headers.entries()),
      body,
      durationMs: Date.now() - started,
    }
  } finally {
    clearTimeout(timer)
  }
}

const seedSession = (sessionId: string = SESSION_ID) =>
  Effect.gen(function* () {
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
        id: sessionId,
        project_id: Project.ID.global,
        slug: sessionId,
        directory: "/project",
        title: "retest test",
        version: "test",
        // The default fixture authorizes only the local test server; this session intentionally authorizes a separate domain.
        ...(sessionId === SCOPED_SESSION_ID ? { scope_domains: ["*.allowed.test"] } : { scope_cidrs: ["127.0.0.0/8"] }),
      })
      .onConflictDoNothing()
      .run()
      .pipe(Effect.orDie)
  })

const seedFinding = (input: {
  id: string
  title: string
  vector: string
  status?: string
  poc?: PocRecord
  sessionId?: string
}) =>
  Effect.gen(function* () {
    const sessionId = input.sessionId ?? SESSION_ID
    const { db } = yield* Database.Service
    yield* seedSession(sessionId)
    yield* db
      .insert(FindingTable)
      .values({
        id: input.id,
        session_id: sessionId,
        project_id: Project.ID.global,
        fingerprint: input.id,
        title: input.title,
        severity: "high",
        status: input.status ?? "open",
        source: "memory",
        vector: input.vector,
        target: input.vector,
        evidence: {},
        poc: input.poc,
        tags: [],
        time_created: Date.now(),
        time_updated: Date.now(),
      })
      .onConflictDoNothing()
      .run()
      .pipe(Effect.orDie)
  })

const statusOf = (id: string) =>
  Effect.gen(function* () {
    const { db } = yield* Database.Service
    const row = yield* db
      .select({ status: FindingTable.status })
      .from(FindingTable)
      .where(eq(FindingTable.id, id))
      .get()
      .pipe(Effect.orDie)
    return row?.status
  })

const evidenceOf = (id: string) =>
  Effect.gen(function* () {
    const { db } = yield* Database.Service
    const row = yield* db
      .select({ evidence: FindingTable.validation_evidence })
      .from(FindingTable)
      .where(eq(FindingTable.id, id))
      .get()
      .pipe(Effect.orDie)
    return row?.evidence
  })

describe("retestFinding — nunca afirma 'verified' sin una comprobación real", () => {
  for (const withPoc of [false, true]) {
    it.effect(`sin transporte aislado no emite red ni modifica el hallazgo (${withPoc ? "PoC" : "pasivo"})`, () =>
      Effect.gen(function* () {
        let requests = 0
        const { server, port } = yield* Effect.promise(() =>
          startServer((_req, res) => {
            requests++
            res.writeHead(200, { "strict-transport-security": "max-age=31536000" })
            res.end("fixed")
          }),
        )
        const id = withPoc ? "find-no-transport-poc" : "find-no-transport-passive"
        const url = `http://127.0.0.1:${port}/`
        try {
          yield* seedFinding({
            id,
            title: "Missing HSTS header",
            vector: url,
            status: "remediated",
            ...(withPoc
              ? {
                  poc: {
                    kind: "sqli",
                    method: "GET",
                    url,
                    matcher: { kind: "body_absent", needle: "vulnerable" },
                    baseline: { status: 200 },
                  } satisfies PocRecord,
                }
              : {}),
          })
          const { db } = yield* Database.Service
          const before = yield* db.select().from(FindingTable).where(eq(FindingTable.id, id)).get().pipe(Effect.orDie)
          const result = yield* retestFinding(db, id)
          const after = yield* db.select().from(FindingTable).where(eq(FindingTable.id, id)).get().pipe(Effect.orDie)

          expect(requests).toBe(0)
          expect(result?.checked).toBe(false)
          expect(result?.previousStatus).toBe("remediated")
          expect(result?.newStatus).toBe("remediated")
          expect(result?.message.toLowerCase()).toContain("transporte aislado")
          expect(after).toEqual(before)
        } finally {
          server.close()
        }
      }),
    )

    it.effect(`no sigue redirecciones ni las acepta como remediación (${withPoc ? "PoC" : "pasivo"})`, () =>
      Effect.gen(function* () {
        let destinationRequests = 0
        const destination = yield* Effect.promise(() =>
          startServer((_req, res) => {
            destinationRequests++
            res.writeHead(200, { "strict-transport-security": "max-age=31536000" })
            res.end("fixed")
          }),
        )
        const redirect = yield* Effect.promise(() =>
          startServer((_req, res) => {
            res.writeHead(302, {
              location: `http://127.0.0.1:${destination.port}/`,
              "strict-transport-security": "max-age=31536000",
            })
            res.end()
          }),
        )
        const id = withPoc ? "find-redirect-poc" : "find-redirect-passive"
        const url = `http://127.0.0.1:${redirect.port}/`
        try {
          yield* seedFinding({
            id,
            title: "Missing HSTS header",
            vector: url,
            ...(withPoc
              ? {
                  poc: {
                    kind: "sqli",
                    method: "GET",
                    url,
                    matcher: { kind: "body_absent", needle: "vulnerable" },
                    baseline: { status: 200 },
                  } satisfies PocRecord,
                }
              : {}),
          })
          const { db } = yield* Database.Service
          const result = yield* retestFinding(db, id, undefined, fixtureExecutor)

          expect(destinationRequests).toBe(0)
          expect(result?.checked).toBe(false)
          expect(result?.newStatus).not.toBe("verified")
          expect(result?.message.toLowerCase()).toContain("redirección")
          expect(yield* statusOf(id)).not.toBe("verified")
        } finally {
          redirect.server.close()
          destination.server.close()
        }
      }),
    )
  }

  it.effect(
    "un hallazgo sin chequeo específico (ej. SQLi) NO se marca 'verified': queda 'in-progress'",
    () =>
      Effect.gen(function* () {
        const { server, port } = yield* Effect.promise(() =>
          startServer((_req, res) => {
            // Servidor que responde 200 sin ninguna cabecera de seguridad —
            // antes esto se marcaba "verified" solo por responder 200.
            res.writeHead(200, { "content-type": "text/plain" })
            res.end("ok")
          }),
        )
        yield* seedFinding({
          id: "find-sqli",
          title: "SQL injection en /login",
          vector: `http://127.0.0.1:${port}/login`,
        })

        const { db } = yield* Database.Service
        const result = yield* retestFinding(db, "find-sqli", undefined, fixtureExecutor)
        server.close()

        expect(result).toBeDefined()
        expect(result?.checked).toBe(false)
        expect(result?.newStatus).toBe("in-progress")
        expect(result?.newStatus).not.toBe("verified")

        const row = yield* db
          .select({ status: FindingTable.status })
          .from(FindingTable)
          .where(eq(FindingTable.id, "find-sqli"))
          .get()
          .pipe(Effect.orDie)
        expect(row?.status).toBe("in-progress")
      }),
    { timeout: 15000 },
  )

  it.effect(
    "un hallazgo de HSTS con la cabecera presente SÍ se marca 'verified' — con evidencia real",
    () =>
      Effect.gen(function* () {
        const { server, port } = yield* Effect.promise(() =>
          startServer((_req, res) => {
            res.writeHead(200, {
              "content-type": "text/plain",
              "strict-transport-security": "max-age=31536000; includeSubDomains",
            })
            res.end("ok")
          }),
        )
        yield* seedFinding({
          id: "find-hsts",
          title: "Falta cabecera HSTS",
          vector: `http://127.0.0.1:${port}/`,
        })

        const { db } = yield* Database.Service
        const result = yield* retestFinding(db, "find-hsts", undefined, fixtureExecutor)
        server.close()

        expect(result?.checked).toBe(true)
        expect(result?.stillVulnerable).toBe(false)
        expect(result?.newStatus).toBe("verified")
        expect(result?.message).toContain("Strict-Transport-Security")
      }),
    { timeout: 15000 },
  )

  it.effect(
    "un hallazgo de HSTS SIN la cabecera se marca 'open' (sigue vulnerable), no 'verified'",
    () =>
      Effect.gen(function* () {
        const { server, port } = yield* Effect.promise(() =>
          startServer((_req, res) => {
            res.writeHead(200, { "content-type": "text/plain" })
            res.end("ok")
          }),
        )
        yield* seedFinding({
          id: "find-hsts-2",
          title: "Falta cabecera HSTS",
          vector: `http://127.0.0.1:${port}/`,
          status: "in-progress",
        })

        const { db } = yield* Database.Service
        const result = yield* retestFinding(db, "find-hsts-2", undefined, fixtureExecutor)
        server.close()

        expect(result?.checked).toBe(true)
        expect(result?.stillVulnerable).toBe(true)
        expect(result?.newStatus).toBe("open")
      }),
    { timeout: 15000 },
  )

  it.effect(
    "target inalcanzable (timeout/red) NO se marca 'verified'",
    () =>
      Effect.gen(function* () {
        yield* seedFinding({
          id: "find-unreachable",
          title: "Puerto de gestión expuesto",
          // Puerto que casi seguro no tiene nada escuchando.
          vector: "http://127.0.0.1:1",
        })

        const { db } = yield* Database.Service
        const result = yield* retestFinding(db, "find-unreachable", undefined, fixtureExecutor)

        expect(result?.checked).toBe(false)
        expect(result?.newStatus).toBe("in-progress")
      }),
    { timeout: 15000 },
  )

  it.effect("hallazgo inexistente devuelve undefined, no lanza", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      const result = yield* retestFinding(db, "no-existe", undefined, fixtureExecutor)
      expect(result).toBeUndefined()
    }),
  )
})

describe("updateFindingStatus", () => {
  it.effect("persiste la transición de estado en la base de datos", () =>
    Effect.gen(function* () {
      yield* seedFinding({ id: "find-status", title: "Algo", vector: "http://example.invalid/" })
      const { db } = yield* Database.Service

      const ok = yield* updateFindingStatus(db, "find-status", "accepted-risk")
      expect(ok).toBe(true)

      const row = yield* db
        .select({ status: FindingTable.status })
        .from(FindingTable)
        .where(eq(FindingTable.id, "find-status"))
        .get()
        .pipe(Effect.orDie)
      expect(row?.status).toBe("accepted-risk")
    }),
  )

  it.effect("hallazgo inexistente devuelve false sin lanzar", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      const ok = yield* updateFindingStatus(db, "no-existe", "verified")
      expect(ok).toBe(false)
    }),
  )
})

const SQLI_PAYLOAD = "1' AND '1'='1"

describe("retestFinding — re-test por tipo de vector (PoC)", () => {
  it.effect(
    "un PoC 'body_absent' cuyo payload ya no se refleja deja el hallazgo en 'verified'",
    () =>
      Effect.gen(function* () {
        const { server, port } = yield* Effect.promise(() =>
          startServer((_req, res) => {
            // El endpoint ya no refleja el payload: la inyección está corregida.
            res.writeHead(200, { "content-type": "text/html" })
            res.end("<html><body><p>Catalog</p><ul><li>Item 1</li></ul></body></html>")
          }),
        )
        const original = `<html><body><p>Catalog</p><p>error near: ${SQLI_PAYLOAD}</p></body></html>`
        yield* seedFinding({
          id: "find-poc-sqli-fixed",
          title: "SQL injection en /item",
          vector: `http://127.0.0.1:${port}/item?id=1`,
          status: "in-progress",
          poc: {
            kind: "sqli",
            method: "GET",
            url: `http://127.0.0.1:${port}/item?id=${encodeURIComponent(SQLI_PAYLOAD)}`,
            payload: SQLI_PAYLOAD,
            matcher: { kind: "body_absent", needle: SQLI_PAYLOAD },
            baseline: { status: 200, bodyDigest: digestBody(original), bodySnippet: original },
          },
        })

        const { db } = yield* Database.Service
        const result = yield* retestFinding(db, "find-poc-sqli-fixed", undefined, fixtureExecutor)
        server.close()

        expect(result?.checked).toBe(true)
        expect(result?.stillVulnerable).toBe(false)
        expect(result?.newStatus).toBe("verified")
        // El mensaje dice QUÉ se verificó, no sólo "verified".
        expect(result?.message).toContain("body_absent")
        expect(result?.message).toContain("dejó de reproducirse")
        expect(yield* statusOf("find-poc-sqli-fixed")).toBe("verified")

        // La evidencia del re-test queda persistida.
        const evidence = yield* evidenceOf("find-poc-sqli-fixed")
        expect(evidence?.poc_kind).toBe("sqli")
        expect(evidence?.matcher).toBe("body_absent")
        expect(evidence?.baseline_status).toBe(200)
        expect(evidence?.retest_status).toBe(200)
        expect(typeof evidence?.executed_at).toBe("number")
      }),
    { timeout: 15000 },
  )

  it.effect(
    "el mismo PoC contra un target que sigue reflejando deja el hallazgo en 'open'",
    () =>
      Effect.gen(function* () {
        const { server, port } = yield* Effect.promise(() =>
          startServer((req, res) => {
            // El endpoint sigue reflejando el payload: la inyección sigue ahí.
            const value = new URL(req.url ?? "/", "http://localhost").searchParams.get("id") ?? ""
            res.writeHead(200, { "content-type": "text/html" })
            res.end(`<html><body><p>value: ${value}</p></body></html>`)
          }),
        )
        const original = `<html><body><p>value: ${SQLI_PAYLOAD}</p></body></html>`
        yield* seedFinding({
          id: "find-poc-sqli-open",
          title: "SQL injection en /item",
          vector: `http://127.0.0.1:${port}/item?id=1`,
          status: "in-progress",
          poc: {
            kind: "sqli",
            method: "GET",
            url: `http://127.0.0.1:${port}/item?id=${encodeURIComponent(SQLI_PAYLOAD)}`,
            payload: SQLI_PAYLOAD,
            matcher: { kind: "body_absent", needle: SQLI_PAYLOAD },
            baseline: { status: 200, bodyDigest: digestBody(original), bodySnippet: original },
          },
        })

        const { db } = yield* Database.Service
        const result = yield* retestFinding(db, "find-poc-sqli-open", undefined, fixtureExecutor)
        server.close()

        expect(result?.checked).toBe(true)
        expect(result?.stillVulnerable).toBe(true)
        expect(result?.newStatus).toBe("open")
        expect(result?.newStatus).not.toBe("verified")
        expect(yield* statusOf("find-poc-sqli-open")).toBe("open")
      }),
    { timeout: 15000 },
  )

  it.effect(
    "un PoC destructivo NO se re-ejecuta nunca: checked=false y el estado no se mueve",
    () =>
      Effect.gen(function* () {
        let requests = 0
        const { server, port } = yield* Effect.promise(() =>
          startServer((_req, res) => {
            requests++
            res.writeHead(200, { "content-type": "text/html" })
            res.end("ok")
          }),
        )
        yield* seedFinding({
          id: "find-poc-destructive",
          title: "SQL injection en /item",
          vector: `http://127.0.0.1:${port}/item?id=1`,
          status: "in-progress",
          poc: {
            kind: "sqli",
            method: "GET",
            url: `http://127.0.0.1:${port}/item?id=${encodeURIComponent("1; DROP TABLE users--")}`,
            payload: "1; DROP TABLE users--",
            matcher: { kind: "body_absent", needle: "1; DROP TABLE users--" },
            baseline: { status: 200 },
          },
        })

        const { db } = yield* Database.Service
        const result = yield* retestFinding(db, "find-poc-destructive", undefined, fixtureExecutor)
        server.close()

        expect(requests).toBe(0)
        expect(result?.checked).toBe(false)
        expect(result?.newStatus).not.toBe("verified")
        expect(result?.message.toLowerCase()).toContain("destructivo")
        // El estado queda como estaba: un PoC que no se ejecuta no empuja nada.
        expect(yield* statusOf("find-poc-destructive")).toBe("in-progress")
      }),
    { timeout: 15000 },
  )

  it.effect(
    "un PoC cuyo target está fuera de scope no se ejecuta: checked=false y el estado no se mueve",
    () =>
      Effect.gen(function* () {
        let requests = 0
        const { server, port } = yield* Effect.promise(() =>
          startServer((_req, res) => {
            requests++
            res.writeHead(200, { "content-type": "text/html" })
            res.end("ok")
          }),
        )
        yield* seedFinding({
          id: "find-poc-out-of-scope",
          title: "SQL injection en /item",
          vector: "http://attacker.example.net/steal",
          status: "open",
          sessionId: SCOPED_SESSION_ID,
          poc: {
            kind: "sqli",
            method: "GET",
            url: `http://127.0.0.1:${port}/item?id=1`,
            payload: SQLI_PAYLOAD,
            matcher: { kind: "body_absent", needle: SQLI_PAYLOAD },
            baseline: { status: 200 },
          },
        })

        const { db } = yield* Database.Service
        const result = yield* retestFinding(db, "find-poc-out-of-scope", SCOPED_SESSION_ID, fixtureExecutor)
        server.close()

        expect(requests).toBe(0)
        expect(result?.checked).toBe(false)
        expect(result?.newStatus).toBe("open")
        expect(result?.newStatus).toBe(result?.previousStatus)
        expect(result?.message.toLowerCase()).toContain("scope")
        expect(yield* statusOf("find-poc-out-of-scope")).toBe("open")
      }),
    { timeout: 15000 },
  )

  it.effect(
    "un matcher 'timing_under' sobre un target que ya no delayea deja el hallazgo en 'verified'",
    () =>
      Effect.gen(function* () {
        const { server, port } = yield* Effect.promise(() =>
          startServer((_req, res) => {
            // El retardo ya no ocurre: el PoC time-based dejó de reproducir.
            res.writeHead(200, { "content-type": "text/html" })
            res.end("<html><body><p>Catalog</p></body></html>")
          }),
        )
        yield* seedFinding({
          id: "find-poc-timing",
          title: "SQL injection time-based en /item",
          vector: `http://127.0.0.1:${port}/item?id=1`,
          status: "in-progress",
          poc: {
            kind: "sqli",
            method: "GET",
            url: `http://127.0.0.1:${port}/item?id=${encodeURIComponent("1' AND SLEEP(3)--")}`,
            payload: "1' AND SLEEP(3)--",
            matcher: { kind: "timing_under", ms: 1500 },
            baseline: { status: 200 },
          },
        })

        const { db } = yield* Database.Service
        const result = yield* retestFinding(db, "find-poc-timing", undefined, fixtureExecutor)
        server.close()

        expect(result?.checked).toBe(true)
        expect(result?.stillVulnerable).toBe(false)
        expect(result?.newStatus).toBe("verified")
        expect(result?.message).toContain("timing_under")
        expect(yield* statusOf("find-poc-timing")).toBe("verified")
      }),
    { timeout: 15000 },
  )

  it.effect(
    "un hallazgo SIN PoC sigue sin verificación automática: 'in-progress'",
    () =>
      Effect.gen(function* () {
        const { server, port } = yield* Effect.promise(() =>
          startServer((_req, res) => {
            res.writeHead(200, { "content-type": "text/plain" })
            res.end("ok")
          }),
        )
        yield* seedFinding({
          id: "find-no-poc",
          title: "SQL injection en /login",
          vector: `http://127.0.0.1:${port}/login`,
        })

        const { db } = yield* Database.Service
        const result = yield* retestFinding(db, "find-no-poc", undefined, fixtureExecutor)
        server.close()

        expect(result?.checked).toBe(false)
        expect(result?.newStatus).toBe("in-progress")
        expect(result?.newStatus).not.toBe("verified")
      }),
    { timeout: 15000 },
  )
})

describe("ingest — el PoC que la tool escribe en la evidencia queda listo para el re-test", () => {
  it.effect("una tool que confirma un vector deja el PoC en su propia columna", () =>
    Effect.gen(function* () {
      yield* seedSession()
      const { db } = yield* Database.Service

      const output = JSON.stringify({
        findings: [
          {
            source: "web.sqli",
            source_tool: "web.sqli",
            title: "SQL injection en /item",
            severity: "critical",
            cwe: "CWE-89",
            target: "http://target.test/item",
            vector: "query:id",
            evidence: {
              surface: "query",
              parameter: "id",
              // Así es como las tools Go lo escriben: dentro de la evidencia.
              poc: {
                kind: "sqli",
                method: "GET",
                url: "http://target.test/item?id=1",
                headers: { "User-Agent": "Mozilla/5.0" },
                payload: SQLI_PAYLOAD,
                matcher: { kind: "body_absent", needle: SQLI_PAYLOAD },
                baseline: {
                  status: 200,
                  bodyDigest: digestBody("<html><body>error</body></html>"),
                  bodySnippet: "<html><body>error</body></html>",
                },
              },
            },
          },
        ],
      })

      yield* ingestToolFindings(
        db,
        {
          sessionID: SESSION_ID,
          type: "tool",
          tool: "web.sqli",
          state: { status: "completed", output },
        },
        { source: "import" },
      )

      const row = yield* db.select({ poc: FindingTable.poc }).from(FindingTable).get().pipe(Effect.orDie)
      expect(row?.poc?.kind).toBe("sqli")
      expect(row?.poc?.matcher.kind).toBe("body_absent")
      expect(row?.poc?.payload).toBe(SQLI_PAYLOAD)
      expect(row?.poc?.headers?.["User-Agent"]).toBe("Mozilla/5.0")
      expect(row?.poc?.baseline?.status).toBe(200)
      expect(row?.poc?.baseline?.bodyDigest).toBe(digestBody("<html><body>error</body></html>"))
      expect(row?.poc?.baseline?.bodySnippet).toBe("<html><body>error</body></html>")
    }),
  )
})

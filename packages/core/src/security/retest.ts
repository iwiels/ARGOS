import { and, eq } from "drizzle-orm"
import { Effect } from "effect"
import type { Database } from "../database/database"
import { applyMatcher, evaluatePocSafety, type PocRecord, type PocResponse } from "./poc"
import * as ScopeService from "./scope-service"
import { FindingTable } from "./sql"

type DatabaseService = Database.Interface["db"]

export type FindingLifecycleStatus =
  | "open"
  | "in-progress"
  | "remediated"
  | "verified"
  | "false-positive"
  | "accepted-risk"

export type RetestHttpRequest = {
  sessionId: string
  url: string
  method: string
  headers: Record<string, string>
  body?: string
  redirect: "manual"
  timeoutMs: number
  maxResponseBytes: number
}

export type RetestHttpExecutor = (request: RetestHttpRequest) => Promise<PocResponse | undefined>

export interface RetestResult {
  findingId: string
  previousStatus: string
  newStatus: string
  stillVulnerable: boolean
  /** false cuando no hay una verificación real detrás — ver `checked`. */
  checked: boolean
  message: string
  verifiedAt: number
}

/**
 * Actualiza el estado del ciclo de vida de un hallazgo con validación.
 */
export function updateFindingStatus(
  db: DatabaseService,
  findingId: string,
  newStatus: FindingLifecycleStatus,
  sessionId?: string,
): Effect.Effect<boolean> {
  return Effect.gen(function* () {
    const scope = sessionId
      ? and(eq(FindingTable.id, findingId), eq(FindingTable.session_id, sessionId))
      : eq(FindingTable.id, findingId)

    const existing = yield* db
      .select({ id: FindingTable.id, status: FindingTable.status })
      .from(FindingTable)
      .where(scope)
      .get()
      .pipe(Effect.orDie)

    if (!existing) return false

    yield* db
      .update(FindingTable)
      .set({
        status: newStatus,
        time_updated: Date.now(),
      })
      .where(scope)
      .run()
      .pipe(Effect.orDie)

    return true
  })
}

type PassiveCheck = {
  /** true si el chequeo determinó con evidencia real que sigue vulnerable/no. */
  checked: boolean
  stillVulnerable: boolean
  message: string
}

/** Veredicto del gate de scope: o pasa, o viene con su razón de rechazo. */
type ScopeVerdict = { allowed: true } | { allowed: false; error: ScopeService.ScopeViolationError }

const HEADER_CHECKS: Array<{
  test: (title: string) => boolean
  header: string
  present: (value: string) => string
  absent: string
}> = [
  {
    test: (t) => t.includes("hsts") || t.includes("strict-transport"),
    header: "strict-transport-security",
    present: (v) => `Cabecera Strict-Transport-Security presente: ${v}. Vulnerabilidad remediada.`,
    absent: "La cabecera Strict-Transport-Security aún no está presente en la respuesta.",
  },
  {
    test: (t) => t.includes("content-security-policy") || t.includes(" csp"),
    header: "content-security-policy",
    present: (v) => `Cabecera Content-Security-Policy presente: ${v.slice(0, 120)}${v.length > 120 ? "…" : ""}.`,
    absent: "La cabecera Content-Security-Policy aún no está presente en la respuesta.",
  },
  {
    test: (t) => t.includes("x-frame-options") || t.includes("clickjacking"),
    header: "x-frame-options",
    present: (v) => `Cabecera X-Frame-Options presente: ${v}. Vulnerabilidad remediada.`,
    absent: "La cabecera X-Frame-Options aún no está presente en la respuesta.",
  },
  {
    test: (t) => t.includes("x-content-type-options"),
    header: "x-content-type-options",
    present: (v) => `Cabecera X-Content-Type-Options presente: ${v}. Vulnerabilidad remediada.`,
    absent: "La cabecera X-Content-Type-Options aún no está presente en la respuesta.",
  },
]

/**
 * Verificación pasiva real contra la evidencia disponible del hallazgo.
 *
 * Antes: cualquier hallazgo sin lógica de verificación específica caía en un
 * `else` que marcaba `stillVulnerable = false` y "Re-test ejecutado. El
 * servicio respondió conforme al estándar de verificación" — SIN comprobar
 * nada. Eso es indistinguible de mentir: un hallazgo de SQLi o de puerto
 * expuesto se marcaba "verificado" solo porque el endpoint respondió 200 a
 * un GET, que no prueba absolutamente nada sobre esa vulnerabilidad
 * específica. Ahora, si no hay una verificación real disponible, `checked`
 * queda en `false` y el estado NO se mueve a "verified" — se deja al
 * operador humano confirmar.
 */
function evaluateHeaderResponse(title: string, headers: Record<string, string>): PassiveCheck {
  const normalized = title.toLowerCase()
  for (const check of HEADER_CHECKS) {
    if (!check.test(normalized)) continue
    const value = headers[check.header]
    return value
      ? { checked: true, stillVulnerable: false, message: check.present(value) }
      : { checked: true, stillVulnerable: true, message: check.absent }
  }
  return {
    checked: false,
    stillVulnerable: false,
    message:
      "No hay una verificación automática para este tipo de hallazgo. Requiere confirmación manual del operador.",
  }
}

function evaluateTlsResponse(title: string, ok: boolean, status: number): PassiveCheck {
  const normalized = title.toLowerCase()
  if (!normalized.includes("tls") && !normalized.includes("ssl") && !normalized.includes("certificado")) {
    return {
      checked: false,
      stillVulnerable: false,
      message:
        "No hay una verificación automática para este tipo de hallazgo. Requiere confirmación manual del operador.",
    }
  }
  // Una petición HTTPS que completa el handshake y responde confirma, como
  // mínimo, que el certificado ya no está bloqueando la conexión (los
  // navegadores/fetch rechazan handshakes con certificados inválidos antes
  // de recibir cualquier respuesta). No confirma vencimiento próximo
  // resuelto ni protocolo/cifrado específico — solo que el handshake ya no
  // falla, que es la causa más común de este tipo de hallazgo.
  if (ok || status > 0) {
    return {
      checked: true,
      stillVulnerable: false,
      message: "El handshake TLS se completó sin error. La condición de certificado inválido/vencido ya no reproduce.",
    }
  }
  return {
    checked: true,
    stillVulnerable: true,
    message: "El handshake TLS sigue fallando o el certificado sigue siendo inválido.",
  }
}

/** Límite del cuerpo que se lee en la re-ejecución: evita tragar una respuesta enorme. */
const MAX_POC_RESPONSE_BYTES = 1 << 20

/** Timeout de la re-ejecución: un PoC time-based necesita margen para el retardo. */
const POC_TIMEOUT_MS = 10_000

/**
 * Ejecuta el PoC y devuelve la respuesta con su latencia.
 *
 * Devuelve `undefined` cuando la petición no se pudo completar (error de red
 * o timeout): en ese caso el re-test no comprobó nada.
 */
async function executePoc(
  poc: PocRecord,
  sessionId: string,
  executor: RetestHttpExecutor,
): Promise<{ response: PocResponse; durationMs: number } | undefined> {
  const started = Date.now()
  try {
    const method = (poc.method || "GET").toUpperCase()
    const response = await executor({
      sessionId,
      url: poc.url,
      method,
      headers: {
        "User-Agent": "Argos-Retest-Engine/2.0",
        ...poc.headers,
      },
      body: method === "GET" || method === "HEAD" ? undefined : (poc.body ?? undefined),
      redirect: "manual",
      timeoutMs: POC_TIMEOUT_MS,
      maxResponseBytes: MAX_POC_RESPONSE_BYTES,
    })
    if (!response) return undefined
    const durationMs = response.durationMs ?? Date.now() - started
    return { response: { ...response, durationMs }, durationMs }
  } catch {
    return undefined
  }
}

/**
 * Re-test por tipo de vector: re-ejecuta el PoC del hallazgo y compara la
 * respuesta nueva con la original.
 *
 * El PoC lo escribe la tool que confirmó el vector (lo persistió en
 * `evidence["poc"]` y el ingest lo levantó a su columna). Un PoC
 * `destructive` nunca se ejecuta: re-ejecutarlo sería repetir el daño que la
 * herramienta secto de no hacer.
 *
 * Invariante de seguridad: el `vector` del hallazgo lo escribe una tool o un
 * agente, no el operador — no es una fuente confiable. Antes de emitir la
 * petición de re-verificación se valida contra el scope de la sesión: sin ese
 * gate, un finding con vector malicioso convierte el re-test en un SSRF
 * contra cualquier host, incluida la red interna del operador.
 */
export function retestFinding(
  db: DatabaseService,
  findingId: string,
  sessionId?: string,
  executor?: RetestHttpExecutor,
): Effect.Effect<RetestResult | undefined, never, ScopeService.Service> {
  return Effect.gen(function* () {
    const scope = sessionId
      ? and(eq(FindingTable.id, findingId), eq(FindingTable.session_id, sessionId))
      : eq(FindingTable.id, findingId)

    const finding = yield* db.select().from(FindingTable).where(scope).get().pipe(Effect.orDie)

    if (!finding) return undefined

    const previousStatus = finding.status
    if (!executor) {
      return {
        findingId,
        previousStatus,
        newStatus: previousStatus,
        stillVulnerable: false,
        checked: false,
        message: "Re-test omitido: transporte aislado no disponible. Requiere confirmación manual del operador.",
        verifiedAt: Date.now(),
      } satisfies RetestResult
    }
    const poc = finding.poc ?? undefined

    let outcome: PassiveCheck = {
      checked: false,
      stillVulnerable: false,
      message: "El hallazgo no tiene un vector HTTP/HTTPS verificable de forma pasiva. Requiere confirmación manual.",
    }
    let validationEvidence: Record<string, unknown> | undefined

    if (poc) {
      const pocResult = yield* retestWithPoc(finding.session_id, sessionId, poc, executor)
      outcome = pocResult.outcome
      validationEvidence = pocResult.evidence
      if (pocResult.skip) {
        // El PoC no se ejecutó por estar fuera de scope: el estado del
        // hallazgo se queda donde estaba, sin evidencia que lo mueva.
        return {
          findingId,
          previousStatus,
          newStatus: previousStatus,
          stillVulnerable: false,
          checked: false,
          message: pocResult.outcome.message,
          verifiedAt: Date.now(),
        } satisfies RetestResult
      }
    } else {
      const passive = yield* passiveRetest(
        finding.title,
        finding.vector || finding.target || undefined,
        sessionId,
        finding.session_id,
        executor,
      )
      if (passive.skip) {
        return {
          findingId,
          previousStatus,
          newStatus: previousStatus,
          stillVulnerable: false,
          checked: false,
          message: passive.outcome.message,
          verifiedAt: Date.now(),
        } satisfies RetestResult
      }
      outcome = passive.outcome
    }

    const verifiedAt = Date.now()
    // Sin verificación real, la corrección más honesta es "en curso" — deja
    // constancia de que se intentó re-testear sin afirmar un resultado que
    // no se comprobó. Nunca cae en "verified" por defecto.
    const newStatus: FindingLifecycleStatus = !outcome.checked
      ? "in-progress"
      : outcome.stillVulnerable
        ? "open"
        : "verified"

    yield* db
      .update(FindingTable)
      .set({
        status: newStatus,
        ...(validationEvidence ? { validation_evidence: validationEvidence, validated_at: verifiedAt } : {}),
        time_updated: verifiedAt,
      })
      .where(eq(FindingTable.id, findingId))
      .run()
      .pipe(Effect.orDie)

    return {
      findingId,
      previousStatus,
      newStatus,
      stillVulnerable: outcome.stillVulnerable,
      checked: outcome.checked,
      message: outcome.message,
      verifiedAt,
    } satisfies RetestResult
  })
}

/** Resultado interno del re-test por PoC. */
type PocRetest = {
  outcome: PassiveCheck
  evidence?: Record<string, unknown>
  /** true cuando el PoC no se ejecutó y el estado no se debe mover. */
  skip?: boolean
}

/**
 * Re-ejecuta el PoC del hallazgo y aplica el matcher.
 *
 * El orden importa: el gate de scope va antes de la petición (un PoC con una
 * URL fuera del alcance es un SSRF), y la evaluación de seguridad va antes
 * también (un PoC destructivo nunca se ejecuta, aunque el target esté en
 * scope).
 */
function retestWithPoc(
  findingSessionId: string,
  sessionId: string | undefined,
  poc: PocRecord,
  executor: RetestHttpExecutor,
): Effect.Effect<PocRetest, never, ScopeService.Service> {
  return Effect.gen(function* () {
    const target = poc.url.trim()
    if (!target.startsWith("http://") && !target.startsWith("https://")) {
      return {
        outcome: {
          checked: false,
          stillVulnerable: false,
          message:
            "El PoC del hallazgo no apunta a un target HTTP/HTTPS verificable. Requiere confirmación manual del operador.",
        },
        skip: true,
      } satisfies PocRetest
    }

    const scopeService = yield* ScopeService.Service
    const verdict: ScopeVerdict = yield* scopeService.assertTarget(sessionId ?? findingSessionId, target).pipe(
      Effect.map(() => ({ allowed: true }) as const),
      Effect.catchTag("ScopeViolationError", (error) => Effect.succeed({ allowed: false, error } as const)),
    )

    if (!verdict.allowed) {
      // El estado del hallazgo NO se mueve: un target fuera del alcance no
      // puede empujar el hallazgo a "verified" ni a "open" — no hay
      // evidencia de nada y el re-test queda para confirmación manual.
      return {
        outcome: {
          checked: false,
          stillVulnerable: false,
          message: `Re-test omitido: el target del PoC está fuera del scope autorizado. Requiere confirmación manual. (${verdict.error.reason})`,
        },
        skip: true,
      } satisfies PocRetest
    }

    const safety = evaluatePocSafety({
      target,
      payload: poc.payload,
      method: poc.method,
      headers: poc.headers,
    })
    const bodySafety = poc.body
      ? evaluatePocSafety({ target, payload: poc.body, method: poc.method, headers: poc.headers })
      : undefined
    const destructive = !safety.safe || (bodySafety !== undefined && !bodySafety.safe)
    if (destructive) {
      return {
        outcome: {
          checked: false,
          stillVulnerable: false,
          message:
            "El PoC del hallazgo es destructivo: nunca se re-ejecuta. Requiere confirmación manual del operador.",
        },
        evidence: {
          poc_kind: poc.kind,
          matcher: poc.matcher.kind,
          skipped: "destructive_poc",
        },
      } satisfies PocRetest
    }

    const executed = yield* Effect.tryPromise({
      try: async () => await executePoc(poc, sessionId ?? findingSessionId, executor),
      catch: (err) => err,
    }).pipe(Effect.catch(() => Effect.succeed(undefined)))

    if (!executed) {
      return {
        outcome: {
          checked: false,
          stillVulnerable: false,
          message: "No se pudo re-ejecutar el PoC (timeout o error de red). Requiere confirmación manual del operador.",
        },
      } satisfies PocRetest
    }

    const baselineStatus = poc.baseline?.status ?? 0
    const retestStatus = executed.response.status
    // Un 5xx es un endpoint que ahora falla y un 3xx es una redirección: en
    // ninguno de los dos casos la ausencia del payload en la respuesta prueba
    // que la vulnerabilidad esté remediada. Y las redirecciones no se siguen:
    // el gate de scope autorizó la URL del PoC, no su destino.
    if (retestStatus >= 300 && retestStatus < 400) {
      return {
        outcome: {
          checked: false,
          stillVulnerable: false,
          message: `El PoC fue re-ejecutado pero el endpoint respondió ${retestStatus} (redirección): la re-ejecución no es concluyente. Requiere confirmación manual del operador.`,
        },
        evidence: pocEvidence(poc, retestStatus, executed.durationMs, false, "redirect"),
      } satisfies PocRetest
    }
    if (retestStatus >= 500 && baselineStatus < 500) {
      // El endpoint ahora falla: la ausencia del payload en una página de
      // error no prueba que la vulnerabilidad esté remediada.
      return {
        outcome: {
          checked: false,
          stillVulnerable: false,
          message: `El PoC fue re-ejecutado pero el endpoint respondió ${retestStatus}: la re-ejecución no es concluyente. Requiere confirmación manual del operador.`,
        },
        evidence: pocEvidence(poc, retestStatus, executed.durationMs, false, "endpoint_error"),
      } satisfies PocRetest
    }

    const applied = applyMatcher(poc.matcher, executed.response, poc.baseline)
    if (!applied.applicable) {
      return {
        outcome: {
          checked: false,
          stillVulnerable: false,
          message: `El PoC fue re-ejecutado pero su matcher no se pudo aplicar: ${applied.detail} Requiere confirmación manual del operador.`,
        },
        evidence: pocEvidence(poc, executed.response.status, executed.durationMs, false, "matcher_not_applicable"),
      } satisfies PocRetest
    }

    // La dirección del matcher decide el veredicto: los matchers de ausencia
    // se cumplen cuando el síntoma desapareció, los de estado y cabecera se
    // cumplen cuando la condición vulnerable sigue presente.
    const stillVulnerable = applied.direction === "remediated" ? !applied.matched : applied.matched
    const conclusion = stillVulnerable
      ? "El PoC volvió a reproducir la vulnerabilidad: sigue presente."
      : "El PoC fue re-ejecutado y dejó de reproducirse."

    return {
      outcome: {
        checked: true,
        stillVulnerable,
        message: `PoC re-ejecutado (${poc.kind}, matcher: ${poc.matcher.kind}): ${applied.detail} ${conclusion}`,
      },
      evidence: pocEvidence(poc, executed.response.status, executed.durationMs, stillVulnerable, undefined, applied),
    } satisfies PocRetest
  })
}

/** Evidencia del re-test: qué se comparó, con qué y con qué resultado. */
function pocEvidence(
  poc: PocRecord,
  retestStatus: number,
  durationMs: number,
  stillVulnerable: boolean,
  skipped?: string,
  applied?: ReturnType<typeof applyMatcher>,
): Record<string, unknown> {
  return {
    poc_kind: poc.kind,
    matcher: poc.matcher.kind,
    baseline_status: poc.baseline?.status,
    retest_status: retestStatus,
    executed_at: Date.now(),
    duration_ms: durationMs,
    still_vulnerable: stillVulnerable,
    ...(skipped ? { skipped } : {}),
    ...(applied
      ? {
          applied_matcher: applied.applied.kind,
          degraded: applied.degraded,
          confidence: applied.confidence,
          detail: applied.detail,
        }
      : {}),
  }
}

/**
 * Re-test pasivo: la verificación de cabeceras y del handshake TLS.
 *
 * Es el fallback para los hallazgos que no tienen PoC: los que no se pueden
 * comprobar de forma específica quedan para confirmación manual.
 */
function passiveRetest(
  title: string,
  targetUrl: string | undefined,
  sessionId: string | undefined,
  findingSessionId: string,
  executor: RetestHttpExecutor,
): Effect.Effect<PocRetest, never, ScopeService.Service> {
  return Effect.gen(function* () {
    if (!targetUrl || (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://"))) {
      return {
        outcome: {
          checked: false,
          stillVulnerable: false,
          message:
            "El hallazgo no tiene un vector HTTP/HTTPS verificable de forma pasiva. Requiere confirmación manual.",
        },
      } satisfies PocRetest
    }

    const scopeService = yield* ScopeService.Service
    const verdict: ScopeVerdict = yield* scopeService.assertTarget(sessionId ?? findingSessionId, targetUrl).pipe(
      Effect.map(() => ({ allowed: true }) as const),
      Effect.catchTag("ScopeViolationError", (error) => Effect.succeed({ allowed: false, error } as const)),
    )

    if (!verdict.allowed) {
      // El estado del hallazgo NO se mueve: un target fuera del alcance no
      // puede empujar el hallazgo a "verified" ni a "open" — no hay
      // evidencia de nada y el re-test queda para confirmación manual.
      return {
        outcome: {
          checked: false,
          stillVulnerable: false,
          message: `Re-test omitido: el target está fuera del scope autorizado. Requiere confirmación manual. (${verdict.error.reason})`,
        },
        skip: true,
      } satisfies PocRetest
    }

    if (!evaluatePocSafety({ target: targetUrl, method: "GET" }).safe) {
      return {
        outcome: {
          checked: false,
          stillVulnerable: false,
          message: "Re-test omitido: el target contiene un patrón destructivo. Requiere confirmación manual.",
        },
        skip: true,
      } satisfies PocRetest
    }

    const probeResult = yield* Effect.tryPromise({
      try: () =>
        executor({
          sessionId: sessionId ?? findingSessionId,
          url: targetUrl,
          method: "GET",
          headers: { "User-Agent": "Argos-Retest-Engine/1.0" },
          redirect: "manual",
          timeoutMs: 6000,
          maxResponseBytes: MAX_POC_RESPONSE_BYTES,
        }),
      catch: (err) => err,
    }).pipe(Effect.catch(() => Effect.succeed(undefined)))

    if (!probeResult || typeof probeResult !== "object") {
      return {
        outcome: {
          checked: false,
          stillVulnerable: false,
          message:
            "No se pudo contactar al target para re-verificar (timeout o error de red). Requiere confirmación manual.",
        },
      } satisfies PocRetest
    }

    if (probeResult.status >= 300 && probeResult.status < 400) {
      return {
        outcome: {
          checked: false,
          stillVulnerable: false,
          message: `El endpoint respondió ${probeResult.status} (redirección): el re-test no es concluyente. Requiere confirmación manual.`,
        },
      } satisfies PocRetest
    }

    const result = probeResult
    const headerOutcome = evaluateHeaderResponse(title, result.headers)
    return {
      outcome: headerOutcome.checked
        ? headerOutcome
        : evaluateTlsResponse(title, result.status >= 200 && result.status < 300, result.status),
    } satisfies PocRetest
  })
}

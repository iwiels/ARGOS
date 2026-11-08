/**
 * Resumen del proof of concept de un hallazgo.
 *
 * El PoC lo escribe la tool que confirmó el vector (viaja dentro de la
 * evidencia) y el motor de re-test lo re-ejecuta: la fila del ledger lo
 * muestra para que el auditor sepa QUÉ se comprobó y con qué matcher, no
 * sólo que el hallazgo quedó "verified".
 */

export interface PocSummary {
  /** Tipo de vector: "sqli" | "xss" | "ssti" | "jwt" | … */
  kind: string
  /** El matcher con el que se compara la respuesta nueva con la original. */
  matcher: string
  method: string
  url: string
  payload?: string
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value)

const str = (value: unknown): string | undefined => {
  if (typeof value !== "string") return undefined
  const trimmed = value.trim()
  return trimmed ? trimmed : undefined
}

/**
 * Extrae el PoC de la evidencia de un hallazgo.
 *
 * La evidencia llega como texto: puede ser el PoC mismo (la evidencia
 * "plana" lo desenvuelve cuando el único contenido interesante es el PoC) o
 * el objeto de evidencia completo con el PoC dentro.
 */
export function pocSummaryFromEvidence(evidence: string | undefined): PocSummary | undefined {
  if (!evidence) return undefined
  let parsed: unknown
  try {
    parsed = JSON.parse(evidence)
  } catch {
    return undefined
  }
  if (!isRecord(parsed)) return undefined
  const candidate = isRecord(parsed.poc) ? parsed.poc : parsed
  return toSummary(candidate)
}

function toSummary(candidate: Record<string, unknown>): PocSummary | undefined {
  const kind = str(candidate.kind)
  const matcher = candidate.matcher
  if (!kind || !isRecord(matcher)) return undefined
  const matcherKind = str(matcher.kind)
  if (!matcherKind) return undefined
  const summary: PocSummary = {
    kind,
    matcher: matcherKind,
    method: str(candidate.method) ?? "GET",
    url: str(candidate.url) ?? "",
  }
  const payload = str(candidate.payload)
  if (payload) summary.payload = payload
  return summary
}

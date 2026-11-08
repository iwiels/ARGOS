import { Effect } from "effect"
import type { Ioc } from "./iocs"

/**
 * Reputation para IoCs. Los proveedores (VirusTotal, AbuseIPDB) se consumen
 * con la API key del CLIENTE vía env vars — nunca redistribuimos datos de
 * terceros; cada despliegue aporta sus propias credenciales.
 *
 * Sin key configurada la búsqueda se omite (resultado vacío), degradando con
 * gracia — el enrichment local (ATT&CK + IoC extraction) siempre corre.
 */

export type ReputationSource = "virustotal" | "abuseipdb"

export type ReputationVerdict = "malicious" | "suspicious" | "clean" | "unknown"

export interface ReputationResult {
  source: ReputationSource
  verdict: ReputationVerdict
  /** Score numérico: detecciones maliciosas VT o confidence score de AbuseIPDB. */
  score: number
  detail: string
  checkedAt: number
}

export interface ReputationConfig {
  virusTotalKey?: string
  abuseIPDBKey?: string
  /** Tiempo máximo por lookup (ms). */
  timeoutMs?: number
}

export const reputationConfigFromEnv = (): ReputationConfig => ({
  virusTotalKey: process.env.ARGOS_VIRUSTOTAL_KEY || undefined,
  abuseIPDBKey: process.env.ARGOS_ABUSEIPDB_KEY || undefined,
})

const TIMEOUT_MS = 5000

const fetchJson = (
  url: string,
  headers: Record<string, string>,
  timeoutMs: number,
): Effect.Effect<Record<string, unknown> | undefined> =>
  Effect.tryPromise({
    try: async () => {
      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), timeoutMs)
      try {
        const response = await fetch(url, { headers, signal: controller.signal })
        if (!response.ok) throw new Error(`HTTP ${response.status}`)
        return (await response.json()) as Record<string, unknown>
      } finally {
        clearTimeout(timer)
      }
    },
    catch: (error: unknown) => error,
  }).pipe(Effect.catch(() => Effect.succeed(undefined as Record<string, unknown> | undefined)))

/** VirusTotal v3: ip_addresses, domains, files. */
const virusTotalLookup = (ioc: Ioc, key: string, timeoutMs: number) => {
  const segment =
    ioc.type === "ip"
      ? `ip_addresses/${encodeURIComponent(ioc.value)}`
      : ioc.type === "domain"
        ? `domains/${encodeURIComponent(ioc.value)}`
        : ioc.type === "hash"
          ? `files/${encodeURIComponent(ioc.value)}`
          : undefined
  if (!segment) return Effect.succeed(undefined)
  const url = `https://www.virustotal.com/api/v3/${segment}`
  return fetchJson(url, { "x-apikey": key }, timeoutMs).pipe(
    Effect.map((body) => {
      const attrs = body?.["data"] as Record<string, unknown> | undefined
      const stats = (attrs?.["attributes"] as Record<string, unknown> | undefined)?.["last_analysis_stats"] as
        | Record<string, unknown>
        | undefined
      if (!stats) return undefined
      const malicious = Number(stats["malicious"] ?? 0)
      const suspicious = Number(stats["suspicious"] ?? 0)
      const verdict: ReputationVerdict =
        malicious > 0 ? "malicious" : suspicious > 0 ? "suspicious" : "clean"
      return {
        source: "virustotal" as const,
        verdict,
        score: malicious,
        detail: `VT: ${malicious} malicious / ${suspicious} suspicious detections`,
        checkedAt: Date.now(),
      } satisfies ReputationResult
    }),
  )
}

/** AbuseIPDB v2: solo IPs. */
const abuseIpdbLookup = (ioc: Ioc, key: string, timeoutMs: number) => {
  if (ioc.type !== "ip") return Effect.succeed(undefined)
  const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ioc.value)}&maxAgeInDays=90`
  return fetchJson(url, { Key: key, Accept: "application/json" }, timeoutMs).pipe(
    Effect.map((body) => {
      const data = body?.["data"] as Record<string, unknown> | undefined
      if (!data) return undefined
      const score = Number(data["abuseConfidenceScore"] ?? 0)
      const reports = Number(data["totalReports"] ?? 0)
      const verdict: ReputationVerdict =
        score >= 50 || reports >= 5 ? "malicious" : score >= 25 ? "suspicious" : "clean"
      return {
        source: "abuseipdb" as const,
        verdict,
        score,
        detail: `AbuseIPDB: ${score}% confidence, ${reports} reports`,
        checkedAt: Date.now(),
      } satisfies ReputationResult
    }),
  )
}

/**
 * Consulta la reputación de un IoC contra los proveedores configurados.
 * Devuelve [] si no hay keys o el IoC no es consultable.
 */
export const lookupIocReputation = (
  ioc: Ioc,
  config: ReputationConfig = reputationConfigFromEnv(),
): Effect.Effect<ReputationResult[]> => {
  const timeoutMs = config.timeoutMs ?? TIMEOUT_MS
  const lookups: Effect.Effect<ReputationResult | undefined>[] = []
  if (config.virusTotalKey) lookups.push(virusTotalLookup(ioc, config.virusTotalKey, timeoutMs))
  if (config.abuseIPDBKey) lookups.push(abuseIpdbLookup(ioc, config.abuseIPDBKey, timeoutMs))
  if (lookups.length === 0) return Effect.succeed([])
  return Effect.all(lookups, { concurrency: "unbounded" }).pipe(
    Effect.map((results) => results.filter((result): result is ReputationResult => !!result)),
  )
}

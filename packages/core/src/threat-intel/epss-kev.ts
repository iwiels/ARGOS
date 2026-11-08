import { Effect } from "effect"

export interface EpssResult {
  cve: string
  epssScore: number
  epssPercentile: number
  date?: string
}

export interface CisaKevResult {
  isKev: boolean
  cve: string
  vendorProject?: string
  product?: string
  vulnerabilityName?: string
  dateAdded?: string
  shortDescription?: string
  requiredAction?: string
  dueDate?: string
  notes?: string
}

export interface EpssKevEnrichment {
  cves: string[]
  primaryCve?: string
  epss?: EpssResult
  cisaKev?: CisaKevResult
  allEpss: EpssResult[]
  allKev: CisaKevResult[]
  checkedAt: number
}

const CVE_REGEX = /\bCVE-\d{4}-\d{4,7}\b/gi

/** Extrae CVEs únicos normalizados en mayúsculas desde cualquier texto o payload. */
export function extractCves(input: unknown): string[] {
  if (!input) return []
  const text = typeof input === "string" ? input : JSON.stringify(input)
  const matches = text.match(CVE_REGEX)
  if (!matches) return []
  return Array.from(new Set(matches.map((cve) => cve.toUpperCase())))
}

const epssCache = new Map<string, { result?: EpssResult; expiresAt: number }>()
const KEV_CACHE_TTL_MS = 24 * 60 * 60 * 1000 // 24 horas
const EPSS_CACHE_TTL_MS = 6 * 60 * 60 * 1000 // 6 horas

let cisaKevCatalogCache: { catalog: Map<string, Record<string, unknown>>; expiresAt: number } | undefined

const fetchJson = (
  url: string,
  timeoutMs: number,
): Effect.Effect<Record<string, unknown> | undefined> =>
  Effect.tryPromise({
    try: async () => {
      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), timeoutMs)
      try {
        const response = await fetch(url, {
          headers: { Accept: "application/json", "User-Agent": "Argos-ThreatIntel/1.0" },
          signal: controller.signal,
        })
        if (!response.ok) throw new Error(`HTTP ${response.status}`)
        return (await response.json()) as Record<string, unknown>
      } finally {
        clearTimeout(timer)
      }
    },
    catch: (error: unknown) => error,
  }).pipe(Effect.catch(() => Effect.succeed(undefined as Record<string, unknown> | undefined)))

/** Consulta el score EPSS en First.org con caché en memoria. */
export const lookupEpss = (cve: string, timeoutMs = 5000): Effect.Effect<EpssResult | undefined> => {
  const norm = cve.toUpperCase().trim()
  const cached = epssCache.get(norm)
  if (cached && cached.expiresAt > Date.now()) {
    return Effect.succeed(cached.result)
  }

  const url = `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(norm)}`
  return fetchJson(url, timeoutMs).pipe(
    Effect.map((body) => {
      const dataArr = body?.["data"] as Array<Record<string, unknown>> | undefined
      const item = dataArr?.[0]
      if (!item) {
        epssCache.set(norm, { result: undefined, expiresAt: Date.now() + EPSS_CACHE_TTL_MS })
        return undefined
      }

      const score = typeof item["epss"] === "string" ? parseFloat(item["epss"]) : Number(item["epss"] ?? 0)
      const percentile = typeof item["percentile"] === "string" ? parseFloat(item["percentile"]) : Number(item["percentile"] ?? 0)
      const date = typeof item["date"] === "string" ? item["date"] : undefined

      const result: EpssResult = {
        cve: norm,
        epssScore: isNaN(score) ? 0 : score,
        epssPercentile: isNaN(percentile) ? 0 : percentile,
        date,
      }
      epssCache.set(norm, { result, expiresAt: Date.now() + EPSS_CACHE_TTL_MS })
      return result
    }),
  )
}

/** Carga y cachea el catálogo CISA KEV oficial. */
const loadCisaKevCatalog = (timeoutMs = 8000): Effect.Effect<Map<string, Record<string, unknown>>> => {
  if (cisaKevCatalogCache && cisaKevCatalogCache.expiresAt > Date.now()) {
    return Effect.succeed(cisaKevCatalogCache.catalog)
  }

  const url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
  return fetchJson(url, timeoutMs).pipe(
    Effect.map((body) => {
      const map = new Map<string, Record<string, unknown>>()
      const vulns = body?.["vulnerabilities"] as Array<Record<string, unknown>> | undefined
      if (Array.isArray(vulns)) {
        for (const v of vulns) {
          const id = typeof v["cveID"] === "string" ? v["cveID"].toUpperCase().trim() : undefined
          if (id) map.set(id, v)
        }
      }
      cisaKevCatalogCache = { catalog: map, expiresAt: Date.now() + KEV_CACHE_TTL_MS }
      return map
    }),
  )
}

/** Verifica si un CVE está en el catálogo CISA KEV (Known Exploited Vulnerabilities). */
export const checkCisaKev = (cve: string, timeoutMs = 8000): Effect.Effect<CisaKevResult> => {
  const norm = cve.toUpperCase().trim()
  return loadCisaKevCatalog(timeoutMs).pipe(
    Effect.map((catalog) => {
      const item = catalog.get(norm)
      if (!item) {
        return { isKev: false, cve: norm } satisfies CisaKevResult
      }
      return {
        isKev: true,
        cve: norm,
        vendorProject: typeof item["vendorProject"] === "string" ? item["vendorProject"] : undefined,
        product: typeof item["product"] === "string" ? item["product"] : undefined,
        vulnerabilityName: typeof item["vulnerabilityName"] === "string" ? item["vulnerabilityName"] : undefined,
        dateAdded: typeof item["dateAdded"] === "string" ? item["dateAdded"] : undefined,
        shortDescription: typeof item["shortDescription"] === "string" ? item["shortDescription"] : undefined,
        requiredAction: typeof item["requiredAction"] === "string" ? item["requiredAction"] : undefined,
        dueDate: typeof item["dueDate"] === "string" ? item["dueDate"] : undefined,
        notes: typeof item["notes"] === "string" ? item["notes"] : undefined,
      } satisfies CisaKevResult
    }),
  )
}

/**
 * Enriquecimiento consolidado de EPSS + KEV para una lista de CVEs.
 * Selecciona como primario aquel con CISA KEV activo o con mayor EPSS score.
 */
export const enrichEpssAndKev = (
  cves: string[],
  opts?: { timeoutMs?: number },
): Effect.Effect<EpssKevEnrichment | undefined> =>
  Effect.gen(function* () {
    if (cves.length === 0) return undefined
    const timeout = opts?.timeoutMs ?? 6000

    const epssResults = yield* Effect.all(cves.map((cve) => lookupEpss(cve, timeout)), {
      concurrency: 5,
    })
    const kevResults = yield* Effect.all(cves.map((cve) => checkCisaKev(cve, timeout)), {
      concurrency: 5,
    })

    const allEpss = epssResults.filter((r): r is EpssResult => r !== undefined)
    const allKev = kevResults.filter((r): r is CisaKevResult => r.isKev)

    // Determinar el CVE de mayor impacto (KEV primero, luego mayor EPSS score)
    let primaryCve: string | undefined = allKev[0]?.cve
    if (!primaryCve && allEpss.length > 0) {
      const sorted = [...allEpss].sort((a, b) => b.epssScore - a.epssScore)
      primaryCve = sorted[0]?.cve
    }
    if (!primaryCve) {
      primaryCve = cves[0]
    }

    const primaryEpss = allEpss.find((e) => e.cve === primaryCve) || allEpss[0]
    const primaryKev = allKev.find((k) => k.cve === primaryCve) || allKev[0]

    return {
      cves,
      primaryCve,
      epss: primaryEpss,
      cisaKev: primaryKev,
      allEpss,
      allKev,
      checkedAt: Date.now(),
    } satisfies EpssKevEnrichment
  })

import { createMemo, createResource, type Accessor } from "solid-js"
import { useOptionalServerSync } from "@/context/server-sync"
import { useSync } from "@/context/sync"
import { useSDK } from "@/context/sdk"
import {
  extractFindings,
  mergeFindingBuckets,
  normalizeToolParts,
  type Finding,
  type Severity,
  SEVERITY_ORDER,
  severityCounts,
} from "@/components/session/findings-data"
import { extractedToolPartsSignature } from "@/components/session/topology-data"
import { loadFindingsForSessions } from "@/components/session/security-findings-api"
import { collectSessionFamilyIds } from "@/pages/layout/helpers"
import { selectSessionFindings } from "./audit-findings-selection"

const extractionCache = new Map<string, { sig: number; findings: Finding[] }>()
const extractionCacheLimit = 512

function cachedExtractFindings(
  messageID: string,
  rawParts: readonly unknown[] | undefined,
): Finding[] {
  const sig = extractedToolPartsSignature(rawParts)
  const cached = extractionCache.get(messageID)
  if (cached && cached.sig === sig) return cached.findings
  const findings = extractFindings(normalizeToolParts(rawParts ?? []))
  extractionCache.set(messageID, { sig, findings })
  if (extractionCache.size > extractionCacheLimit) extractionCache.clear()
  return findings
}

export interface UseAuditFindingsOptions {
  dir?: Accessor<string | undefined> | string
  sessionID?: Accessor<string | undefined> | string
  persistedOnly?: boolean
}

export interface UseAuditFindingsResult {
  findings: Accessor<Finding[]>
  counts: Accessor<Record<Severity, number>>
  total: Accessor<number>
  loading: Accessor<boolean>
  error: Accessor<unknown>
  refetch: () => void
}

export function useAuditFindings(options: UseAuditFindingsOptions = {}): UseAuditFindingsResult {
  const serverSync = useOptionalServerSync()
  let sync: ReturnType<typeof useSync> | undefined
  try {
    sync = useSync()
  } catch {}
  let sdk: ReturnType<typeof useSDK> | undefined
  try {
    sdk = useSDK()
  } catch {}

  const getDir = () => (typeof options.dir === "function" ? options.dir() : options.dir) ?? ""
  const getSessionID = () => (typeof options.sessionID === "function" ? options.sessionID() : options.sessionID)

  const childStore = createMemo(() => (serverSync && getDir() ? serverSync.child(getDir(), { bootstrap: false })[0] : undefined))

  const sessions = createMemo(() => {
    const sid = getSessionID()
    if (sid && sync) {
      const family = collectSessionFamilyIds(sync.data.session, sid)
      return (sync.data.session ?? []).filter((s) => family.includes(s.id))
    }
    return childStore()?.session ?? []
  })

  const [apiFindingsResource, { refetch }] = createResource(
    () =>
      sessions()
        .map((s) => s.id)
        .join("\0"),
    (sessionKey) =>
      sdk
        ? loadFindingsForSessions(sdk.request, sessionKey ? sessionKey.split("\0") : []).catch((err) => {
            console.warn("Failed to load audit findings:", err)
            return {} as Record<string, Finding[]>
          })
        : Promise.resolve({} as Record<string, Finding[]>),
  )

  const findings = createMemo(() => {
    const findingBuckets: Finding[][] = []
    const sessionList = sessions()
    let apiData: Record<string, Finding[]> | undefined
    try {
      apiData = (apiFindingsResource.state === "ready" ? apiFindingsResource() : apiFindingsResource.latest) as Record<string, Finding[]> | undefined
    } catch {
      apiData = undefined
    }

    for (const session of sessionList) {
      const perMessageFindings: Finding[][] = []

      if (sync && !options.persistedOnly) {
        const messages = sync.data.message[session.id] ?? []
        for (const msg of messages) {
          perMessageFindings.push(cachedExtractFindings(msg.id, sync.data.part[msg.id]))
        }
      }

      const sessionFindings = selectSessionFindings(session.id, apiData?.[session.id] ?? [], perMessageFindings.flat(), options.persistedOnly)
      findingBuckets.push(sessionFindings.map((finding, index) => ({
        ...finding,
        session: session.id,
        observationID: finding.id || finding.fingerprint ? finding.observationID : finding.observationID ?? `local:${session.id}:${index}`,
      })))
    }

    return mergeFindingBuckets(findingBuckets).sort(
      (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
    )
  })

  const counts = createMemo(() => severityCounts(findings()))
  const total = createMemo(() => findings().length)

  return {
    findings,
    counts,
    total,
    loading: () => apiFindingsResource.loading,
    error: () => apiFindingsResource.error,
    refetch,
  }
}

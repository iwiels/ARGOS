import { useServerSync } from "@/context/server-sync"
import { useSync } from "@/context/sync"
import { useSDK } from "@/context/sdk"
import { useLanguage } from "@/context/language"
import { useParams, A } from "@solidjs/router"
import { Icon } from "@argos/ui/icon"
import { PageHeader } from "@/components/audit-ui"
import { decode64 } from "@/utils/base64"

import { createMemo, createResource, For, Show } from "solid-js"
import { createStore } from "solid-js/store"
import { TopologyCanvas } from "@/components/session/topology-canvas"
import {
  createTopologySnapshotSource,
  DEFAULT_RISKY_PORTS,
  type TopologySnapshot,
} from "@/components/session/topology-data"
import { collectSessionFamilyIds } from "@/pages/layout/helpers"
import { loadFindingsForSessions } from "@/components/session/security-findings-api"

interface SessionTopologyEntry {
  sessionId: string
  sessionTitle: string
  snapshot: TopologySnapshot
}

function countRiskyDevices(snap: TopologySnapshot): number {
  const devices = snap.devices ?? []
  return devices.filter((d) => d.openPorts?.some((p) => DEFAULT_RISKY_PORTS.has(p)) ?? false).length
}

export default function TopologyPage() {
  const params = useParams<{ auditId?: string; dir?: string }>()
  const serverSync = useServerSync()
  const sync = useSync()
  const sdk = useSDK()
  const language = useLanguage()
  const [store, setStore] = createStore<{
    selectedSession: string | null
    search: string
  }>({
    selectedSession: null,
    search: "",
  })

  const targetDir = () => {
    if (params.auditId) return decode64(params.auditId) ?? params.auditId
    if (params.dir) return decode64(params.dir) ?? params.dir
    return ""
  }

  const [childStore] = serverSync.child(targetDir(), { bootstrap: false })
  const sessions = createMemo(() => childStore?.session ?? [])

  // Findings reconciled from peer agents (e.g. security-ops running the LAN
  // scan out-of-process) — see topologyPartsFromFindings for why live message
  // parts alone miss network scans that didn't run in this exact session.
  const [reconciledFindings] = createResource(
    () => sessions().map((s) => s.id).join("\0"),
    (key) => loadFindingsForSessions(sdk.request, key ? key.split("\0") : []),
  )

  // Extract topology data from all sessions (including descendant subagents)
  const topologySource = createTopologySnapshotSource()
  const topologyEntries = createMemo(() => {
    const entries: SessionTopologyEntry[] = []
    const sessionList = sessions()
    const findingsBySession = reconciledFindings()

    for (const session of sessionList) {
      const familyIds = collectSessionFamilyIds(sync.data.session, session.id)
      const messages: { id: string }[] = []
      for (const sid of familyIds) {
        messages.push(...(sync.data.message[sid] ?? []))
      }
      const snapshot = topologySource({
        sessionId: session.id,
        messages,
        partStore: sync.data.part as Record<string, unknown[] | undefined>,
        apiFindings: findingsBySession?.[session.id],
      })
      if (snapshot && (snapshot.devices.length > 0 || snapshot.gateway)) {
        entries.push({
          sessionId: session.id,
          sessionTitle: session.title ?? session.id,
          snapshot,
        })
      }
    }

    // Sort by total hosts descending
    return entries.sort((a, b) => b.snapshot.totalHosts - a.snapshot.totalHosts)
  })

  const filteredEntries = createMemo(() => {
    const q = store.search.trim().toLowerCase()
    if (!q) return topologyEntries()
    return topologyEntries().filter(
      (e) =>
        e.sessionTitle.toLowerCase().includes(q) ||
        e.sessionId.toLowerCase().includes(q) ||
        e.snapshot.devices.some((d) => d.ip.includes(q) || d.hostname?.toLowerCase().includes(q)),
    )
  })

  const selectedEntry = createMemo(() => {
    const id = store.selectedSession
    if (!id) return topologyEntries()[0] ?? null
    return topologyEntries().find((e) => e.sessionId === id) ?? topologyEntries()[0] ?? null
  })

  const totalHosts = createMemo(() =>
    topologyEntries().reduce((sum, e) => sum + e.snapshot.totalHosts, 0),
  )
  const totalSessions = createMemo(() => topologyEntries().length)
  const totalRiskyDevices = createMemo(() =>
    topologyEntries().reduce((sum, e) => sum + countRiskyDevices(e.snapshot), 0),
  )

  return (
    <div class="flex h-full flex-col bg-bg-base text-text-primary">
      <PageHeader
        title={<>{language.t("topology.page.title")}</>}
        description={<>{language.t("topology.page.subtitle", { devices: totalHosts(), sessions: totalSessions() })}</>}
      />

      {/* Stats Bar */}
      <div class="grid grid-cols-3 gap-3 px-6 py-4 shrink-0">
        <div class="flex flex-col gap-0.5 rounded-lg border border-border-weaker-base bg-bg-surface px-4 py-3">
          <span class="text-22 font-semibold tabular-nums text-text-primary">{totalHosts()}</span>
          <span class="text-xs text-text-secondary tracking-wide uppercase">{language.t("topology.page.devices")}</span>
        </div>
        <div class="flex flex-col gap-0.5 rounded-lg border border-border-weaker-base bg-bg-surface px-4 py-3">
          <span class="text-22 font-semibold tabular-nums text-text-primary">{totalSessions()}</span>
          <span class="text-xs text-text-secondary tracking-wide uppercase">{language.t("topology.page.sessionsWithTopology")}</span>
        </div>
        <div class="flex flex-col gap-0.5 rounded-lg border border-border-weaker-base bg-bg-surface px-4 py-3">
          <span class={`text-22 font-semibold tabular-nums ${totalRiskyDevices() > 0 ? "text-severity-fg-critical" : "text-accent"}`}>
            {totalRiskyDevices()}
          </span>
          <span class="text-xs text-text-secondary tracking-wide uppercase">
            {language.t(totalRiskyDevices() === 1 ? "topology.page.vulnerable.one" : "topology.page.vulnerable.other")}
          </span>
        </div>
      </div>

      {/* Main content: session list + canvas */}
      <Show
        when={topologyEntries().length > 0}
        fallback={
          <div class="flex flex-1 flex-col items-center justify-center gap-3 p-8 text-center">
            <div class="flex h-12 w-12 items-center justify-center rounded-lg bg-bg-surface border border-border-weaker-base text-text-secondary mb-1">
              <Icon name="server" class="w-6 h-6 text-text-secondary" />
            </div>
            <div class="text-sm font-medium text-text-primary">
              {language.t("topology.page.empty.title")}
            </div>
            <div class="text-xs text-text-secondary max-w-100 leading-relaxed">
              {language.t("topology.page.empty.body")}{" "}
              {language.t("topology.page.empty.hintPrefix")} (<span class="font-mono text-text-primary">/auditoria-red</span>){" "}
              {language.t("topology.page.empty.hintSuffix")}
            </div>
          </div>
        }
      >
        <div class="flex flex-1 min-h-0">
          {/* Session list sidebar */}
          <div class="w-70 shrink-0 border-r border-border-weaker-base flex flex-col">
            {/* Search */}
            <div class="p-3 border-b border-border-weaker-base">
              <div class="relative">
                <Icon name="magnifying-glass" class="absolute left-2.5 top-1/2 -translate-y-1/2 text-text-secondary pointer-events-none size-3.5" />
                <input
                  id="topology-session-search"
                  name="topology-session-search"
                  type="search"
                  value={store.search}
                  onInput={(e) => setStore("search", (e.target as HTMLInputElement).value)}
                  placeholder={language.t("topology.page.searchPlaceholder")}
                  class="w-full h-8 rounded-md border border-border-weaker-base bg-bg-surface pl-8 pr-2 text-xs text-text-primary placeholder:text-text-secondary outline-none focus:border-border-strong transition-colors"
                  aria-label={language.t("topology.page.searchAriaLabel")}
                />
              </div>
            </div>

            {/* Session list */}
            <div class="flex-1 overflow-y-auto">
              <For each={filteredEntries()}>
                {(entry) => {
                  const isSelected = selectedEntry()?.sessionId === entry.sessionId
                  const riskyCount = countRiskyDevices(entry.snapshot)
                  return (
                    <button
                      type="button"
                      onClick={() => setStore("selectedSession", entry.sessionId)}
                      class={`w-full text-left px-3 py-2.5 border-b border-border-weaker-base transition-colors hover:bg-bg-surface ${
                        isSelected ? "bg-bg-elevated" : ""
                      }`}
                      aria-current={isSelected ? "true" : undefined}
                    >
                      <div class="flex items-center justify-between gap-2">
                        <span class="text-sm font-medium text-text-primary truncate flex-1">
                          {entry.sessionTitle}
                        </span>
                        <Show when={riskyCount > 0}>
                          <span
                            class="size-2 rounded-full bg-severity-bg-critical shrink-0"
                            title={language.t(riskyCount === 1 ? "topology.page.riskyCount.one" : "topology.page.riskyCount.other", { count: riskyCount })}
                          />
                        </Show>
                      </div>
                      <div class="flex items-center gap-2 mt-0.5">
                        <span class="text-xs text-text-secondary font-mono tabular-nums">
                          {language.t(entry.snapshot.totalHosts === 1 ? "topology.page.hosts.one" : "topology.page.hosts.other", { count: entry.snapshot.totalHosts })}
                        </span>
                        <span class="text-text-secondary">·</span>
                        <span class="text-xs text-text-secondary font-mono tabular-nums">
                          {language.t("topology.page.devicesShort", { count: entry.snapshot.devices.length })}
                        </span>
                        <A
                          href={`/${targetDir()}/session/${entry.sessionId}`}
                          class="ml-auto text-xs text-text-secondary hover:text-text-primary shrink-0"
                          onClick={(e) => e.stopPropagation()}
                          aria-label={language.t("topology.page.goToSession")}
                        >
                          <Icon name="chevron-right" size="small" class="size-3" />
                        </A>
                      </div>
                    </button>
                  )
                }}
              </For>
            </div>
          </div>

          {/* Canvas area */}
          <div class="flex-1 flex flex-col">
            <Show when={selectedEntry()} keyed>
              {(entry) => (
                <div class="flex-1 relative bg-bg-base">
                  <TopologyCanvas
                    devices={entry.snapshot.devices}
                    gateway={entry.snapshot.gateway}
                    riskyPorts={DEFAULT_RISKY_PORTS}
                  />
                </div>
              )}
            </Show>
          </div>
        </div>
      </Show>
    </div>
  )
}

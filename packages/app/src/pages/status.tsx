import { createMemo, For, Show, type JSX } from "solid-js"
import { Icon } from "@argos/ui/icon"
import { useGlobal } from "@/context/global"
import { useServer, ServerConnection } from "@/context/server"
import { useSync } from "@/context/sync"
import { useLanguage } from "@/context/language"
import { ServerHealthIndicator } from "@/components/server/server-row"
import { PageHeader } from "@/components/audit-ui"
import { OpsCard } from "@/pages/shared/ops-shell"

// ── Sub-components ───────────────────────────────────────────────────────────

function StatusCard(props: {
  label: string
  status: "healthy" | "warning" | "critical" | "offline" | "unknown"
  icon: string
  children?: JSX.Element
}) {
  const language = useLanguage()
  const dotClass = () => {
    const map: Record<string, string> = {
      healthy: "bg-accent",
      warning: "bg-severity-bg-high",
      critical: "bg-severity-bg-critical",
      offline: "bg-bg-elevated",
      unknown: "bg-bg-elevated",
    }
    return map[props.status] ?? map.unknown
  }

  const labelText = () => {
    const map: Record<string, string> = {
      healthy: language.t("status.card.healthy") ?? "Saludable",
      warning: language.t("status.card.warning") ?? "Advertencia",
      critical: language.t("status.card.critical") ?? "Crítico",
      offline: language.t("status.card.offline") ?? "Sin conexión",
      unknown: language.t("status.card.unknown") ?? "Desconocido",
    }
    return map[props.status] ?? map.unknown
  }

  return (
    <OpsCard
      class="overflow-hidden"
      headerClass="flex items-center justify-between px-4 py-3 border-b border-border-weaker-base"
      contentClass="p-2"
      title={
        <div class="flex items-center gap-2.5">
          <div class="flex h-7 w-7 items-center justify-center rounded bg-bg-elevated text-text-secondary">
            <Icon name={props.icon} size="small" />
          </div>
          <span class="text-sm font-medium text-text-primary">{props.label}</span>
        </div>
      }
      trailing={
        <div class="flex items-center gap-1.5 font-mono">
          <span class={`size-1.5 rounded-full ${dotClass()}`} />
          <span class="text-xs text-text-secondary">{labelText()}</span>
        </div>
      }
    >
      {props.children}
    </OpsCard>
  )
}

function HealthDot(props: { healthy?: boolean; status?: string }) {
  const dotClass = () => {
    if (props.healthy === true) return "bg-accent"
    if (props.healthy === false) return "bg-severity-bg-critical"
    const status = props.status
    if (status === "connected") return "bg-accent"
    if (status === "failed" || status === "needs_client_registration") return "bg-severity-bg-critical"
    if (status === "needs_auth") return "bg-severity-bg-high"
    return "bg-bg-elevated"
  }
  return <span class={`size-1.5 rounded-full shrink-0 ${dotClass()}`} />
}

function SectionTitle(props: { label: string; count?: number }) {
  return (
    <div class="flex items-center gap-2 px-3 py-1.5">
      <span class="text-xs font-medium uppercase tracking-wide text-text-secondary">
        {props.label}
      </span>
      <Show when={props.count !== undefined}>
        <span class="text-xs font-mono text-text-secondary tabular-nums">({props.count})</span>
      </Show>
    </div>
  )
}

function EmptyRow(props: { label: string }) {
  return (
    <div class="px-3 py-4 text-center text-xs text-text-secondary font-mono">
      {props.label}
    </div>
  )
}

// ── Main Page ────────────────────────────────────────────────────────────────

export default function StatusPage() {
  const global = useGlobal()
  const server = useServer()
  const sync = useSync()
  const language = useLanguage()

  // ── Server Health ──
  const sortedServers = createMemo(() => {
    const list = global.servers.list()
    const activeKey = server.key
    return list.slice().sort((a, b) => {
      if (ServerConnection.key(a) === activeKey) return -1
      if (ServerConnection.key(b) === activeKey) return 1
      const ha = global.servers.health[ServerConnection.key(a)]?.healthy
      const hb = global.servers.health[ServerConnection.key(b)]?.healthy
      if (ha === hb) return 0
      if (ha === true) return -1
      if (hb === true) return 1
      return 0
    })
  })

  const serverStatus = createMemo<"healthy" | "warning" | "critical" | "offline">(() => {
    const list = global.servers.list()
    if (list.length === 0) return "offline"
    const anyHealthy = list.some((c) => global.servers.health[ServerConnection.key(c)]?.healthy === true)
    const anyFailed = list.some((c) => global.servers.health[ServerConnection.key(c)]?.healthy === false)
    if (anyHealthy && !anyFailed) return "healthy"
    if (anyHealthy) return "warning"
    if (anyFailed) return "critical"
    return "offline"
  })

  // ── MCP Status ──
  const mcpEntries = createMemo(() => {
    const mcp = sync.data.mcp ?? {}
    return Object.entries(mcp)
      .map(([name, status]) => ({ name, ...status }))
      .sort((a, b) => a.name.localeCompare(b.name))
  })

  const mcpStatus = createMemo<"healthy" | "warning" | "critical" | "offline">(() => {
    const entries = mcpEntries()
    if (entries.length === 0) return "offline"
    const allConnected = entries.every((e) => e.status === "connected")
    const anyFailed = entries.some((e) => e.status === "failed" || e.status === "needs_client_registration")
    if (allConnected) return "healthy"
    if (anyFailed) return "critical"
    return "warning"
  })

  const mcpConnected = createMemo(() => mcpEntries().filter((e) => e.status === "connected").length)

  // ── Session Status ──
  const sessionStatuses = createMemo(() => {
    const statuses: Array<{ id: string; type: string }> = []
    for (const [id, s] of Object.entries(sync.data.session_status ?? {})) {
      statuses.push({ id, type: s?.type ?? "idle" })
    }
    return statuses
  })

  const activeSessions = createMemo(() => sessionStatuses().filter((s) => s.type !== "idle"))
  const idleSessions = createMemo(() => sessionStatuses().filter((s) => s.type === "idle"))
  const totalSessions = createMemo(() => sync.data.session.length)

  const sessionStatusOverall = createMemo<"healthy" | "warning" | "critical" | "offline">(() => {
    const active = activeSessions().length
    if (active === 0) return "healthy"
    if (active <= 3) return "warning"
    return "critical"
  })

  // ── LSP Status ──
  const lspItems = createMemo(() => sync.data.lsp ?? [])

  const lspStatus = createMemo<"healthy" | "warning" | "critical" | "offline">(() => {
    if (lspItems().length === 0) return "offline"
    const anyError = lspItems().some((l) => l.status === "error")
    if (anyError) return "warning"
    return "healthy"
  })

  // ── VCS Status ──
  const vcs = createMemo(() => sync.data.vcs)
  const vcsAvailable = createMemo(() => !!vcs())
  const currentBranch = createMemo(() => vcs()?.branch)

  // ── Overall System Status ──
  const overallStatus = createMemo<"healthy" | "warning" | "critical" | "offline" | "unknown">(() => {
    const statuses = [serverStatus(), mcpStatus(), sessionStatusOverall(), lspStatus()]
    if (statuses.some((s) => s === "critical")) return "critical"
    if (statuses.some((s) => s === "warning")) return "warning"
    if (statuses.some((s) => s === "offline")) return "offline"
    if (statuses.every((s) => s === "healthy")) return "healthy"
    return "unknown"
  })

  return (
    <div class="flex h-full flex-col bg-bg-base text-text-primary">
      <PageHeader
        title={
          <span class="inline-flex items-center gap-3">
            <span>{language.t("status.title")}</span>
            <span class={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium border ${
              overallStatus() === "healthy" ? "border-border-default text-accent bg-bg-surface" :
              overallStatus() === "warning" ? "border-border-default text-severity-fg-high bg-severity-bg-high" :
              overallStatus() === "critical" ? "border-border-strong text-severity-fg-critical bg-severity-bg-critical" :
              "border-border-default text-text-secondary bg-bg-surface"
            }`}>
              <span class={`size-1.5 rounded-full ${
                overallStatus() === "healthy" ? "bg-accent" :
                overallStatus() === "warning" ? "bg-severity-fg-high" :
                overallStatus() === "critical" ? "bg-severity-fg-critical" :
                "bg-bg-elevated"
              }`} />
              {overallStatus() === "healthy" ? language.t("status.overall.healthy") :
               overallStatus() === "warning" ? language.t("status.overall.warning") :
               overallStatus() === "critical" ? language.t("status.overall.critical") :
               overallStatus() === "offline" ? language.t("status.overall.offline") : language.t("status.overall.unknown")}
            </span>
          </span>
        }
        description={<>{language.t("status.subtitle")}</>}
      />

      <div class="flex-1 overflow-y-auto px-6 pb-10">
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-4 max-w-300 pt-6">

          {/* ── Server Health ── */}
          <StatusCard label={language.t("status.servers.title") ?? "Servidores"} status={serverStatus()} icon="server">
            <Show
              when={sortedServers().length > 0}
              fallback={<EmptyRow label={language.t("status.servers.none") ?? "No hay servidores configurados"} />}
            >
              <For each={sortedServers()}>
                {(conn) => {
                  const key = ServerConnection.key(conn)
                  const health = () => global.servers.health[key]
                  const isActive = key === server.key
                  return (
                    <div class="flex items-center gap-3 rounded-sm px-3 py-2 hover:bg-bg-elevated transition-colors">
                      <ServerHealthIndicator health={health()} />
                      <div class="flex-1 min-w-0">
                        <div class="flex items-center gap-2">
                          <span class="text-sm font-medium text-text-primary truncate">
                            {conn.displayName ?? new URL(conn.http.url).host}
                          </span>
                          <Show when={isActive}>
                            <span class="text-xs font-mono px-1.5 py-0.5 rounded bg-bg-elevated border border-border-weaker-base text-text-primary">
                              {language.t("status.server.active")}
                            </span>
                          </Show>
                        </div>
                        <div class="flex items-center gap-2 mt-0.5">
                          <span class="text-xs text-text-secondary font-mono truncate">{conn.http.url}</span>
                          <Show when={health()?.version}>
                            <span class="text-xs text-text-secondary font-mono">
                              v{health()!.version}
                            </span>
                          </Show>
                        </div>
                      </div>
                    </div>
                  )
                }}
              </For>
            </Show>
          </StatusCard>

          {/* ── MCP Status ── */}
          <StatusCard
            label={`MCP (${mcpConnected()}/${mcpEntries().length})`}
            status={mcpStatus()}
            icon="plugin"
          >
            <Show
              when={mcpEntries().length > 0}
              fallback={<EmptyRow label={language.t("status.mcp.none") ?? "No hay MCPs configurados"} />}
            >
              <For each={mcpEntries()}>
                {(entry) => {
                  const statusText = () => {
                    const map: Record<string, string> = {
                      connected: language.t("status.mcp.connected") ?? "Conectado",
                      failed: language.t("status.mcp.failed") ?? "Falló",
                      needs_auth: language.t("status.mcp.needs_auth") ?? "Requiere autenticación",
                      needs_client_registration: language.t("status.mcp.needs_client_registration") ?? "Requiere registro",
                      disabled: language.t("status.mcp.disabled") ?? "Deshabilitado",
                    }
                    return map[entry.status] ?? entry.status
                  }
                  return (
                    <div class="flex items-center gap-3 rounded-sm px-3 py-2 hover:bg-bg-elevated transition-colors">
                      <HealthDot status={entry.status} />
                      <div class="flex-1 min-w-0">
                        <span class="text-sm font-mono text-text-primary truncate block">
                          {entry.name}
                        </span>
                      </div>
                      <span class={`text-xs font-mono ${
                        entry.status === "connected" ? "text-accent" :
                        entry.status === "failed" ? "text-severity-fg-critical" :
                        entry.status === "needs_auth" ? "text-severity-fg-high" :
                        "text-text-secondary"
                      }`}>
                        {statusText()}
                      </span>
                    </div>
                  )
                }}
              </For>
            </Show>
          </StatusCard>

          {/* ── Session Status ── */}
          <StatusCard
            label={language.t("status.sessions.title", { count: totalSessions() })}
            status={sessionStatusOverall()}
            icon="console"
          >
            <div class="grid grid-cols-2 gap-2 px-3 py-2">
              <div class="flex flex-col gap-1 rounded-sm bg-bg-elevated border border-border-weaker-base px-3 py-2.5">
                <span class="text-xl font-semibold tabular-nums text-text-primary">{activeSessions().length}</span>
                <span class="text-xs text-text-secondary">{language.t("status.sessions.active")}</span>
              </div>
              <div class="flex flex-col gap-1 rounded-sm bg-bg-elevated border border-border-weaker-base px-3 py-2.5">
                <span class="text-xl font-semibold tabular-nums text-text-primary">{idleSessions().length}</span>
                <span class="text-xs text-text-secondary">{language.t("status.sessions.idle")}</span>
              </div>
            </div>
            <Show when={activeSessions().length > 0}>
              <SectionTitle label={language.t("status.sessions.activeSection")} count={activeSessions().length} />
              <For each={activeSessions().slice(0, 8)}>
                {(s) => (
                  <div class="flex items-center gap-2 px-3 py-1.5">
                    <span class="size-1.5 rounded-full bg-accent animate-pulse" />
                    <span class="text-xs font-mono text-text-secondary truncate">{s.id.slice(0, 12)}…</span>
                    <span class="text-xs text-text-secondary font-mono ml-auto">{s.type}</span>
                  </div>
                )}
              </For>
            </Show>
          </StatusCard>

          {/* ── LSP + VCS Status ── */}
          <StatusCard label={language.t("status.services.title")} status={lspStatus()} icon="plugin">
            {/* VCS */}
            <SectionTitle label={language.t("status.vcs.title")} />
            <Show
              when={vcsAvailable()}
              fallback={
                <div class="px-3 py-2">
                  <span class="text-xs text-text-secondary">{language.t("status.vcs.notDetected")}</span>
                </div>
              }
            >
              <div class="flex items-center gap-3 px-3 py-2">
                <HealthDot healthy={vcsAvailable()} />
                <div class="flex-1 min-w-0">
                  <span class="text-sm font-mono text-text-primary">Git</span>
                </div>
                <Show when={currentBranch()}>
                  <span class="text-xs font-mono text-text-secondary bg-bg-elevated border border-border-weaker-base px-2 py-0.5 rounded">
                    {currentBranch()}
                  </span>
                </Show>
              </div>
            </Show>

            {/* LSP */}
            <SectionTitle label={language.t("status.lsp.title")} count={lspItems().length} />
            <Show
              when={lspItems().length > 0}
              fallback={<div class="px-3 py-2"><span class="text-xs text-text-secondary">{language.t("status.lsp.none")}</span></div>}
            >
              <For each={lspItems()}>
                {(item) => (
                  <div class="flex items-center gap-3 px-3 py-2">
                    <HealthDot healthy={item.status === "connected"} />
                    <div class="flex-1 min-w-0">
                      <span class="text-sm font-mono text-text-primary truncate block">
                        {item.name || item.id}
                      </span>
                    </div>
                    <span class={`text-xs font-mono ${
                      item.status === "connected" ? "text-accent" : "text-severity-fg-critical"
                    }`}>
                      {item.status === "connected" ? (language.t("status.lsp.connected") ?? "Conectado") : (language.t("status.lsp.error") ?? "Error")}
                    </span>
                  </div>
                )}
              </For>
            </Show>
          </StatusCard>
        </div>
      </div>
    </div>
  )
}


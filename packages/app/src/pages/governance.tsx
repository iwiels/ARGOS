import { createMemo, createResource, For, Show } from "solid-js"
import { createStore } from "solid-js/store"
import { Icon } from "@argos/ui/icon"
import { PixelIcon } from "@argos/ui/pixel-icon"
import { useSDK } from "@/context/sdk"
import { useLanguage } from "@/context/language"
import { getRelativeTimeFromMs } from "@/utils/time"
import { PageHeader, KpiCard, EmptyState } from "@/components/audit-ui"
import { OpsCard, OpsErrorPanel, OpsRefreshButton, useAutoRefresh } from "@/pages/shared/ops-shell"
import {
  loadAuditEntries,
  loadGovernanceSummary,
  verifyAuditChain,
  type AgentSummary,
  type AuditEntry,
  type AuditIntegrity,
  type GovernanceSummary,
} from "@/components/session/governance-api"
import { agentLabelKey, agentColor, eventLabelKey, eventColor } from "@/components/session/governance-data"

function IntegrityCard(props: {
  integrity?: GovernanceSummary["integrity"]
  onVerify: () => void
  verifying: boolean
}) {
  const language = useLanguage()
  const verified = () => props.integrity?.verified === true
  const valid = () => props.integrity?.valid === true
  const total = () => props.integrity?.total ?? 0
  const pending = () => !props.integrity || !verified()
  const tone = () => (pending() ? "neutral" : valid() ? "ok" : "bad")
  return (
    <div
      class={`flex flex-col gap-3 rounded-[4px] border bg-bg-surface p-4 shadow-xs ${
        tone() === "bad" ? "border-severity-border-critical" : "border-border-weaker-base"
      }`}
    >
      <div class="flex items-center justify-between gap-3">
        <div class="flex items-center gap-2.5">
          <div
            class={`flex size-10 items-center justify-center rounded-[4px] border border-border-weaker-base ${
              tone() === "bad"
                ? "bg-severity-bg-critical text-severity-fg-critical"
                : tone() === "ok"
                  ? "bg-severity-bg-low text-severity-fg-low"
                  : "bg-bg-elevated text-text-secondary"
            }`}
          >
            <PixelIcon name="shield-check" size={24} />
          </div>
          <div>
            <div class="text-sm font-semibold text-text-primary">{language.t("governance.integrity.title")}</div>
            <div class="mt-0.5 text-xs text-text-tertiary">{language.t("governance.integrity.subtitle")}</div>
          </div>
        </div>
        <OpsRefreshButton
          label={language.t("governance.integrity.verify")}
          onClick={props.onVerify}
          disabled={props.verifying}
          class="inline-flex shrink-0 items-center gap-1.5 rounded-[4px] border border-border-weaker-base bg-bg-elevated px-2.5 py-1.5 text-xs font-medium text-text-primary transition-colors hover:bg-bg-elevated disabled:opacity-60 cursor-pointer"
          iconClass={props.verifying ? "animate-spin" : ""}
        />
      </div>
      <div class="flex items-center gap-2">
        <span
          class={`inline-flex items-center gap-1.5 rounded-[3px] border px-2 py-0.5 text-xs font-semibold ${
            tone() === "bad"
              ? "border-severity-border-critical bg-severity-bg-critical text-severity-fg-critical"
              : tone() === "ok"
                ? "border-severity-border-low bg-severity-bg-low text-severity-fg-low"
                : "border-border-weaker-base bg-bg-elevated text-text-secondary"
          }`}
        >
          <span
            class={`size-1.5 rounded-full ${
              tone() === "bad" ? "bg-severity-fg-critical" : tone() === "ok" ? "bg-severity-fg-low" : "bg-text-tertiary"
            }`}
          />
          {pending()
            ? language.t("governance.integrity.status.pending")
            : valid()
              ? language.t("governance.integrity.status.valid")
              : language.t("governance.integrity.status.invalid")}
        </span>
        <span class="font-mono text-xs tabular-nums text-text-secondary">
          {language.t("governance.integrity.entries", { count: total() })}
        </span>
        <Show when={!pending() && props.integrity?.firstInvalidSeq !== undefined}>
          <span class="font-mono text-xs text-severity-fg-critical">
            {language.t("governance.integrity.entry", { seq: props.integrity?.firstInvalidSeq ?? 0 })}
          </span>
        </Show>
        <Show when={pending()}>
          <span class="text-xs text-text-tertiary">{language.t("governance.integrity.hint")}</span>
        </Show>
      </div>
    </div>
  )
}

function AgentCard(props: { agent: AgentSummary }) {
  const language = useLanguage()
  const color = () => agentColor(props.agent.agent)
  const labelKey = () => agentLabelKey(props.agent.agent)
  const agentLabel = () => (labelKey() ? language.t(labelKey()!) : props.agent.agent)
  const successRate = () =>
    props.agent.completed + props.agent.errors > 0
      ? Math.round((props.agent.completed / (props.agent.completed + props.agent.errors)) * 100)
      : 100
  const topTool = () => props.agent.topTools[0]
  const maxTool = () => Math.max(...props.agent.topTools.map((tool) => tool.count), 1)

  return (
    <div class="flex flex-col gap-3 rounded-[4px] border border-border-weaker-base bg-bg-surface p-4 shadow-xs">
      <div class="flex items-center justify-between gap-2">
        <div class="flex items-center gap-2.5">
          <div class="flex size-9 items-center justify-center rounded-[4px] bg-bg-elevated" style={{ color: color() }}>
            <Icon name="terminal" size="small" />
          </div>
          <div>
            <div class="text-sm font-semibold text-text-primary">{agentLabel()}</div>
            <Show when={agentLabel() !== props.agent.agent}>
              <div class="font-mono text-[11px] text-text-tertiary">{props.agent.agent}</div>
            </Show>
          </div>
        </div>
        <span class="rounded-[3px] border border-border-weaker-base bg-bg-elevated px-2 py-0.5 font-mono text-[11px] tabular-nums text-text-secondary">
          {language.t("governance.agent.actions", { count: props.agent.total })}
        </span>
      </div>

      <div class="grid grid-cols-2 gap-2">
        <div class="flex flex-col gap-0.5 rounded-[4px] border border-border-weaker-base bg-bg-elevated px-2.5 py-2">
          <span class="text-[10px] font-medium uppercase tracking-wide text-text-tertiary">{language.t("governance.agent.successRate")}</span>
          <span class="text-base font-semibold tabular-nums text-text-primary">{successRate()}%</span>
          <span class="font-mono text-[10px] text-text-tertiary">
            {language.t("governance.agent.okErr", { ok: props.agent.completed, err: props.agent.errors })}
          </span>
        </div>
        <div class="flex flex-col gap-0.5 rounded-[4px] border border-border-weaker-base bg-bg-elevated px-2.5 py-2">
          <span class="text-[10px] font-medium uppercase tracking-wide text-text-tertiary">{language.t("governance.agent.topTool")}</span>
          <span class="truncate font-mono text-[13px] font-medium text-text-primary">{topTool()?.tool ?? "—"}</span>
          <span class="font-mono text-[10px] text-text-tertiary">
            {language.t("governance.agent.runs", { count: topTool()?.count ?? 0 })}
          </span>
        </div>
      </div>

      <Show when={props.agent.topTools.length > 1}>
        <div class="flex flex-col gap-1">
          <For each={props.agent.topTools.slice(1, 5)}>
            {(tool) => (
              <div class="flex items-center gap-2">
                <span class="w-0 flex-1 truncate font-mono text-[11px] text-text-secondary">{tool.tool}</span>
                <div class="h-1.5 w-20 overflow-hidden rounded-full bg-bg-elevated">
                  <div class="h-full rounded-full" style={{ width: `${(tool.count / maxTool()) * 100}%`, "background-color": color() }} />
                </div>
                <span class="w-6 text-right font-mono text-[10px] tabular-nums text-text-tertiary">{tool.count}</span>
              </div>
            )}
          </For>
        </div>
      </Show>
    </div>
  )
}

function AuditRow(props: { entry: AuditEntry }) {
  const language = useLanguage()
  const labelKey = () => eventLabelKey(props.entry.event_type)
  const label = () => (labelKey() ? language.t(labelKey()!) : props.entry.event_type)
  const color = () => eventColor(props.entry.event_type)
  return (
    <div class="flex items-start gap-2.5 rounded-[4px] border border-border-weaker-base bg-bg-surface px-3 py-2 shadow-xs">
      <div class="mt-0.5 flex size-6 shrink-0 items-center justify-center rounded-[4px] bg-bg-elevated text-text-secondary">
        <Icon
          name={props.entry.event_type === "tool.executed" ? "code-lines" : props.entry.event_type === "tool.error" ? "ban" : "terminal"}
          size="small"
        />
      </div>
      <div class="min-w-0 flex-1">
        <div class="flex items-center gap-2">
          <span class={`shrink-0 font-mono text-[11px] font-medium ${color()}`}>{label()}</span>
          <span class="shrink-0 rounded bg-bg-elevated px-1 py-px font-mono text-[10px] text-text-tertiary">
            seq {props.entry.seq}
          </span>
          <span class="ml-auto shrink-0 text-[11px] text-text-tertiary">{getRelativeTimeFromMs(props.entry.time_created, language.t)}</span>
        </div>
        <div class="mt-0.5 min-w-0">
          <span class="text-13-medium text-text-primary">{props.entry.summary}</span>
          <Show when={props.entry.agent}>
            <span class="ml-1.5 rounded bg-bg-elevated px-1 py-px font-mono text-[10px] text-accent">
              {props.entry.agent}
            </span>
          </Show>
        </div>
        <Show when={props.entry.target}>
          <div class="mt-0.5 truncate font-mono text-[11px] text-text-tertiary">{props.entry.target}</div>
        </Show>
      </div>
    </div>
  )
}

export default function GovernancePage() {
  const sdk = useSDK()
  const language = useLanguage()
  const [state, setState] = createStore({
    version: 0,
    verifying: false,
    verifiedAt: undefined as number | undefined,
    verifiedIntegrity: undefined as AuditIntegrity | undefined,
    agentFilter: "",
    loadError: false,
  })

  const [summary] = createResource(
    () => state.version,
    async () => {
      try {
        return await loadGovernanceSummary(sdk.request)
      } catch {
        setState("loadError", true)
        return undefined
      }
    },
  )
  const [entries] = createResource(
    () => state.version,
    async () => {
      try {
        return await loadAuditEntries(sdk.request, 60)
      } catch {
        setState("loadError", true)
        return undefined
      }
    },
  )

  useAutoRefresh(() => setState("version", (v: number) => v + 1))

  const verify = async () => {
    setState("verifying", true)
    try {
      const result = await verifyAuditChain(sdk.request)
      if (result) {
        setState("verifiedIntegrity", result)
        setState("verifiedAt", Date.now())
      }
    } catch {
      setState("loadError", true)
    } finally {
      setState("verifying", false)
    }
  }

  const agents = createMemo(() => (summary()?.agents ?? []).filter((agent) => agent.total > 0))
  const filteredEntries = createMemo(() => {
    const filter = state.agentFilter
    if (!filter) return entries() ?? []
    return (entries() ?? []).filter((entry) => entry.agent === filter)
  })

  const hasData = createMemo(() => (summary()?.activity.total ?? 0) > 0)
  const integrity = createMemo(() => state.verifiedIntegrity ?? summary()?.integrity)

  return (
    <div class="flex h-full flex-col bg-bg-base text-text-primary">
      <PageHeader
        title={language.t("governance.title")}
        description={language.t("governance.description")}
        actions={
          <OpsRefreshButton
            label={language.t("governance.refresh")}
            onClick={() => setState("version", (v: number) => v + 1)}
          />
        }
      />

      <Show
        when={hasData()}
        fallback={
          <Show
            when={!state.loadError}
            fallback={
              <OpsErrorPanel
                title={language.t("governance.error.title")}
                body={language.t("governance.error.body")}
                retryLabel={language.t("governance.retry")}
                onRetry={() => {
                  setState("loadError", false)
                  setState("version", (v: number) => v + 1)
                }}
              />
            }
          >
            <EmptyState
              icon={<PixelIcon name="shield-check" size={40} class="text-text-tertiary" />}
              title={language.t("governance.empty.title")}
              description={language.t("governance.empty.body")}
            />
          </Show>
        }
      >
        <div class="flex-1 overflow-y-auto px-6 pb-10">
          <div class="mx-auto flex max-w-240 flex-col gap-6 pt-6">
            {/* Integrity */}
            <IntegrityCard integrity={integrity()} onVerify={verify} verifying={state.verifying} />
            <Show when={state.verifiedAt}>
              <div class="-mt-4 text-xs text-text-tertiary">
                {language.t("governance.verifiedAt", { time: getRelativeTimeFromMs(state.verifiedAt, language.t) })}
              </div>
            </Show>

            {/* KPI row */}
            <div class="grid grid-cols-2 gap-3">
              <KpiCard label={language.t("governance.auditedActions")} value={summary()?.activity.total ?? 0} icon="checklist" />
              <KpiCard
                label={language.t("governance.activeAgents")}
                value={agents().length}
                icon="server"
                accent="var(--accent)"
              />
            </div>

            {/* Agents */}
            <div>
              <div class="mb-2 flex items-center justify-between">
                <h2 class="text-sm font-semibold text-text-primary">{language.t("governance.byAgent")}</h2>
                <span class="text-xs text-text-tertiary">{language.t("governance.byAgent.subtitle")}</span>
              </div>
              <div class="grid grid-cols-1 gap-3 lg:grid-cols-2 xl:grid-cols-4">
                <For each={agents()}>{(agent) => <AgentCard agent={agent} />}</For>
              </div>
            </div>

            {/* Audit feed */}
            <OpsCard
              headerClass="flex items-center justify-between gap-3 border-b border-border-weaker-base px-4 py-3"
              contentClass="flex max-h-96 flex-col gap-1.5 overflow-y-auto p-2.5"
              title={
                <div class="flex items-center gap-2">
                  <span class="text-sm font-semibold text-text-primary">{language.t("governance.feed.title")}</span>
                  <span class="text-xs text-text-tertiary">{language.t("governance.feed.subtitle")}</span>
                </div>
              }
              trailing={
                <select
                  value={state.agentFilter}
                  onChange={(event) => setState("agentFilter", (event.target as HTMLSelectElement).value)}
                  class="rounded-md border border-border-weaker-base bg-bg-elevated px-2 py-1 text-xs text-text-primary outline-none"
                  aria-label={language.t("governance.filter.aria")}
                >
                  <option value="">{language.t("governance.filter.all")}</option>
                  <For each={agents()}>
                    {(agent) => {
                      const key = agentLabelKey(agent.agent)
                      return <option value={agent.agent}>{key ? language.t(key) : agent.agent}</option>
                    }}
                  </For>
                </select>
              }
            >
              <Show
                when={filteredEntries().length > 0}
                fallback={
                  <div class="flex flex-col items-center gap-2 py-8 text-center">
                    <Icon name="checklist" class="h-6 w-6 text-text-tertiary" />
                    <div class="text-xs text-text-secondary">{language.t("governance.feed.empty")}</div>
                  </div>
                }
              >
                <For each={filteredEntries()}>{(entry) => <AuditRow entry={entry} />}</For>
              </Show>
            </OpsCard>

            <p class="text-[11px] leading-relaxed text-text-tertiary">{language.t("governance.footer")}</p>
          </div>
        </div>
      </Show>
    </div>
  )
}

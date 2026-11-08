import { createMemo, createResource, createSignal, For, Show } from "solid-js"
import { Icon } from "@argos/ui/icon"
import { useSDK } from "@/context/sdk"
import { useLanguage } from "@/context/language"
import { getRelativeTimeFromMs } from "@/utils/time"
import { PageHeader, KpiCard, EmptyState } from "@/components/audit-ui"
import { loadComplianceDrift, loadComplianceSummary, type ComplianceDriftEvent, type ComplianceSummary } from "@/components/session/ccm-api"
import { frameworkLabel } from "@/components/session/compliance-panel"
import { STATUS_META, STATUS_ORDER, statusLabelKey, statusMeta, driftWorsened } from "@/components/session/ccm-data"
import { OpsCard, OpsErrorPanel, OpsRefreshButton, useAutoRefresh } from "@/pages/shared/ops-shell"

/** Rampa de la confianza de la derivación (no de la severidad del hallazgo). */
const CONFIDENCE_CHIP: Record<string, string> = {
  high: "bg-severity-bg-low text-severity-fg-low border-severity-border-low",
  medium: "bg-severity-bg-medium text-severity-fg-medium border-severity-border-medium",
  low: "bg-severity-bg-critical text-severity-fg-critical border-severity-border-critical",
}

const CONFIDENCE_LABEL_KEYS: Record<string, string> = {
  high: "compliance.confidence.high",
  medium: "compliance.confidence.medium",
  low: "compliance.confidence.low",
}

function ScoreRing(props: { score: number }) {
  const color = () => {
    if (props.score >= 80) return "var(--severity-fg-low)"
    if (props.score >= 50) return "var(--severity-fg-medium)"
    return "var(--severity-fg-critical)"
  }
  const pct = () => Math.min(100, Math.max(0, props.score))
  return (
    <div class="relative flex h-16 w-16 shrink-0 items-center justify-center">
      <div
        class="absolute inset-0 rounded-full transition-all duration-700 ease-out"
        style={{ background: `conic-gradient(${color()} ${pct()}%, var(--bg-elevated) 0)` }}
        aria-hidden="true"
      />
      <div class="absolute inset-[6px] rounded-full bg-bg-surface" aria-hidden="true" />
      <span class="relative text-sm font-semibold tabular-nums text-text-primary">{props.score}%</span>
    </div>
  )
}

function FrameworkCard(props: { framework: ComplianceSummary["frameworks"][number] }) {
  const language = useLanguage()
  const total = () => props.framework.totalControls || 1
  const confidence = () => props.framework.confidence ?? "high"
  // La confianza se muestra solo cuando hay una derivación detrás del estado
  // del framework: sin hallazgos mapeados no hay nada que auditar.
  const audited = () => props.framework.counts.deficient + props.framework.counts.partial > 0
  return (
    <div class="flex flex-col gap-3 rounded-[4px] border border-border-weaker-base bg-bg-surface p-4 shadow-xs">
      <div class="flex items-center justify-between gap-3">
        <div class="min-w-0">
          <div class="text-sm font-semibold text-text-primary">
            {frameworkLabel(props.framework.framework, props.framework.title, language.t)}
          </div>
          <div class="mt-0.5 text-xs text-text-tertiary">
            {props.framework.version} · {language.t("ccm.framework.controls", { count: props.framework.totalControls })}
          </div>
        </div>
        <ScoreRing score={props.framework.score} />
      </div>

      <div class="flex h-2 w-full gap-0.5 overflow-hidden rounded-sm bg-bg-elevated">
        <For each={STATUS_ORDER}>
          {(status) => {
            const count = props.framework.counts[status]
            const pct = (count / total()) * 100
            return (
              <Show when={count > 0}>
                <div
                  class="h-full transition-all duration-300"
                  style={{ width: `${pct}%`, "background-color": STATUS_META[status].bar }}
                  title={`${language.t(statusLabelKey(status))}: ${count}`}
                />
              </Show>
            )
          }}
        </For>
      </div>

      <div class="flex flex-wrap items-center justify-between gap-x-3 gap-y-1">
        <div class="flex flex-wrap gap-x-3 gap-y-1">
          <For each={STATUS_ORDER}>
            {(status) => {
              const count = props.framework.counts[status]
              return (
                <Show when={count > 0}>
                  <span class="inline-flex items-center gap-1.5 text-xs text-text-secondary">
                    <span class="size-2 rounded-full" style={{ "background-color": STATUS_META[status].bar }} />
                    {count} {language.t(statusLabelKey(status)).toLowerCase()}
                  </span>
                </Show>
              )
            }}
          </For>
        </div>
        <Show when={audited()}>
          <span
            class={`inline-flex items-center gap-1.5 rounded-sm border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${CONFIDENCE_CHIP[confidence()] ?? CONFIDENCE_CHIP.high}`}
            title={language.t("compliance.confidence.tooltip")}
          >
            {language.t("ccm.confidence")}
            {language.t(CONFIDENCE_LABEL_KEYS[confidence()] ?? CONFIDENCE_LABEL_KEYS.high)}
          </span>
        </Show>
      </div>
    </div>
  )
}

function DriftRow(props: { event: ComplianceDriftEvent }) {
  const language = useLanguage()
  const from = () => statusMeta(props.event.statusFrom)
  const to = () => statusMeta(props.event.statusTo)
  const worsened = () => driftWorsened(props.event.statusFrom, props.event.statusTo)
  return (
    <div class="flex items-center gap-3 rounded-[4px] border border-border-weaker-base bg-bg-surface px-3 py-2.5 shadow-xs">
      <div
        class={`flex size-6 shrink-0 items-center justify-center rounded-[4px] ${
          worsened() ? "bg-severity-bg-critical text-severity-fg-critical" : "bg-severity-bg-low text-severity-fg-low"
        }`}
      >
        <Icon name={worsened() ? "warning" : "shield-check"} size="small" />
      </div>
      <div class="min-w-0 flex-1">
        <div class="flex items-center gap-2">
          <span class="shrink-0 font-mono text-xs font-semibold text-text-primary">{props.event.controlId}</span>
          <span class="truncate font-mono text-11-mono text-text-tertiary">{props.event.framework}</span>
        </div>
        <div class="mt-0.5 truncate text-[11px] text-text-tertiary font-mono">
          {language.t("ccm.project", { id: props.event.projectID.slice(0, 12) })} ·{" "}
          {getRelativeTimeFromMs(props.event.timeRecorded, language.t)}
        </div>
      </div>
      <div class="flex shrink-0 items-center gap-1.5 font-mono">
        <span class={`rounded-[3px] border px-1.5 py-0.5 text-[10px] font-semibold ${from().badge}`}>
          {language.t(from().labelKey)}
        </span>
        <span class="text-text-tertiary text-xs">→</span>
        <span class={`rounded-[3px] border px-1.5 py-0.5 text-[10px] font-semibold ${to().badge}`}>
          {language.t(to().labelKey)}
        </span>
      </div>
    </div>
  )
}

export default function CcmPage() {
  const sdk = useSDK()
  const language = useLanguage()
  const [version, bump] = createSignal(0)
  const [loadError, setLoadError] = createSignal(false)

  const [summary] = createResource(
    () => version(),
    async () => {
      try {
        return await loadComplianceSummary(sdk.request)
      } catch {
        setLoadError(true)
        return undefined
      }
    },
  )
  const [drift] = createResource(
    () => version(),
    async () => {
      try {
        return await loadComplianceDrift(sdk.request, 20)
      } catch {
        setLoadError(true)
        return undefined
      }
    },
  )

  useAutoRefresh(() => bump((value) => value + 1))

  const deficientTotal = createMemo(() =>
    (summary()?.frameworks ?? []).reduce((acc, framework) => acc + framework.counts.deficient, 0),
  )
  const partialTotal = createMemo(() =>
    (summary()?.frameworks ?? []).reduce((acc, framework) => acc + framework.counts.partial, 0),
  )
  const driftCount = createMemo(() => drift()?.length ?? 0)

  const hasData = createMemo(() => (summary()?.frameworks.length ?? 0) > 0)

  return (
    <div class="flex h-full flex-col bg-bg-base text-text-primary">
      <PageHeader
        title={language.t("ccm.title")}
        description={language.t("ccm.description")}
        actions={<OpsRefreshButton label={language.t("ccm.refresh")} onClick={() => bump((value) => value + 1)} />}
      />

      <Show
        when={hasData()}
        fallback={
          <Show
            when={!loadError()}
            fallback={
              <OpsErrorPanel
                title={language.t("ccm.error.title")}
                body={language.t("ccm.error.body")}
                retryLabel={language.t("ccm.retry")}
                onRetry={() => {
                  setLoadError(false)
                  bump((value) => value + 1)
                }}
              />
            }
          >
            <EmptyState
              icon={<Icon name="checklist" class="h-6 w-6" />}
              title={language.t("ccm.noData.title")}
              description={language.t("ccm.noData.body")}
            />
          </Show>
        }
      >
        <div class="flex-1 overflow-y-auto px-6 pb-10">
          <div class="mx-auto flex max-w-240 flex-col gap-6 pt-6">
            {/* KPI row */}
            <div class="grid grid-cols-2 gap-3 lg:grid-cols-4">
              <KpiCard label={language.t("ccm.kpi.projects")} value={summary()?.projectCount ?? 0} icon="server" />
              <KpiCard
                label={language.t("ccm.kpi.deficient")}
                value={deficientTotal()}
                icon="warning"
                accent="var(--severity-fg-critical)"
              />
              <KpiCard label={language.t("ccm.kpi.partial")} value={partialTotal()} icon="shield" accent="var(--severity-fg-medium)" />
              <KpiCard label={language.t("ccm.kpi.drift")} value={driftCount()} icon="ban" accent="var(--accent)" />
            </div>

            {/* Frameworks */}
            <div>
              <div class="mb-2 flex items-center justify-between">
                <h2 class="text-sm font-semibold text-text-primary">{language.t("ccm.framework.by")}</h2>
                <span class="text-xs text-text-tertiary">
                  {language.t("ccm.lastUpdated", { time: getRelativeTimeFromMs(summary()?.lastUpdated, language.t) })}
                </span>
              </div>
              <div class="grid grid-cols-1 gap-3 lg:grid-cols-2">
                <For each={summary()?.frameworks ?? []}>
                  {(framework) => <FrameworkCard framework={framework} />}
                </For>
              </div>
            </div>

            {/* Drift feed */}
            <OpsCard
              headerClass="flex items-center justify-between border-b border-border-weaker-base px-4 py-3"
              contentClass="flex max-h-80 flex-col gap-1.5 overflow-y-auto p-2.5"
              title={<span class="text-sm font-semibold text-text-primary">{language.t("ccm.drift.title")}</span>}
              trailing={<span class="text-xs text-text-tertiary">{language.t("ccm.drift.subtitle")}</span>}
            >
              <Show
                when={(drift()?.length ?? 0) > 0}
                fallback={
                  <div class="flex flex-col items-center gap-2 py-8 text-center">
                    <Icon name="shield-check" class="h-6 w-6 text-text-tertiary" />
                    <div class="text-xs text-text-secondary">{language.t("ccm.drift.empty")}</div>
                  </div>
                }
              >
                <For each={drift() ?? []}>{(event) => <DriftRow event={event} />}</For>
              </Show>
            </OpsCard>

            <p class="text-[11px] leading-relaxed text-text-tertiary">{language.t("ccm.footer")}</p>
          </div>
        </div>
      </Show>
    </div>
  )
}

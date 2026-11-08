import { createMemo, For, Show } from "solid-js"
import type { Severity } from "../../findings-data"
import type { CockpitTab } from "./cockpit-types"

const SEVERITY_BUTTONS: { key: Severity | "all"; label: string; dotClass: string }[] = [
  { key: "all", label: "Todos", dotClass: "" },
  { key: "critical", label: "Crítico", dotClass: "bg-severity-fg-critical" },
  { key: "high", label: "Alto", dotClass: "bg-severity-fg-high" },
  { key: "medium", label: "Medio", dotClass: "bg-severity-fg-medium" },
  { key: "low", label: "Bajo", dotClass: "bg-severity-fg-low" },
  { key: "info", label: "Info", dotClass: "bg-severity-fg-info" },
]

export function CockpitHeaderBar(props: {
  targetScope: string
  totalEndpoints: number
  totalFindings: number
  maxCvss?: number
  tlp: string
  activeSeverity: Severity | "all"
  severityCounts: Record<Severity | "all", number>
  onSeverityChange: (sev: Severity | "all") => void
  activeTab: CockpitTab
  onTabChange: (tab: CockpitTab) => void
  strategistOpen: boolean
  onToggleStrategist: () => void
  hideUnpersisted: boolean
  onToggleHideUnpersisted: () => void
  unpersistedCount?: number
  onExportSarif: () => void
}) {

  const riskLabel = createMemo(() => {
    if (props.maxCvss === undefined) return "sin puntuar"
    if (props.maxCvss >= 9.0) return "crítico"
    if (props.maxCvss >= 7.0) return "alto"
    if (props.maxCvss >= 4.0) return "medio"
    return "bajo"
  })

  return (
    <header class="shrink-0 bg-bg-surface border-b border-border-weaker-base px-6 pt-4 pb-0 flex flex-col gap-3 no-print print:hidden">
      {/* Barra superior de acciones y alcance */}
      <div class="flex flex-wrap items-start justify-between gap-4">
        <div class="min-w-0">
          <div class="flex items-center gap-2 font-mono text-11-mono text-text-tertiary">
            <span>{props.targetScope || "auditoría"}</span>
          </div>
          <h1 class="mt-1 text-lg font-semibold tracking-tight text-text-primary">
            {"Informe de auditoría de seguridad"}
          </h1>
          <p class="mt-0.5 text-xs text-text-secondary">
            {`${new Date().toLocaleDateString("es-ES", { day: "numeric", month: "long", year: "numeric" })} · ${props.totalEndpoints} endpoints registrados · `}
            <span class="font-medium text-text-primary">{`${props.totalFindings} hallazgos`}</span>
            {` · riesgo ${riskLabel()} (CVSS máx. ${props.maxCvss?.toFixed(1) ?? "—"}) · `}
            <span class="font-mono text-11-mono text-severity-fg-medium">{props.tlp}</span>
          </p>
        </div>

        {/* Acciones principales y filtros */}
        <div class="flex flex-wrap items-center gap-2">
          {/* Botones de filtro de severidad */}
          <div class="hidden md:flex items-center gap-1 border border-border-weaker-base rounded-sm p-0.5 bg-bg-base/50">
            <For each={SEVERITY_BUTTONS}>
              {(btn) => {
                const isActive = () => props.activeSeverity === btn.key
                const count = () => props.severityCounts[btn.key] ?? 0
                return (
                  <button
                    type="button"
                    onClick={() => props.onSeverityChange(btn.key)}
                    class={`px-2 py-1 rounded-xs flex items-center gap-1.5 text-xs transition-colors ${
                      isActive()
                        ? "bg-bg-elevated text-text-primary font-medium shadow-xs"
                        : "text-text-secondary hover:text-text-primary hover:bg-bg-surface"
                    }`}
                  >
                    <Show when={btn.dotClass}>
                      <span class={`size-1.5 rounded-full ${btn.dotClass}`} />
                    </Show>
                    <span>{btn.label}</span>
                    <span class="tabular-nums font-mono text-11-mono text-text-tertiary">{count()}</span>
                  </button>
                )
              }}
            </For>
          </div>

          <button
            type="button"
            onClick={() => props.onToggleStrategist()}
            class={`px-2.5 py-1.5 rounded-sm border text-xs transition-colors ${
              props.strategistOpen
                ? "border-text-primary bg-text-primary text-bg-base font-medium"
                : "border-border-weaker-base text-text-secondary hover:text-text-primary hover:border-border-strong bg-bg-surface"
            }`}
            title={"Abrir u ocultar el estado del expediente"}
          >
            {"Estado"}
          </button>

          <button
            type="button"
            onClick={() => props.onExportSarif()}
            class="hidden sm:block px-2.5 py-1.5 rounded-sm border border-border-weaker-base text-xs text-text-secondary hover:text-text-primary hover:border-border-strong bg-bg-surface transition-colors"
            title={"Copiar informe SARIF 2.1.0"}
          >
            {"SARIF"}
          </button>

        </div>
      </div>

      {/* Navegación por sub-pestañas operativas */}
      <div class="mt-2 flex items-center justify-between gap-4 border-t border-border-weaker-base/60 pt-2">
        <div class="flex items-center gap-6 overflow-x-auto">
          <button
            type="button"
            aria-pressed={props.activeTab === "findings"}
            onClick={() => props.onTabChange("findings")}
            class={`pb-2.5 -mb-px text-sm border-b-2 font-medium transition-colors whitespace-nowrap ${
              props.activeTab === "findings"
                ? "border-text-primary text-text-primary"
                : "border-transparent text-text-tertiary hover:text-text-secondary"
            }`}
          >
            {`Hallazgos (${props.totalFindings})`}
          </button>
          <button
            type="button"
            aria-pressed={props.activeTab === "compliance"}
            onClick={() => props.onTabChange("compliance")}
            class={`pb-2.5 -mb-px text-sm border-b-2 font-medium transition-colors whitespace-nowrap ${
              props.activeTab === "compliance"
                ? "border-text-primary text-text-primary"
                : "border-transparent text-text-tertiary hover:text-text-secondary"
            }`}
          >
            {"Cumplimiento"}
          </button>
          <button
            type="button"
            aria-pressed={props.activeTab === "report"}
            onClick={() => props.onTabChange("report")}
            class={`pb-2.5 -mb-px text-sm border-b-2 font-medium transition-colors whitespace-nowrap ${
              props.activeTab === "report"
                ? "border-text-primary text-text-primary"
                : "border-transparent text-text-tertiary hover:text-text-secondary"
            }`}
          >
            {"Informe ejecutivo"}
          </button>
        </div>

        <label class="hidden sm:flex items-center gap-2 pb-2.5 text-xs text-text-secondary cursor-pointer select-none">
          <input
            type="checkbox"
            checked={props.hideUnpersisted}
            onChange={() => props.onToggleHideUnpersisted()}
            class="accent-accent size-3.5 rounded-xs"
          />
          <span>
            {"Ocultar hallazgos no persistidos"}
            <Show when={props.unpersistedCount !== undefined && props.unpersistedCount > 0}>
              {` (${props.unpersistedCount})`}
            </Show>
          </span>
        </label>
      </div>
    </header>
  )
}

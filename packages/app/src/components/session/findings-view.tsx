import { createEffect, createMemo, createSignal, For, Show } from "solid-js"
import { createStore } from "solid-js/store"
import { Button } from "@argos/ui/button"
import { Icon } from "@argos/ui/icon"
import { PixelIcon } from "@argos/ui/pixel-icon"
import { useLanguage } from "@/context/language"
import { useSDK } from "@/context/sdk"
import { generateSarifLog, type SarifFinding } from "@argos/core/security/sarif"
import { retestFinding, setFindingStatus } from "./security-findings-api"
import { persistFindingStatusChange } from "./finding-status-action"
import { type Finding, findingDedupeKey, type WebSurface, type Severity } from "./findings-data"
import { showToast } from "@/utils/toast"
import { AttckFilterBar } from "./finding/cockpit/AttckFilterBar"
import { FindingsMasterDetail } from "./finding/cockpit/FindingsMasterDetail"
import { FindingCasesPanel } from "./FindingCasesPanel"
import { mapToCockpitFinding, aggregateAttackTechniques } from "./finding/cockpit/cockpit-data"
import type { CockpitFinding } from "./finding/cockpit/cockpit-types"

/** Adapta el `Finding` de la vista a la forma que consume el generador SARIF compartido. */
function toSarifFinding(f: Finding): SarifFinding {
  return {
    id: f.id ?? findingDedupeKey(f),
    title: f.title,
    severity: f.severity,
    status: f.status ?? "open",
    feedback: f.feedback,
    cwe: f.cwe,
    vector: f.vector,
    target: f.target,
    remediation: f.remediation,
    tags: f.tags,
    attackTechniqueIds: f.attack?.map((t) => t.id),
    epssScore: f.epssKev?.epssScore,
    epssPercentile: f.epssKev?.epssPercentile,
    cisaKev: f.epssKev?.cisaKev,
  }
}

function downloadSarif(findings: Finding[], target?: string, language?: ReturnType<typeof useLanguage>) {
  const sarifData = generateSarifLog(findings.map(toSarifFinding), { target })

  const blob = new Blob([JSON.stringify(sarifData, null, 2)], { type: "application/json" })
  const url = URL.createObjectURL(blob)
  const a = document.createElement("a")
  a.href = url
  a.download = `argos-security-findings-${new Date().toISOString().slice(0, 10)}.sarif`
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)

  if (language) {
    showToast({
      title: language.t("findings.export.sarifSuccess"),
      description: `${findings.length} findings → SARIF v2.1.0`,
    })
  }
}

const SEVERITY_BUTTONS: { key: Severity | "all"; label: string; dotClass: string }[] = [
  { key: "all", label: "Todos", dotClass: "" },
  { key: "critical", label: "Crítico", dotClass: "bg-severity-fg-critical" },
  { key: "high", label: "Alto", dotClass: "bg-severity-fg-high" },
  { key: "medium", label: "Medio", dotClass: "bg-severity-fg-medium" },
  { key: "low", label: "Bajo", dotClass: "bg-severity-fg-low" },
  { key: "info", label: "Info", dotClass: "bg-severity-fg-info" },
]

function EmptyFindings(props: { title: string; sub: string }) {
  return (
    <div class="flex flex-1 flex-col items-center justify-center gap-3 p-8 text-center animate-in fade-in duration-300">
      <div class="relative flex h-20 w-20 items-center justify-center rounded-sm border border-border-weaker-base bg-bg-surface text-accent mb-2">
        <PixelIcon name="shield" size={48} />
      </div>
      <div class="flex flex-col gap-1 max-w-sm">
        <div class="text-12-mono font-bold uppercase tracking-wider text-text-primary">{props.title}</div>
        <div class="text-12-regular text-text-secondary leading-relaxed">{props.sub}</div>
      </div>
    </div>
  )
}

export function FindingsTable(props: {
  findings: Finding[]
  sessionID: string
  surface?: WebSurface
  selectable?: boolean
  selectedIds?: string[]
  onToggleSelect?: (finding: Finding) => void
  dense?: boolean
  hideSummary?: boolean
  /**
   * Delega "Re-verificar" al agente del chat en vez del chequeo pasivo por HTTP.
   * Devuelve `true` si el pedido se envió. Solo lo pasa el panel de sesión.
   */
  onAgentVerify?: (finding: Finding) => Promise<boolean> | boolean
}) {
  const language = useLanguage()
  const sdk = useSDK()

  const [selectedFindingId, setSelectedFindingId] = createSignal("")
  const [activeSeverity, setActiveSeverity] = createSignal<Severity | "all">("all")
  const [activeMitreFilter, setActiveMitreFilter] = createSignal<string | null>(null)
  const [search, setSearch] = createSignal("")
  const [localStatusOverrides, setLocalStatusOverrides] = createStore<Record<string, string>>({})
  const [reverifyingId, setReverifyingId] = createSignal<string>()
  const [reverifyMessages, setReverifyMessages] = createStore<Record<string, string>>({})

  // Mapear findings de la sesión a formato pericial cockpit
  const allCockpitFindings = createMemo<CockpitFinding[]>(() => {
    return props.findings.map((f, i) => {
      const mapped = mapToCockpitFinding(f, i)
      const override = localStatusOverrides[mapped.id]
      return override ? { ...mapped, status: override } : mapped
    })
  })
  const findingRefreshKey = createMemo(() =>
    props.findings.map((finding) => finding.id ?? findingDedupeKey(finding)).join("|"),
  )

  // Sincronizar selección inicial o tras cambios en la lista
  createEffect(() => {
    const list = allCockpitFindings()
    if (list.length > 0) {
      if (!selectedFindingId() || !list.some((f) => f.id === selectedFindingId())) {
        setSelectedFindingId(list[0].id)
      }
    }
  })

  // Filtrado de hallazgos
  const filteredFindings = createMemo(() => {
    return allCockpitFindings().filter((f) => {
      if (activeSeverity() !== "all" && f.severity !== activeSeverity()) return false
      if (activeMitreFilter() && !f.mitre.some((m) => m.id === activeMitreFilter())) return false
      if (search().trim()) {
        const q = search().trim().toLowerCase()
        const mitreStr = f.mitre.map((m) => `${m.id} ${m.name}`).join(" ")
        const haystack =
          `${f.title} ${f.cwe} ${f.target} ${f.shortId} ${mitreStr} ${f.iocs.map((i) => i.value).join(" ")}`.toLowerCase()
        if (!haystack.includes(q)) return false
      }
      return true
    })
  })

  // Agregación de técnicas ATT&CK para la barra de filtros
  const techniques = createMemo(() => aggregateAttackTechniques(allCockpitFindings()))

  // Conteo por severidad
  const counts = createMemo(() => {
    const res: Record<Severity | "all", number> = {
      all: props.findings.length,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    }
    for (const f of props.findings) {
      if (f.severity in res) {
        res[f.severity]++
      }
    }
    return res
  })

  const hasSurfaceData = createMemo(
    () => !!props.surface && (props.surface.crawledUrls.length > 0 || props.surface.fuzzingHits.length > 0),
  )

  const handleStatusChange = async (id: string, nextStatus: string) => {
    const finding = allCockpitFindings().find((f) => f.id === id)
    const orig = props.findings.find((f) => (f.id ?? findingDedupeKey(f)) === id)
    const sessionID = orig?.session
    const findingID = orig?.id

    if (!findingID || !sessionID) {
      showToast({ title: language.t("findings.status.manualOnly") })
      return
    }

    const saved = await persistFindingStatusChange(
      () => setFindingStatus((...args) => sdk.request(...args), sessionID, findingID, nextStatus),
      () => setLocalStatusOverrides(id, nextStatus),
    )

    if (!saved) {
      showToast({ title: language.t("findings.status.saveFailed"), description: finding?.shortId ?? id })
      return
    }

    showToast({
      title: `${finding?.shortId ?? id} actualizado`,
      description: `Estado persistido: ${nextStatus}`,
    })
  }

  const handleReverify = async (id: string) => {
    const orig = props.findings.find((f) => (f.id ?? findingDedupeKey(f)) === id)
    if (!orig || !orig.id || !orig.session) {
      showToast({ title: language.t("findings.retest.noId") })
      return
    }

    setReverifyingId(id)
    setReverifyMessages(id, "")

    if (props.onAgentVerify) {
      const sent = await props.onAgentVerify(orig)
      setReverifyingId(undefined)
      if (sent) {
        const msg = language.t("findings.retest.agentHandoff")
        setReverifyMessages(id, msg)
        showToast({
          title: language.t("findings.retest.agentHandoffTitle") ?? "Re-verificación delegada",
          description: msg,
        })
      }
      return
    }

    try {
      const result = await retestFinding((...args) => sdk.request(...args), orig.session, orig.id)
      setReverifyingId(undefined)
      if (!result) {
        showToast({ title: language.t("findings.retest.unavailable") })
        return
      }
      setReverifyMessages(id, result.message)
      const title = !result.checked
        ? language.t("findings.retest.needsManual")
        : result.stillVulnerable
          ? language.t("findings.retest.stillVulnerable")
          : language.t("findings.retest.success")
      showToast({ title, description: result.message })
    } catch {
      setReverifyingId(undefined)
      showToast({ title: language.t("findings.retest.error") })
    }
  }

  return (
    <div class="flex h-full flex-col min-h-0 overflow-hidden">
      <Show
        when={props.findings.length > 0 || hasSurfaceData()}
        fallback={<EmptyFindings title={language.t("findings.empty.title")} sub={language.t("findings.empty.sub")} />}
      >
        {/* Barra superior de severidad pericial y exportación SARIF */}
        <div class="shrink-0 border-b border-border-weaker-base bg-bg-surface px-4 py-2 flex flex-wrap items-center justify-between gap-2.5">
          <div class="flex flex-wrap items-center gap-2 min-w-0">
            {/* Botones de filtro de severidad */}
            <div class="flex items-center gap-1 border border-border-weaker-base rounded-sm p-0.5 bg-bg-base/50">
              <For each={SEVERITY_BUTTONS}>
                {(btn) => {
                  const isActive = () => activeSeverity() === btn.key
                  const count = () => counts()[btn.key] ?? 0
                  return (
                    <button
                      type="button"
                      onClick={() => setActiveSeverity(btn.key)}
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

            <Show when={props.surface?.target}>
              <div class="hidden sm:flex items-center gap-1.5 px-2 py-1 font-mono text-10-mono text-text-tertiary border border-border-weaker-base rounded-xs bg-bg-surface/60 max-w-[200px] truncate">
                <Icon name="magnifying-glass" size="small" class="shrink-0 text-text-tertiary" />
                <span class="truncate">{props.surface?.target}</span>
              </div>
            </Show>
          </div>

          <div class="flex items-center gap-2">
            <Button
              variant="ghost"
              size="small"
              icon="download"
              onClick={() => downloadSarif(props.findings, props.surface?.target, language)}
              title={language.t("findings.export.sarif")}
            >
              <span class="text-10-mono uppercase tracking-wider font-semibold">{"SARIF"}</span>
            </Button>
          </div>
        </div>

        {/* Superficie web expuesta si está disponible */}
        <Show when={hasSurfaceData()}>
          <div class="shrink-0 flex items-center justify-between border-b border-border-weaker-base bg-bg-surface/40 px-4 py-1.5 text-xs text-text-secondary">
            <div class="flex items-center gap-3 font-mono text-11-mono">
              <span class="text-text-tertiary uppercase tracking-wider">{"Superficie web"}</span>
              <span class="text-text-primary tabular-nums">
                {`${props.surface?.crawledUrls.length ?? 0} URLs rastreadas`}
              </span>
              <span>·</span>
              <span class="text-text-primary tabular-nums">
                {`${props.surface?.fuzzingHits.length ?? 0} endpoints expuestos`}
              </span>
            </div>
          </div>
        </Show>

        {/* Píldoras ATT&CK y buscador reactivo */}
        <AttckFilterBar
          techniques={techniques()}
          activeTechnique={activeMitreFilter()}
          onSelectTechnique={(id) => setActiveMitreFilter((curr) => (curr === id ? null : id))}
          search={search()}
          onSearchChange={setSearch}
        />

        <FindingCasesPanel sessionID={props.sessionID} refreshKey={findingRefreshKey()} findings={props.findings} />

        {/* Estructura Master-Detail pericial cockpit (7 cols lista / 5 cols inspector) */}
        <FindingsMasterDetail
          findings={filteredFindings()}
          selectedFindingId={selectedFindingId()}
          onSelectFinding={setSelectedFindingId}
          onStatusChange={handleStatusChange}
          onResetFilters={() => {
            setActiveSeverity("all")
            setActiveMitreFilter(null)
            setSearch("")
          }}
          onReverify={handleReverify}
          reverifying={Boolean(reverifyingId())}
          reverifyMessage={reverifyMessages[selectedFindingId()]}
        />
      </Show>
    </div>
  )
}

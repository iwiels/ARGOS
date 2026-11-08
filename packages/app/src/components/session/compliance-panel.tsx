import { createEffect, createMemo, createResource, For, Show } from "solid-js"
import { createStore } from "solid-js/store"
import { Icon } from "@argos/ui/icon"
import { IconButton } from "@argos/ui/icon-button"
import { Spinner } from "@argos/ui/spinner"
import { Tooltip } from "@argos/ui/tooltip"
import { useSDK } from "@/context/sdk"
import { useLanguage } from "@/context/language"
import { getRelativeTimeFromMs } from "@/utils/time"
import { EmptyState } from "@/components/audit-ui"
import { PanelSummaryCard } from "./panel-ui"
import {
  loadComplianceStatus,
  refreshComplianceCatalog,
  findingBelongsToSession,
  type ComplianceNode,
  type ComplianceStatus,
  type EvidenceConfidence,
} from "./compliance-api"
import { STATUS_ORDER, statusLabelKey, statusMeta } from "./ccm-data"
import { type Finding, severityLabelKey } from "./findings-data"
import { localizeComplianceTitle } from "./compliance-i18n"

const STATUS_KEYS: ComplianceStatus[] = [...STATUS_ORDER]

/** Nombre localizado de cada framework de compliance. */
const FRAMEWORK_LABEL_KEYS: Record<string, string> = {
  nist_csf_v2: "compliance.framework.nist_csf_v2",
  iso27001_2022: "compliance.framework.iso27001_2022",
  soc2: "compliance.framework.soc2",
  nis2: "compliance.framework.nis2",
  dora: "compliance.framework.dora",
  pci_dss_v4: "compliance.framework.pci_dss_v4",
}

/** Etiqueta del framework en el idioma activo; cae al título del servidor. */
export function frameworkLabel(
  framework: string,
  fallback: string,
  t: (key: string) => string,
): string {
  const key = FRAMEWORK_LABEL_KEYS[framework]
  return key ? t(key) : fallback
}

const STATUS_DOT: Record<ComplianceStatus, string> = {
  deficient: "bg-severity-fg-critical",
  partial: "bg-severity-fg-medium",
  compliant: "bg-severity-fg-low",
  unassessed: "bg-text-tertiary",
}

const SEV_CHIP: Record<string, string> = {
  critical: "bg-severity-bg-critical text-severity-fg-critical",
  high: "bg-severity-bg-high text-severity-fg-high",
  medium: "bg-severity-bg-medium text-severity-fg-medium",
  low: "bg-severity-bg-low text-severity-fg-low",
  info: "bg-bg-elevated text-text-secondary",
}

/** Rampa de la confianza de la derivación (no de la severidad del hallazgo). */
const CONFIDENCE_CHIP: Record<EvidenceConfidence, string> = {
  high: "bg-severity-bg-low text-severity-fg-low border-severity-border-low",
  medium: "bg-severity-bg-medium text-severity-fg-medium border-severity-border-medium",
  low: "bg-severity-bg-critical text-severity-fg-critical border-severity-border-critical",
}

const CONFIDENCE_LABEL_KEYS: Record<EvidenceConfidence, string> = {
  high: "compliance.confidence.high",
  medium: "compliance.confidence.medium",
  low: "compliance.confidence.low",
}

const CONFIDENCE_RANK: Record<EvidenceConfidence, number> = { low: 1, medium: 2, high: 3 }

/**
 * Confianza agregada de un control: la **mayor** entre las entradas de
 * evidencia (un finding de confianza alta no degrada al control porque otro
 * match fue heurístico). Sin evidencia no hay derivación que auditar → `high`.
 */
function aggregateConfidence(entries: Array<{ confidence?: EvidenceConfidence }>): EvidenceConfidence {
  let best: EvidenceConfidence | undefined
  for (const entry of entries) {
    if (!entry.confidence) continue
    if (!best || CONFIDENCE_RANK[entry.confidence] > CONFIDENCE_RANK[best]) best = entry.confidence
  }
  return best ?? "high"
}

// Riel lateral ledger para las filas de evidencia (rampa --severity-*).
const EVIDENCE_RAIL: Record<string, string> = {
  critical: "var(--severity-fg-critical)",
  high: "var(--severity-fg-high)",
  medium: "var(--severity-fg-medium)",
  low: "var(--severity-fg-low)",
  info: "var(--severity-fg-info)",
}

const STATUS_WEIGHT: Record<ComplianceStatus, number> = {
  deficient: 4,
  partial: 3,
  unassessed: 2,
  compliant: 1,
}

function worseStatus(a: ComplianceStatus, b: ComplianceStatus): ComplianceStatus {
  return (STATUS_WEIGHT[a] ?? 1) >= (STATUS_WEIGHT[b] ?? 1) ? a : b
}

function applySessionFindings(
  node: ComplianceNode,
  sessionFindingIds: Set<string>,
): ComplianceNode {
  const belongsToSession = (entry: { findingID?: string; title: string }) =>
    findingBelongsToSession(entry.findingID, sessionFindingIds)

  // La evidencia auditable se filtra por los mismos hallazgos: una regla que
  // no tiene ningún hallazgo de la sesión no puede sustentar el control.
  const ownDerivation = node.derivation
    .map((entry) => ({
      ...entry,
      findings: entry.findings.filter((finding) => {
        return findingBelongsToSession(finding.id, sessionFindingIds)
      }),
    }))
    .filter((entry) => entry.findings.length > 0)

  if (node.children.length > 0) {
    const children = node.children.map((child) =>
      applySessionFindings(child, sessionFindingIds),
    )
    // Un nodo agregado puede tener su propia evidencia (p. ej. un requisito de
    // PCI-DSS al que apunta una regla): si no se contara, el hallazgo se
    // perdería en la vista de la sesión.
    const ownEvidence = node.evidence.filter(belongsToSession)
    const ownStatus: ComplianceStatus =
      ownEvidence.length === 0
        ? "compliant"
        : ownEvidence.some((e) => e.severity.toLowerCase() === "critical" || e.severity.toLowerCase() === "high")
          ? "deficient"
          : "partial"
    const findingCount =
      children.reduce((sum, c) => sum + c.findingCount, 0) + ownEvidence.length
    const status = children.reduce<ComplianceStatus>(
      (worst, c) => worseStatus(worst, c.status),
      ownStatus,
    )
    const derivation = [...ownDerivation, ...children.flatMap((child) => child.derivation)]
    return {
      ...node,
      children,
      findingCount,
      status,
      evidence: [],
      derivation,
      confidence: aggregateConfidence(derivation),
    }
  }

  const filteredEvidence = node.evidence.filter(belongsToSession)

  const hasCriticalHigh = filteredEvidence.some(
    (e) => e.severity.toLowerCase() === "critical" || e.severity.toLowerCase() === "high",
  )
  const status: ComplianceStatus =
    filteredEvidence.length === 0
      ? // Un control que el motor no puede evaluar (coverage "not-evaluable")
        // llega como "unassessed": se conserva ese estado en vez de declarar
        // conformidad sobre algo que nadie midió.
        node.status === "unassessed"
        ? "unassessed"
        : "compliant"
      : hasCriticalHigh
        ? "deficient"
        : "partial"

  return {
    ...node,
    evidence: filteredEvidence,
    derivation: ownDerivation,
    confidence: aggregateConfidence(filteredEvidence),
    findingCount: filteredEvidence.length,
    status,
    children: [],
  }
}

function NodeRow(props: {
  node: ComplianceNode
  depth: number
  isExpanded: (id: string) => boolean
  onToggle: (id: string) => void
  isEvidenceOpen: (id: string) => boolean
  onToggleEvidence: (id: string) => void
}) {
  const language = useLanguage()
  const hasChildren = () => props.node.children.length > 0
  const open = () => props.isExpanded(props.node.id)
  const meta = () => statusMeta(props.node.status)
  const label = () => language.t(statusLabelKey(props.node.status))
  const isLeaf = () => !hasChildren()
  const hasEvidence = () => props.node.evidence.length > 0
  // La confianza solo se muestra cuando hay una derivación que auditar: un
  // control sin hallazgos no tiene nada que sostenga (mostrar "alta" ahí
  // sugeriría que el control fue verificado).
  const showConfidence = () => props.node.evidence.length > 0 || props.node.derivation.length > 0
  const evidenceOpen = () => props.isEvidenceOpen(props.node.id)
  const confidenceLabel = () => language.t(CONFIDENCE_LABEL_KEYS[props.node.confidence] ?? CONFIDENCE_LABEL_KEYS.high)

  return (
    <div class="select-none">
      <div
        class={`group/node flex items-start gap-2 border-border-weaker-base py-2 pr-6 transition-colors ${
          props.depth === 0
            ? "border-b bg-bg-elevated/90 hover:bg-bg-elevated cursor-pointer"
            : "cursor-pointer hover:bg-bg-elevated/60"
        }`}
        style={{ "padding-left": `${20 + props.depth * 16}px` }}
        onClick={() => hasChildren() && props.onToggle(props.node.id)}
      >
        <div
          class={`mt-1.5 size-2 shrink-0 rounded-full ${STATUS_DOT[props.node.status] ?? STATUS_DOT.unassessed}`}
          title={label()}
        />
        <Show when={hasChildren()} fallback={<span class="w-3.5 shrink-0" aria-hidden />}>
          <Icon
            name="chevron-down"
            size="small"
            class={`mt-0.5 shrink-0 text-text-tertiary transition-transform duration-150 ${open() ? "" : "-rotate-90"}`}
          />
        </Show>
        <div class="min-w-0 flex-1">
          <div class="flex min-w-0 items-center gap-2">
            <span class="shrink-0 font-mono text-11-mono font-bold text-accent bg-bg-surface px-1.5 py-0.5 border border-border-weaker-base rounded-sm">{props.node.id}</span>
            <span
              class={`min-w-0 truncate ${
                props.depth === 0 ? "text-12-medium font-semibold text-text-primary" : "text-12-regular text-text-secondary"
              }`}
            >
              {localizeComplianceTitle(props.node.id, props.node.title, language.locale())}
            </span>
          </div>
          <Show when={isLeaf() && hasEvidence()}>
            <div class="mt-1.5 flex flex-col">
              <Show when={evidenceOpen()}>
                <For each={props.node.evidence}>
                  {(evidence) => (
                    <div
                      data-component="finding-ledger-row"
                      class="relative flex items-center gap-1.5 border-b border-border-weaker-base bg-bg-base py-1 pl-3 pr-2"
                    >
                      <span
                        aria-hidden="true"
                        data-component="finding-ledger-rail"
                        class="absolute inset-y-0 left-0 w-1"
                        style={{ "background-color": EVIDENCE_RAIL[evidence.severity] ?? EVIDENCE_RAIL.info }}
                      />
                      <span
                        class={`shrink-0 rounded-sm border border-border-weaker-base px-1 py-px text-10-regular font-semibold uppercase tracking-wide tabular-nums ${SEV_CHIP[evidence.severity] ?? SEV_CHIP.info}`}
                      >
                        {language.t(severityLabelKey(evidence.severity) ?? evidence.severity)}
                      </span>
                      <span class="min-w-0 flex-1 truncate text-11-regular text-text-secondary">{evidence.title}</span>
                      <Show when={evidence.cwe}>
                        <span
                          class="shrink-0 rounded-sm border border-border-weaker-base bg-bg-elevated px-1 py-px font-mono text-10-mono text-text-secondary"
                          title={language.t("compliance.evidence.cwe")}
                        >
                          {evidence.cwe}
                        </span>
                      </Show>
                      <Show when={evidence.derivedFrom}>
                        <span
                          class="shrink-0 rounded-sm border border-border-weaker-base bg-bg-elevated px-1 py-px font-mono text-10-mono text-accent"
                          title={language.t("compliance.evidence.rule")}
                        >
                          {evidence.derivedFrom}
                        </span>
                      </Show>
                      <Show when={evidence.confidence}>
                        {(confidence) => (
                          <span
                            class={`shrink-0 rounded-sm border px-1 py-px text-10-regular font-semibold uppercase tracking-wide ${CONFIDENCE_CHIP[confidence()] ?? CONFIDENCE_CHIP.high}`}
                            title={language.t("compliance.confidence.tooltip")}
                          >
                            {language.t(CONFIDENCE_LABEL_KEYS[confidence()] ?? CONFIDENCE_LABEL_KEYS.high)}
                          </span>
                        )}
                      </Show>
                      <Show when={evidence.fromElasticsearch}>
                        <span
                          class="shrink-0 rounded-sm bg-bg-elevated px-1 py-px text-10-regular font-semibold uppercase tracking-wide text-accent"
                          title={language.t("compliance.evidence.elasticsearch")}
                        >
                          ES
                        </span>
                      </Show>
                    </div>
                  )}
                </For>
              </Show>
            </div>
          </Show>
        </div>
        <Show when={hasEvidence()}>
          <button
            type="button"
            class="mt-0.5 shrink-0 rounded-sm p-0.5 text-text-tertiary transition-colors hover:text-text-secondary cursor-pointer"
            aria-label={
              evidenceOpen() ? language.t("compliance.evidence.collapse") : language.t("compliance.evidence.expand")
            }
            title={evidenceOpen() ? language.t("compliance.evidence.collapse") : language.t("compliance.evidence.expand")}
            onClick={(event) => {
              event.stopPropagation()
              props.onToggleEvidence(props.node.id)
            }}
          >
            <Icon
              name="chevron-down"
              size="small"
              class={`transition-transform duration-150 ${evidenceOpen() ? "" : "-rotate-90"}`}
            />
          </button>
        </Show>
        <Show when={showConfidence()}>
          <Tooltip value={language.t("compliance.confidence.tooltip")} placement="bottom">
            <span
              class={`mt-0.5 shrink-0 rounded-sm border px-1.5 py-0.5 text-10-regular font-semibold uppercase tracking-wide ${CONFIDENCE_CHIP[props.node.confidence] ?? CONFIDENCE_CHIP.high}`}
            >
              {confidenceLabel()}
            </span>
          </Tooltip>
        </Show>
        <span class={`shrink-0 rounded-sm border px-2 py-0.5 text-10-regular font-semibold uppercase tracking-wide ${meta().badge}`}>
          {label()}
        </span>
      </div>
      <Show when={hasChildren() && open()}>
        <For each={props.node.children}>
          {(child) => (
            <NodeRow
              node={child}
              depth={props.depth + 1}
              isExpanded={props.isExpanded}
              onToggle={props.onToggle}
              isEvidenceOpen={props.isEvidenceOpen}
              onToggleEvidence={props.onToggleEvidence}
            />
          )}
        </For>
      </Show>
    </div>
  )
}

type SummaryCounts = Record<ComplianceStatus, number> & { total: number }

const LEAF_LEVELS = new Set(["subcategory", "control"])

function summaryOf(tree: ComplianceNode): SummaryCounts {
  const counts: SummaryCounts = { deficient: 0, partial: 0, compliant: 0, unassessed: 0, total: 0 }
  const walk = (node: ComplianceNode) => {
    if (LEAF_LEVELS.has(node.level)) {
      // Un control que el motor no puede evaluar no entra en el score: se
      // cuenta aparte para no inflar la cobertura con controles no medidos.
      if (node.status === "unassessed") return
      counts[node.status] = (counts[node.status] ?? 0) + 1
      counts.total += 1
      return
    }
    for (const child of node.children) walk(child)
  }
  walk(tree)
  return counts
}

function EmptyCatalog(props: { onSync: () => void; syncing: boolean }) {
  const language = useLanguage()
  return (
    <EmptyState
      icon={<Icon name="checklist" class="h-7 w-7" />}
      title={language.t("compliance.empty.title")}
      description={language.t("compliance.empty.body")}
    >
      <button
        type="button"
        onClick={props.onSync}
        disabled={props.syncing}
        class="mt-1 inline-flex items-center gap-2 rounded-sm border border-border-weaker-base bg-bg-elevated px-3.5 py-2 text-13-medium text-accent transition-colors hover:bg-bg-elevated disabled:opacity-60 cursor-pointer"
      >
        <Show when={props.syncing} fallback={<Icon name="download" size="small" />}>
          <Spinner class="size-3.5" />
        </Show>
        {props.syncing ? language.t("compliance.sync.inProgress") : language.t("compliance.sync.action")}
      </button>
    </EmptyState>
  )
}

/**
 * Grupos de primer nivel de cada framework: se abren por defecto para que los
 * controles queden visibles sin un click extra.
 */
const DEFAULT_EXPANDED_NODES = new Set([
  "GV",
  "ID",
  "PR",
  "DE",
  "RS",
  "RC",
  "A.5",
  "A.6",
  "A.7",
  "A.8",
  "Security",
  "ProcessingIntegrity",
  "Availability",
  "Confidentiality",
  "Privacy",
  "Art.21.2",
  "ICTRiskManagement",
  "IncidentManagementAndReporting",
  "DigitalOperationalResilienceTesting",
  "ICTThirdPartyRisk",
])

/**
 * PCI-DSS es el único catálogo con IDs puramente numéricos (`1`, `6.2`): sus
 * dos niveles de agrupación (requisito y sub-requisito) se abren por defecto.
 * El resto de frameworks usa IDs alfanuméricos y cae a `DEFAULT_EXPANDED_NODES`.
 */
const PCI_NUMERIC_ID = /^\d+(\.\d+)?$/

const isDefaultExpanded = (id: string) => DEFAULT_EXPANDED_NODES.has(id) || PCI_NUMERIC_ID.test(id)

export function CompliancePanel(props: {
  sessionID: () => string | undefined
  findings?: () => Finding[]
}) {
  const sdk = useSDK()
  const language = useLanguage()
  const [state, setState] = createStore({
    error: undefined as string | undefined,
    version: 0,
    syncing: false,
    activeFramework: "nist_csf_v2",
    // Nodos que el usuario plegó o desplegó a mano. Se guarda la desviación
    // respecto del default (`isDefaultExpanded`), no el estado absoluto: así
    // un catálogo nuevo no obliga a mantener una lista de IDs aquí.
    toggledNodes: new Set<string>(),
    // Controles cuya evidencia (hallazgos + regla + confianza) está plegada.
    // Por defecto se ve: es lo que el auditor lee primero.
    collapsedEvidence: new Set<string>(),
  })

  const isExpanded = (id: string) => isDefaultExpanded(id) !== state.toggledNodes.has(id)
  const toggleExpanded = (id: string) => {
    setState("toggledNodes", (prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const isEvidenceOpen = (id: string) => !state.collapsedEvidence.has(id)
  const toggleEvidence = (id: string) => {
    setState("collapsedEvidence", (prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const [status] = createResource(
    () => [props.sessionID(), state.version] as const,
    async ([sessionID]) => {
      if (!sessionID) return undefined
      try {
        const result = await loadComplianceStatus(sdk.request, sessionID)
        setState("error", undefined)
        return result
      } catch (cause) {
        setState("error", cause instanceof Error ? cause.message : String(cause))
        return undefined
      }
    },
  )

  const frameworks = createMemo(() =>
    (status()?.frameworks ?? []).filter((framework) => framework.tree.children.length > 0),
  )
  const catalogEmpty = createMemo(() => (status()?.catalogCount ?? 0) === 0)

  createEffect(() => {
    const available = frameworks().map((framework) => framework.framework)
    if (available.length > 0 && !available.includes(state.activeFramework)) {
      setState("activeFramework", available[0])
    }
  })

  const currentFindings = createMemo(() => props.findings?.() ?? [])
  const sessionFindingIds = createMemo(() => new Set(currentFindings().map((f) => f.id ?? "").filter(Boolean)))

  const active = createMemo(() => {
    const fw = frameworks().find((framework) => framework.framework === state.activeFramework)
    if (!fw) return undefined
    if (!props.findings) return fw
    const tree = applySessionFindings(fw.tree, sessionFindingIds())
    return {
      ...fw,
      tree,
    }
  })

  const summary = createMemo<SummaryCounts>(() =>
    active() ? summaryOf(active()!.tree) : { deficient: 0, partial: 0, compliant: 0, unassessed: 0, total: 0 },
  )

  /** Peor estado presente — da color al punto de la tarjeta de resumen. */
  const worstSummaryStatus = createMemo<ComplianceStatus>(
    () => STATUS_KEYS.find((key) => summary()[key] > 0) ?? "unassessed",
  )

  const sync = async () => {
    setState("syncing", true)
    setState("error", undefined)
    try {
      const result = await refreshComplianceCatalog(sdk.request)
      if (result?.sources) {
        const failedSources = result.sources.filter((s) => !s.ok && s.error)
        if (failedSources.length > 0 && result.catalogControlCount === 0) {
          const firstError = failedSources[0].error ?? "Error desconocido"
          setState("error", `No se pudieron descargar los catálogos: ${firstError}. Verifica tu conexión a internet.`)
        }
      }
      setState("version", (v) => v + 1)
    } catch (cause) {
      setState("error", cause instanceof Error ? cause.message : String(cause))
    } finally {
      setState("syncing", false)
    }
  }

  createEffect(() => {
    if (status() !== undefined && (status()?.catalogCount ?? 0) === 0 && !state.syncing && !state.error) {
      sync()
    }
  })

  const refreshedLabel = () => {
    const value = active()?.refreshedAt
    if (!value) return undefined
    return getRelativeTimeFromMs(value, language.t)
  }

  return (
    <div class="flex h-full flex-col">
      <Show when={state.error}>
        <div class="px-6 py-2 text-11-regular text-severity-fg-critical">{state.error}</div>
      </Show>

      <Show
        when={!status.loading || status() !== undefined}
        fallback={
          <div class="flex h-full items-center justify-center p-8 text-text-tertiary">
            <Spinner class="size-4 text-accent" />
          </div>
        }
      >
        <Show when={!catalogEmpty()} fallback={<EmptyCatalog onSync={sync} syncing={state.syncing} />}>
          <Show when={frameworks().length > 1} fallback={null}>
            <div class="flex shrink-0 items-center gap-1.5 border-b border-border-weaker-base/80 bg-bg-surface px-6 pt-2 pb-0">
              <For each={frameworks()}>
                {(framework) => {
                  const isActive = createMemo(() => state.activeFramework === framework.framework)
                  return (
                    <button
                      type="button"
                      onClick={() => setState("activeFramework", framework.framework)}
                      class={`rounded-t-sm px-3 py-1.5 font-mono text-10-mono uppercase tracking-wider font-bold transition-all cursor-pointer ${
                        isActive()
                          ? "border-t border-x border-border-weaker-base bg-bg-elevated text-text-primary -mb-px border-b-bg-elevated shadow-xs"
                          : "border border-transparent text-text-tertiary hover:text-text-secondary hover:bg-bg-elevated/40"
                      }`}
                    >
                      {frameworkLabel(framework.framework, framework.title, language.t)}
                    </button>
                  )
                }}
              </For>
            </div>
          </Show>

          <Show when={active()} fallback={<EmptyCatalog onSync={sync} syncing={state.syncing} />}>
            {(framework) => (
              <>
                <div class="shrink-0 px-6 pt-4 pb-3">
                  <PanelSummaryCard
                    status={language.t("compliance.evaluation.title")}
                    metric={refreshedLabel()}
                    tone={statusMeta(worstSummaryStatus()).bar}
                    segments={STATUS_KEYS.filter((key) => summary()[key] > 0).map((key) => ({
                      key,
                      label: language.t(statusLabelKey(key)),
                      color: statusMeta(key).bar,
                      width: summary().total > 0 ? (summary()[key] / summary().total) * 100 : 0,
                      display: String(summary()[key]),
                    }))}
                    footer={
                      <div class="-mb-1 flex items-center justify-between gap-2 border-t border-border-weaker-base pt-2">
                        <span class="text-10-regular text-text-weak">
                          {language.t("compliance.coverage", {
                            compliant: summary().compliant,
                            total: summary().total,
                          })}
                        </span>
                        <Tooltip value={language.t("compliance.sync.tooltip")} placement="bottom">
                          <IconButton
                            icon="refresh"
                            variant="ghost"
                            class={state.syncing ? "animate-spin size-5" : "size-5"}
                            disabled={state.syncing}
                            aria-label={language.t("compliance.sync.aria")}
                            onClick={sync}
                          />
                        </Tooltip>
                      </div>
                    }
                  />
                </div>

                <div class="flex-1 overflow-y-auto pb-2">
                  <For each={framework().tree.children}>
                    {(group) => (
                      <NodeRow
                        node={group}
                        depth={0}
                        isExpanded={isExpanded}
                        onToggle={toggleExpanded}
                        isEvidenceOpen={isEvidenceOpen}
                        onToggleEvidence={toggleEvidence}
                      />
                    )}
                  </For>
                </div>

                <div class="shrink-0 border-t border-border-weaker-base bg-bg-surface px-6 py-2.5">
                  <p class="text-10-regular leading-relaxed text-text-weak">{language.t("compliance.footer")}</p>
                </div>
              </>
            )}
          </Show>
        </Show>
      </Show>
    </div>
  )
}

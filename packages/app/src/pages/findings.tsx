import { useParams, useSearchParams } from "@solidjs/router"
import { createEffect, createMemo, createSignal, Show } from "solid-js"
import { createStore } from "solid-js/store"
import { useLanguage } from "@/context/language"
import { useSDK } from "@/context/sdk"
import { useAuditFindings } from "@/hooks/use-audit-findings"
import { targetDirFromParams } from "@/utils/target-dir"
import { showToast } from "@/utils/toast"
import { useCopyToClipboard } from "@argos/ui/hooks"
import { generateSarifLog, type SarifFinding } from "@argos/core/security/sarif"
import { retestFinding, setFindingFeedback, setFindingStatus } from "@/components/session/security-findings-api"
import type { FeedbackVerdict, FindingFeedback, Severity } from "@/components/session/findings-data"
import { CockpitHeaderBar } from "@/components/session/finding/cockpit/CockpitHeaderBar"
import { StrategistDrawer } from "@/components/session/finding/cockpit/StrategistDrawer"
import { FindingsCockpitTab } from "@/components/session/finding/cockpit/tabs/FindingsCockpitTab"
import { ComplianceCockpitTab } from "@/components/session/finding/cockpit/tabs/ComplianceCockpitTab"
import { ExecutiveReportCockpitTab } from "@/components/session/finding/cockpit/tabs/ExecutiveReportCockpitTab"
import {
  mapToCockpitFinding,
  aggregateAttackTechniques,
  reportableCockpitFindings,
  cockpitFindingMetrics,
} from "@/components/session/finding/cockpit/cockpit-data"
import type { CockpitFinding, CockpitTab } from "@/components/session/finding/cockpit/cockpit-types"

/** Sufijo i18n de cada veredicto (`findings.feedback.*`). */
const feedbackKey = (verdict: FeedbackVerdict) =>
  verdict === "true-positive" ? "truePositive" : verdict === "false-positive" ? "falsePositive" : "acceptedRisk"

export default function FindingsPage() {
  const params = useParams<{ auditId?: string; dir?: string }>()
  const [searchParams, setSearchParams] = useSearchParams<{ tab?: string }>()
  const language = useLanguage()
  const sdk = useSDK()
  const { copy: copyToClipboard } = useCopyToClipboard()

  const targetDir = () => targetDirFromParams(params)
  const { findings: rawFindings, counts: _totalCounts, error: apiFindingsError, refetch } = useAuditFindings({ dir: targetDir })

  // Inicializar estado del tab a partir de searchParams (?tab=findings|compliance|report)
  const initialTab: CockpitTab =
    searchParams.tab === "compliance" || searchParams.tab === "report" ? searchParams.tab : "findings"

  const [store, setStore] = createStore({
    activeTab: initialTab,
    selectedFindingId: "" as string,
    activeSeverity: "all" as Severity | "all",
    activeMitreFilter: null as string | null,
    search: "",
    hideUnpersisted: false,
    strategistOpen: typeof window !== "undefined" && window.innerWidth >= 1440,
    tlp: "Sin clasificar",
  })

  // Lista local reactiva modificable (para permitir ciclos de estado y re-verificaciones en caliente)
  const [localStatusOverrides, setLocalStatusOverrides] = createStore<Record<string, string>>({})
  const [localFeedbackOverrides, setLocalFeedbackOverrides] = createStore<Record<string, FindingFeedback | undefined>>({})
  const [reverifyingId, setReverifyingId] = createSignal<string>()
  const [feedbackPendingId, setFeedbackPendingId] = createSignal<string>()
  const [reverifyMessages, setReverifyMessages] = createStore<Record<string, string>>({})

  // Historial de comandos del estratega
  const [chatLog, setChatLog] = createSignal<{ text: string; response: string }[]>([])

  // Hallazgos del servidor y los overrides locales de la sesión actual.
  const allFindings = createMemo<CockpitFinding[]>(() => {
    return rawFindings().map((finding, i) => mapToCockpitFinding(finding, i)).map((f) => {
      const statusOverride = localStatusOverrides[f.id]
      const feedback = localFeedbackOverrides[f.id] ?? f.feedback
      return {
        ...f,
        ...(statusOverride ? { status: statusOverride } : {}),
        ...(feedback ? { feedback } : {}),
      }
    })
  })

  // Lo que entra al entregable: un falso positivo marcado en este engagement
  // sigue visible en el ledger (para poder revertirlo) pero no cuenta en el
  // informe, el SARIF ni la derivación de cumplimiento.
  const reportableFindings = createMemo(() => reportableCockpitFindings(allFindings()))
  const deliverableFindings = createMemo(() =>
    store.hideUnpersisted ? reportableFindings().filter((finding) => finding.persisted) : reportableFindings(),
  )

  // Sincronizar tab con searchParams reactivamente (?tab=findings|compliance|report)
  createEffect(() => {
    const tabParam = searchParams.tab
    const validTab: CockpitTab =
      tabParam === "compliance" || tabParam === "report" ? tabParam : "findings"
    if (store.activeTab !== validTab) {
      setStore("activeTab", validTab)
    }
  })

  // Seleccionar automáticamente el primer hallazgo si no hay selección o la actual ya no existe
  createEffect(() => {
    const list = allFindings()
    if (list.length > 0) {
      if (!store.selectedFindingId || !list.some((f) => f.id === store.selectedFindingId)) {
        setStore("selectedFindingId", list[0].id)
      }
    }
  })

  // Sincronizar tab con URL
  const handleTabChange = (tab: CockpitTab) => {
    setStore("activeTab", tab)
    setSearchParams({ tab: tab === "findings" ? undefined : tab })
  }

  // Filtrado reactivo de hallazgos para la pestaña de Hallazgos
  const filteredFindings = createMemo(() => {
    return allFindings().filter((f) => {
      if (store.hideUnpersisted && !f.persisted) return false
      if (store.activeSeverity !== "all" && f.severity !== store.activeSeverity) return false
      if (store.activeMitreFilter && !f.mitre.some((m) => m.id === store.activeMitreFilter)) return false
      if (store.search.trim()) {
        const q = store.search.trim().toLowerCase()
        const mitreStr = f.mitre.map((m) => `${m.id} ${m.name}`).join(" ")
        const haystack = `${f.title} ${f.cwe ?? ""} ${f.target ?? ""} ${f.shortId} ${mitreStr} ${f.iocs.map((i) => i.value).join(" ")}`.toLowerCase()
        if (!haystack.includes(q)) return false
      }
      return true
    })
  })

  // Técnicas MITRE ATT&CK agregadas
  const techniques = createMemo(() => aggregateAttackTechniques(allFindings()))

  const metrics = createMemo(() => cockpitFindingMetrics(
    store.hideUnpersisted ? allFindings().filter((finding) => finding.persisted) : allFindings(),
  ))

  const unpersistedCount = createMemo(() => {
    return allFindings().filter((f) => !f.persisted).length
  })

  // Manejador del ciclo de estado pericial (6 estados canónicos)
  const handleStatusChange = async (id: string, nextStatus: string) => {
    const finding = allFindings().find((f) => f.id === id)
    if (!finding) return

    if (!finding.persisted || !finding.session) {
      setLocalStatusOverrides(id, nextStatus)
      showToast({ title: "Estado local actualizado", description: "Este hallazgo no está persistido en la base de datos." })
      return
    }

    try {
      const saved = await setFindingStatus((path, init) => sdk.request(path, init), finding.session, finding.id, nextStatus)
      if (!saved) throw new Error("Finding status was not persisted")
      setLocalStatusOverrides(id, nextStatus)
      showToast({ title: `${finding.shortId} actualizado`, description: `Estado persistido: ${nextStatus}` })
      refetch()
    } catch {
      showToast({ title: "No se pudo guardar el estado", description: finding.shortId })
    }
  }

  // Manejador del triage per engagement (ARG-064).
  //
  // El veredicto se aplica optimistamente porque la decisión del auditor no
  // debe esperar a la red; si el request falla se revierte y se avisa. Marcar
  // FP no borra el hallazgo de esta pantalla: lo excluye del entregable y deja
  // el veredicto a la vista para poder cambiarlo.
  const handleFeedback = async (id: string, verdict: FeedbackVerdict) => {
    const finding = allFindings().find((f) => f.id === id)
    if (!finding) return
    if (!finding.persisted || !finding.session) {
      showToast({
        title: language.t("findings.feedback.notPersisted"),
        description: language.t("findings.feedback.notPersistedHint"),
      })
      return
    }

    const previous = finding.feedback
    setLocalFeedbackOverrides(id, { verdict, actor: "human", reason: previous?.reason })
    setFeedbackPendingId(id)
    try {
      const stored = await setFindingFeedback(
        (path, init) => sdk.request(path, init),
        finding.session,
        finding.id,
        verdict,
      )
      if (stored) {
        setLocalFeedbackOverrides(id, stored)
        showToast({
          title: language.t("findings.feedback.saved"),
          description: language.t(`findings.feedback.${feedbackKey(verdict)}`),
        })
        refetch()
      } else {
        setLocalFeedbackOverrides(id, previous)
        showToast({ title: language.t("findings.feedback.failed"), description: finding.shortId })
      }
    } catch {
      setLocalFeedbackOverrides(id, previous)
      showToast({ title: language.t("findings.feedback.failed"), description: finding.shortId })
    } finally {
      setFeedbackPendingId(undefined)
    }
  }

  // Manejador de re-verificación activa
  const handleReverify = async (id: string) => {
    const finding = allFindings().find((f) => f.id === id)
    if (!finding) return

    setReverifyingId(id)
    setReverifyMessages(id, "")

    if (finding.persisted && finding.session) {
      try {
        const result = await retestFinding((path, init) => sdk.request(path, init), finding.session, finding.id)
        if (result) {
          setReverifyMessages(id, result.message)
          if (result.newStatus) {
            setLocalStatusOverrides(id, result.newStatus)
          }
          showToast({
            title: result.stillVulnerable ? "Vulnerabilidad confirmada activa" : "Re-verificación completada",
            description: result.message,
          })
        } else {
          setReverifyMessages(id, "El servidor no confirmó la re-verificación. El estado no se modificó.")
        }
      } catch {
        setReverifyMessages(id, "Error en sonda de re-verificación.")
      } finally {
        setReverifyingId(undefined)
      }
    } else {
      setReverifyingId(undefined)
      showToast({ title: "No se pudo iniciar la re-verificación", description: "El hallazgo no está asociado a un registro persistido." })
    }
  }

  // Exportar SARIF 2.1.0
  const handleExportSarif = async () => {
    const toSarif = (f: CockpitFinding): SarifFinding => ({
      id: f.id,
      title: f.title,
      severity: f.severity,
      status: f.status,
      feedback: f.feedback,
      ...(f.cwe ? { cwe: f.cwe } : {}),
      ...(f.vector ? { vector: f.vector } : {}),
      ...(f.target ? { target: f.target } : {}),
      ...(f.remediation ? { remediation: f.remediation } : {}),
      attackTechniqueIds: f.mitre.map((m) => m.id),
      epssScore: f.epssScore,
      cisaKev: f.cisaKev,
    })

    const sarifData = generateSarifLog(deliverableFindings().map(toSarif), { target: targetDir() })
    const jsonStr = JSON.stringify(sarifData, null, 2)
    try {
      await copyToClipboard(jsonStr)
      showToast({
        title: "SARIF 2.1.0 copiado",
        description: `${deliverableFindings().length} hallazgos exportados al portapapeles.`,
      })
    } catch {
      showToast({ title: "Error al exportar SARIF" })
    }
  }

  // Navegación rápida desde Cumplimiento o Informe al Inspector con reseteo de filtros conflictivos
  const handleJumpToFinding = (shortIdOrId: string) => {
    const match = allFindings().find((f) => f.shortId === shortIdOrId || f.id === shortIdOrId)
    if (match) {
      if (store.activeSeverity !== "all" && store.activeSeverity !== match.severity) {
        setStore("activeSeverity", "all")
      }
      if (store.activeMitreFilter && !match.mitre.some((m) => m.id === store.activeMitreFilter)) {
        setStore("activeMitreFilter", null)
      }
      if (store.search.trim()) {
        setStore("search", "")
      }
      if (store.hideUnpersisted && !match.persisted) {
        setStore("hideUnpersisted", false)
      }
      setStore("selectedFindingId", match.id)
      handleTabChange("findings")
    }
  }

  // Ejecución de comandos del estratega
  const handleStrategistAction = (actionText: string) => {
    if (actionText === "Ocultar hallazgos no persistidos") {
      setStore("hideUnpersisted", true)
      setChatLog((prev) => [{
        text: actionText,
        response: "Se aplicó un filtro local para ocultar hallazgos no persistidos. No se borraron ni deduplicaron registros.",
      }, ...prev])
      showToast({ title: "Filtro local aplicado", description: "No se borraron registros." })
    } else if (actionText.includes("script DNS")) {
      setChatLog((prev) => [
        {
          text: actionText,
          response: "La generación de scripts DNS no está conectada a un generador ni a datos verificados de esta sesión.",
        },
        ...prev,
      ])
      showToast({ title: "Acción no disponible", description: "No se generó ningún script." })
    } else if (actionText.toLowerCase().includes("informe") || actionText.toLowerCase().includes("dossier")) {
      handleTabChange("report")
      showToast({ title: "Borrador de informe abierto" })
    } else {
      setChatLog((prev) => [
        {
          text: actionText,
          response: "Esta acción no está conectada a un ejecutor del runtime; no se ejecutó ningún comando ni se cambió la configuración.",
        },
        ...prev,
      ])
      showToast({ title: "Acción no disponible", description: "No se ejecutó ningún comando." })
    }
  }

  return (
    <div class="findings-cockpit-root flex h-full flex-col bg-bg-base text-text-primary overflow-hidden print:overflow-visible print:h-auto print:bg-white print:text-black">
      {/* Barra de cabecera principal */}
      <CockpitHeaderBar
        targetScope={targetDir() || ""}
        totalEndpoints={metrics().targetCount}
        totalFindings={reportableCockpitFindings(filteredFindings()).length}
        maxCvss={metrics().maxCvss}
        tlp={store.tlp}
        activeSeverity={store.activeSeverity}
        severityCounts={metrics().severityCounts}
        onSeverityChange={(sev) => setStore("activeSeverity", sev)}
        activeTab={store.activeTab}
        onTabChange={handleTabChange}
        strategistOpen={store.strategistOpen}
        onToggleStrategist={() => setStore("strategistOpen", !store.strategistOpen)}
        hideUnpersisted={store.hideUnpersisted}
        onToggleHideUnpersisted={() => setStore("hideUnpersisted", !store.hideUnpersisted)}
        unpersistedCount={unpersistedCount()}
        onExportSarif={handleExportSarif}
      />

      <Show when={apiFindingsError()}>
        <div
          role="alert"
          class="mx-6 my-2 rounded-xs border border-severity-fg-critical/50 bg-severity-fg-critical/10 px-3 py-2 text-xs text-severity-fg-critical"
        >
          {language.t("common.requestFailed") ?? "No se pudieron sincronizar todos los hallazgos con el servidor."}
        </div>
      </Show>

      {/* Contenedor central con drawer lateral del estratega + tabs */}
      <div class="flex-1 flex min-h-0 overflow-hidden print:overflow-visible print:h-auto print:block">
        {/* Panel lateral: Asistente del estratega */}
        <StrategistDrawer
          isOpen={store.strategistOpen}
          onClose={() => setStore("strategistOpen", false)}
          onQuickAction={handleStrategistAction}
          onPromptSubmit={handleStrategistAction}
          chatLog={chatLog()}
          targetDomain={targetDir() || undefined}
          onDossierClick={() => handleTabChange("report")}
        />

        {/* Vistas de las 3 sub-pestañas */}
        <div class="flex-1 flex flex-col min-w-0 min-h-0 overflow-hidden print:overflow-visible print:h-auto print:block">
          <Show when={store.activeTab === "findings"}>
            <FindingsCockpitTab
              findings={filteredFindings()}
              selectedFindingId={store.selectedFindingId}
              onSelectFinding={(id) => setStore("selectedFindingId", id)}
              onStatusChange={handleStatusChange}
              techniques={techniques()}
              activeTechnique={store.activeMitreFilter}
              onSelectTechnique={(techId) =>
                setStore("activeMitreFilter", store.activeMitreFilter === techId ? null : techId)
              }
              search={store.search}
              onSearchChange={(q) => setStore("search", q)}
              onResetFilters={() => {
                setStore("activeSeverity", "all")
                setStore("activeMitreFilter", null)
                setStore("search", "")
              }}
              onReverify={handleReverify}
              onFeedback={handleFeedback}
              feedbackPending={feedbackPendingId() === store.selectedFindingId}
              reverifying={reverifyingId() === store.selectedFindingId}
              reverifyMessage={reverifyMessages[store.selectedFindingId]}
            />
          </Show>

          <Show when={store.activeTab === "compliance"}>
            <ComplianceCockpitTab
              findings={deliverableFindings()}
              onJumpToFinding={handleJumpToFinding}
            />
          </Show>

          <Show when={store.activeTab === "report"}>
            <ExecutiveReportCockpitTab
              findings={deliverableFindings()}
              onInspectFinding={handleJumpToFinding}
              targetScope={targetDir() || undefined}
            />
          </Show>
        </div>
      </div>

    </div>
  )
}

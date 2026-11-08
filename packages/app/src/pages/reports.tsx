import { useParams } from "@solidjs/router"
import { PixelIcon } from "@argos/ui/pixel-icon"
import { Button } from "@argos/ui/button"
import { createMemo, createSignal, For, Show } from "solid-js"
import { type Severity, SEVERITY_ORDER, SEVERITY_LABELS } from "@/components/session/findings-data"
import { SEV_COLOR } from "@/utils/severity"
import { SeverityBadge } from "@/utils/severity-badge"
import {
  generateReport,
  cvssColor,
  cvssLabel,
  type EnrichedReportFinding,
  type RemediationPhase,
  type TargetSummary,
  type TopVulnerability,
} from "@/utils/report-generator"
import {
  downloadJson,
  downloadMarkdown,
  downloadHtml,
  exportReportToMarkdown,
  exportReportToHtml,
} from "@/utils/report-exporters"
import { targetDirFromParams } from "@/utils/target-dir"
import { createReportMetaStore, LOGO_MAX_BYTES, readLogoAsDataUrl } from "@/utils/report-meta"
import { EmptyState, KpiCard, PageHeader, SurfaceCard } from "@/components/audit-ui"
import { useLanguage } from "@/context/language"
import { useSDK } from "@/context/sdk"
import { showToast } from "@/utils/toast"
import { TextField } from "@argos/ui/text-field"
import { useAuditFindings } from "@/hooks/use-audit-findings"
import { useOptionalServerSync, useServerSync } from "@/context/server-sync"
import { OpsCard } from "@/pages/shared/ops-shell"
import "./reports-print.css"

// ── Exportadores profesionales (ARG-043 / ARG-044) ─────────────────────────

/** Formatos que el backend sabe renderizar (ver `packages/core/src/security/export`). */
const EXPORT_FORMATS = ["pdf", "sarif", "defectdojo", "junit", "html", "sbom", "har", "csv", "markdown"] as const

type ExportFormat = (typeof EXPORT_FORMATS)[number]

const EXPORT_EXTENSION: Record<ExportFormat, string> = {
  pdf: "pdf",
  sarif: "sarif",
  defectdojo: "json",
  junit: "xml",
  html: "html",
  sbom: "cdx.json",
  har: "har",
  csv: "csv",
  markdown: "md",
}

type ExportArtifact = {
  filename: string
  mimeType: string
  contentBase64: string
  sha256: string
  contentHash: string
}

/** Guarda el artefacto en disco (escritorio) o lo descarga (web). */
async function persistArtifact(
  artifact: ExportArtifact,
  format: ExportFormat,
): Promise<"saved" | "downloaded" | "cancelled"> {
  const api = typeof window === "undefined" ? undefined : window.api
  if (format === "pdf" && api?.exportReportPdf) {
    const result = await api.exportReportPdf({ filename: artifact.filename, contentBase64: artifact.contentBase64 })
    return result ? "saved" : "cancelled"
  }
  if (api?.exportReportFile) {
    const result = await api.exportReportFile({
      filename: artifact.filename,
      contentBase64: artifact.contentBase64,
      label: format.toUpperCase(),
      extensions: [EXPORT_EXTENSION[format]],
    })
    return result ? "saved" : "cancelled"
  }

  const binary = atob(artifact.contentBase64)
  const bytes = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index++) bytes[index] = binary.charCodeAt(index)
  const url = URL.createObjectURL(new Blob([bytes], { type: artifact.mimeType }))
  const anchor = document.createElement("a")
  anchor.href = url
  anchor.download = artifact.filename
  document.body.appendChild(anchor)
  anchor.click()
  requestAnimationFrame(() => {
    document.body.removeChild(anchor)
    URL.revokeObjectURL(url)
  })
  return "downloaded"
}

// ── Subcomponentes del Reporte ──────────────────────────────────────────────

function SeverityBar(props: { distribution: Record<Severity, number>; total: number }) {
  const language = useLanguage()
  return (
    <div class="flex flex-col gap-3 rounded-sm border border-border-weaker-base bg-bg-surface p-4 report-card shadow-xs">
      <span class="text-13-medium font-semibold uppercase tracking-wider text-text-primary">
        {language.t("reports.severityDistribution")}
      </span>
      <div class="flex h-2.5 w-full gap-0.5 overflow-hidden rounded-sm bg-bg-elevated">
        <For each={SEVERITY_ORDER}>
          {(sev) => {
            const pct = props.total > 0 ? (props.distribution[sev] / props.total) * 100 : 0
            return (
              <Show when={pct > 0}>
                <div
                  class="h-full transition-all duration-300 first:rounded-l-sm last:rounded-r-sm"
                  style={{
                    width: `${pct}%`,
                    "background-color": SEV_COLOR[sev],
                  }}
                  title={`${language.t(SEVERITY_LABELS[sev])}: ${props.distribution[sev]} (${Math.round(pct)}%)`}
                />
              </Show>
            )
          }}
        </For>
      </div>
      <div class="flex flex-wrap gap-x-4 gap-y-1.5">
        <For each={SEVERITY_ORDER}>
          {(sev) => {
            const count = props.distribution[sev]
            const pct = props.total > 0 ? ((count / props.total) * 100).toFixed(0) : "0"
            return (
              <Show when={count > 0}>
                <div class="flex items-center gap-1.5">
                  <div class="size-2 rounded-full shrink-0" style={{ "background-color": SEV_COLOR[sev] }} />
                  <span class="text-xs font-medium tabular-nums text-text-secondary">
                    {language.t(SEVERITY_LABELS[sev])}
                  </span>
                  <span class="text-xs font-medium tabular-nums text-text-primary font-mono">{count}</span>
                  <span class="text-xs text-text-secondary font-mono">({pct}%)</span>
                </div>
              </Show>
            )
          }}
        </For>
      </div>
    </div>
  )
}

function CvssBadge(props: { score: number; severity: string }) {
  const language = useLanguage()
  const color = () => cvssColor(props.score)
  const label = () => cvssLabel(props.severity, language.t)

  return (
    <div class="flex items-center gap-3">
      <div
        class="flex h-12 w-12 items-center justify-center rounded-sm text-base font-mono font-bold tabular-nums border border-border-strong"
        style={{
          color: color(),
          "background-color": `color-mix(in srgb, ${color()} 10%, transparent)`,
        }}
      >
        {props.score.toFixed(1)}
      </div>
      <div class="flex flex-col">
        <span class="text-sm font-semibold tracking-wide uppercase" style={{ color: color() }}>
          {label()}
        </span>
        <span class="text-xs text-text-secondary font-mono">{language.t("reports.cvssAverageBadge")}</span>
      </div>
    </div>
  )
}

function TargetRow(props: { target: TargetSummary }) {
  const { target } = props
  const maxBar = Math.max(target.total, 1)
  return (
    <div class="flex items-center gap-3 rounded-sm px-3 py-2 hover:bg-bg-surface transition-colors">
      <div class="flex-1 min-w-0">
        <span class="text-sm font-mono text-text-primary truncate block">{target.url}</span>
        <div class="flex items-center gap-2 mt-1">
          <div class="flex h-1.5 flex-1 gap-0.5 rounded-sm overflow-hidden bg-bg-elevated">
            <Show when={target.critical > 0}>
              <div class="h-full bg-severity-bg-critical" style={{ width: `${(target.critical / maxBar) * 100}%` }} />
            </Show>
            <Show when={target.high > 0}>
              <div class="h-full bg-severity-bg-high" style={{ width: `${(target.high / maxBar) * 100}%` }} />
            </Show>
            <Show when={target.medium > 0}>
              <div class="h-full bg-severity-bg-medium" style={{ width: `${(target.medium / maxBar) * 100}%` }} />
            </Show>
            <Show when={target.low > 0}>
              <div class="h-full bg-severity-bg-low" style={{ width: `${(target.low / maxBar) * 100}%` }} />
            </Show>
          </div>
          <span class="text-xs text-text-secondary font-mono tabular-nums">{target.total}</span>
        </div>
      </div>
      <div class="flex items-center gap-1.5 shrink-0 font-mono">
        <Show when={target.critical > 0}>
          <SeverityBadge
            severity="critical"
            class="justify-center min-w-4.5 h-4 rounded-sm px-1 text-xs font-semibold tabular-nums"
          >
            {target.critical}
          </SeverityBadge>
        </Show>
        <Show when={target.high > 0}>
          <SeverityBadge
            severity="high"
            class="justify-center min-w-4.5 h-4 rounded-sm px-1 text-xs font-semibold tabular-nums"
          >
            {target.high}
          </SeverityBadge>
        </Show>
      </div>
    </div>
  )
}

function TopVulnRow(props: { vuln: TopVulnerability }) {
  const language = useLanguage()
  const color = () => SEV_COLOR[props.vuln.severity]
  return (
    <div class="flex items-center gap-3 rounded-sm px-3 py-2 hover:bg-bg-surface transition-colors">
      <div
        class="flex h-7 w-7 items-center justify-center rounded-sm text-xs font-mono font-semibold bg-bg-elevated shrink-0"
        style={{ color: color() }}
      >
        {props.vuln.count}
      </div>
      <div class="flex-1 min-w-0">
        <div class="flex items-center gap-2">
          <span class="text-sm font-medium text-text-primary truncate block">{props.vuln.title}</span>
          <Show when={props.vuln.cwe}>
            <span class="font-mono text-10-mono text-text-secondary rounded-sm bg-bg-elevated px-1.5 py-0.5 border border-border-weaker-base shrink-0">
              {props.vuln.cwe}
            </span>
          </Show>
        </div>
      </div>
      <div class="flex items-center gap-2 shrink-0">
        <span class="font-mono text-xs font-bold text-text-primary">
          {props.vuln.cvssScore === undefined ? "CVSS N/A" : "CVSS " + props.vuln.cvssScore.toFixed(1)}
        </span>
        <span class="text-11-mono font-mono px-2 py-0.5 rounded-sm border border-border-weaker-base text-text-secondary">
          {language.t(SEVERITY_LABELS[props.vuln.severity])}
        </span>
      </div>
    </div>
  )
}

// Nota ledger: esta card conserva anatomía inline a propósito — el detalle de
// reporte añade PoC con soporte print, remediación y CVSS que FindingLedgerRow
// (fila de panel) no cubre. Comparte clases y data-component finding-ledger-*
// con `components/session/finding/` para convergencia visual.
function FindingDetailedCard(props: { finding: EnrichedReportFinding }) {
  const language = useLanguage()
  const f = props.finding
  const [showPoC, setShowPoC] = createSignal(false)

  return (
    <article
      data-component="finding-ledger-row"
      class="finding-card report-card relative flex flex-col gap-2.5 border border-border-weaker-base bg-bg-base py-3 pl-5 pr-4"
    >
      <span
        aria-hidden="true"
        data-component="finding-ledger-rail"
        class="absolute inset-y-0 left-0 w-1"
        style={{ "background-color": SEV_COLOR[f.severity] }}
      />
      <div class="flex items-start justify-between gap-3">
        <div class="flex flex-col gap-1 min-w-0">
          <div class="flex items-center gap-2 flex-wrap">
            <span class="font-mono text-10-mono font-bold tabular-nums text-text-secondary">{f.id}</span>
            <SeverityBadge
              severity={f.severity}
              class="rounded-sm px-2 py-0.5 text-10-mono font-bold uppercase tracking-wider"
            >
              {language.t(SEVERITY_LABELS[f.severity])}
            </SeverityBadge>
            <span class="font-mono text-10-mono font-bold tabular-nums text-text-primary bg-bg-elevated px-1.5 py-0.5 border border-border-weaker-base rounded-sm">
              {f.cvss ? "CVSS " + f.cvss.baseScore.toFixed(1) : "CVSS N/A"}
            </span>
            <Show when={f.cwe}>
              <span class="font-mono text-10-mono tabular-nums text-text-secondary bg-bg-elevated px-1.5 py-0.5 border border-border-weaker-base rounded-sm">
                {f.cwe}
              </span>
            </Show>
          </div>
          <h3 class="text-13-medium font-semibold text-text-primary">{f.title}</h3>
        </div>
      </div>

      <div class="font-mono text-10-mono tabular-nums text-text-secondary flex flex-wrap items-center gap-x-4 gap-y-1">
        <span>
          <strong>{language.t("reports.detail.cvssVector")}:</strong> {f.cvss?.vector ?? language.t("reports.cvssUnavailable")}
        </span>
        <Show when={f.target || f.vector}>
          <span>
            <strong>{language.t("reports.detail.target")}:</strong> {f.target ?? f.vector}
          </span>
        </Show>
      </div>

      <Show when={f.attack && f.attack.length > 0}>
        <div data-component="finding-ledger-attck" class="flex flex-wrap items-center gap-1.5 pt-1">
          <span class="font-mono text-10-mono font-semibold uppercase tracking-wider text-text-tertiary">
            {language.t("reports.detail.mitreAttack")}:
          </span>
          <For each={f.attack}>
            {(technique) => (
              <span
                class="inline-flex items-center gap-1 rounded-sm border border-border-weaker-base bg-bg-elevated px-1.5 py-0.5 font-mono text-10-mono text-text-secondary"
                title={`${technique.name} — ${technique.tactics.join(", ")}`}
              >
                <span class="font-bold tabular-nums text-text-primary">{technique.id}</span>
                <span class="max-w-40 truncate">{technique.name}</span>
              </span>
            )}
          </For>
        </div>
      </Show>

      <Show when={f.iocs && f.iocs.length > 0}>
        <div data-component="finding-ledger-iocs" class="flex flex-wrap items-center gap-1.5 pt-1">
          <span class="font-mono text-10-mono font-semibold uppercase tracking-wider text-text-tertiary">
            {language.t("reports.detail.iocs")}:
          </span>
          <For each={f.iocs}>
            {(ioc) => {
              const worst = ioc.reputation?.find((r) => r.verdict === "malicious" || r.verdict === "suspicious")
              return (
                <span
                  class={`inline-flex items-center gap-1 rounded-sm border px-1.5 py-0.5 font-mono text-10-mono ${
                    worst?.verdict === "malicious"
                      ? "text-severity-fg-critical bg-severity-bg-critical border-severity-border-critical"
                      : worst?.verdict === "suspicious"
                        ? "text-severity-fg-high bg-severity-bg-high border-severity-border-high"
                        : "text-text-secondary bg-bg-elevated border-border-weaker-base"
                  }`}
                  title={worst?.detail ?? `${ioc.type}:${ioc.value}`}
                >
                  <span class="opacity-70">{ioc.type.toUpperCase()}</span>
                  <span class="max-w-48 truncate">{ioc.value}</span>
                  {worst && worst.score > 0 && <span class="tabular-nums opacity-80">{worst.score}</span>}
                </span>
              )
            }}
          </For>
        </div>
      </Show>

      {/* Evidencia y PoC */}
      <div
        data-component="finding-ledger-evidence"
        class="flex flex-col gap-1.5 pt-2 border-t border-border-weaker-base"
      >
        <span class="text-xs font-semibold text-text-primary uppercase tracking-wide">
          {language.t("reports.evidence")}
        </span>
        <p class="text-xs text-text-secondary leading-relaxed">
          {f.evidence || "Hallazgo verificado mediante escaneo y análisis automatizado de seguridad."}
        </p>

        <Show when={f.curlCommand || f.httpRequest || f.httpResponse}>
          <div data-component="finding-ledger-actions" class="mt-1">
            <Button
              variant="ghost"
              size="small"
              icon={showPoC() ? "chevron-down" : "chevron-right"}
              onClick={() => setShowPoC(!showPoC())}
              class="print:hidden"
            >
              {showPoC() ? language.t("reports.poc.hide") : language.t("reports.poc.show")}
            </Button>

            <div class={showPoC() ? "block mt-2" : "hidden print:block print:mt-2"}>
              <Show when={f.curlCommand}>
                <div class="mb-2">
                  <span class="font-mono text-10-mono text-text-tertiary">
                    {language.t("reports.detail.curlRepro")}:
                  </span>
                  <pre class="overflow-x-auto whitespace-pre-wrap break-words bg-bg-base p-2 font-mono text-11-mono tabular-nums text-text-primary border border-border-weaker-base rounded-sm">
                    {f.curlCommand}
                  </pre>
                </div>
              </Show>
              <Show when={f.httpRequest}>
                <div class="mb-2">
                  <span class="font-mono text-10-mono text-text-tertiary">
                    {language.t("reports.detail.httpRequest")}:
                  </span>
                  <pre class="overflow-x-auto whitespace-pre-wrap break-words bg-bg-base p-2 font-mono text-11-mono tabular-nums text-text-secondary border border-border-weaker-base rounded-sm">
                    {f.httpRequest}
                  </pre>
                </div>
              </Show>
              <Show when={f.httpResponse}>
                <div>
                  <span class="font-mono text-10-mono text-text-tertiary">
                    {language.t("reports.detail.httpResponse")}:
                  </span>
                  <pre class="overflow-x-auto whitespace-pre-wrap break-words bg-bg-base p-2 font-mono text-11-mono tabular-nums text-text-secondary border border-border-weaker-base rounded-sm">
                    {f.httpResponse}
                  </pre>
                </div>
              </Show>
            </div>
          </div>
        </Show>
      </div>

      {/* Remediación */}
      <div class="flex flex-col gap-1.5 border-l-2 border-accent border-r border-t border-b border-border-weaker-base bg-bg-elevated/40 px-3 py-2 rounded-sm">
        <span class="text-xs font-semibold text-accent uppercase tracking-wide">
          {language.t("reports.remediation")}
        </span>
        <p class="text-xs text-text-primary leading-relaxed">
          {f.remediation || "—"}
        </p>
      </div>
    </article>
  )
}

function RoadmapPhaseCard(props: { phase: RemediationPhase }) {
  const language = useLanguage()
  return (
    <div class="roadmap-card rounded-sm border border-border-weaker-base bg-bg-surface p-4 flex flex-col gap-3 report-card shadow-xs">
      <div class="flex items-center justify-between gap-2 border-b border-border-weaker-base pb-2">
        <div class="flex items-center gap-2">
          <h4 class="text-sm font-semibold text-text-primary">{props.phase.title}</h4>
          <span class="font-mono text-xs text-text-secondary bg-bg-elevated px-2 py-0.5 rounded-sm border border-border-weaker-base">
            Criterio: {props.phase.basis}
          </span>
        </div>
        <span class="font-mono text-xs font-bold text-text-primary">
          {language.t("reports.findingsCount", { count: props.phase.findings.length })}
        </span>
      </div>
      <p class="text-xs text-text-secondary leading-relaxed">{props.phase.description}</p>
      <Show
        when={props.phase.findings.length > 0}
        fallback={<div class="text-xs text-text-tertiary italic">{language.t("reports.roadmap.empty")}</div>}
      >
        <div class="flex flex-col gap-1.5">
          <For each={props.phase.findings}>
            {(f) => (
              <div class="flex items-center justify-between gap-2 p-2 rounded-sm bg-bg-elevated text-xs">
                <div class="flex items-center gap-2 min-w-0">
                  <span class="font-mono font-bold text-text-secondary shrink-0">{f.id}</span>
                  <span class="font-medium text-text-primary truncate">{f.title}</span>
                </div>
                <div class="flex items-center gap-2 shrink-0">
                  <span class={`font-mono font-bold uppercase ${SEV_COLOR[f.severity]}`}>{f.severity}</span>
                  <span class="font-mono text-text-secondary">
                    {f.cvss ? "CVSS " + f.cvss.baseScore.toFixed(1) : "CVSS N/A"}
                  </span>
                </div>
              </div>
            )}
          </For>
        </div>
      </Show>
    </div>
  )
}

// ── Página Principal de Reportes ───────────────────────────────────────────

export default function ReportsPage() {
  const language = useLanguage()
  const params = useParams<{ auditId?: string; dir?: string }>()
  const serverSync = useOptionalServerSync()

  const targetDir = () => targetDirFromParams(params)

  const childStore = createMemo(() =>
    serverSync && targetDir() ? serverSync.child(targetDir(), { bootstrap: false })[0] : undefined,
  )
  const sessions = createMemo(() => childStore()?.session ?? [])

  const { findings: allFindings, counts } = useAuditFindings({ dir: targetDir, persistedOnly: true })

  const { meta, setMeta } = createReportMetaStore(targetDir() || "local")
  const [metaEditorOpen, setMetaEditorOpen] = createSignal(false)
  const [metaSaved, setMetaSaved] = createSignal(false)
  const [exportFormat, setExportFormat] = createSignal<ExportFormat>("pdf")
  const [exporting, setExporting] = createSignal(false)
  let logoInput: HTMLInputElement | undefined

  const sdk = (() => {
    try {
      return useSDK()
    } catch {
      return undefined
    }
  })()

  const handleLogoSelect = async (file: File | undefined) => {
    if (!file) return
    try {
      const dataUrl = await readLogoAsDataUrl(file)
      setMeta("logoDataUrl", dataUrl)
      flashMetaSaved()
    } catch (err) {
      if ((err as Error)?.message === "logo-too-large") {
        showToast({ title: language.t("reports.meta.logoTooLarge", { max: Math.round(LOGO_MAX_BYTES / 1024) }) })
      }
    }
  }

  function flashMetaSaved() {
    setMetaSaved(true)
    window.setTimeout(() => setMetaSaved(false), 1500)
  }

  const report = createMemo(() =>
    generateReport({
      findings: allFindings(),
      sessionCount: sessions().length,
      clientName: "No indicado",
      clientLegalName: meta.legalName,
      clientLogoDataUrl: meta.logoDataUrl,
      classification: meta.classification || undefined,
      leadAuditor: meta.leadAuditor || undefined,
      scope: "No indicado",
    }),
  )

  const hasData = createMemo(() => allFindings().length > 0)

  const handleExportJson = () => {
    downloadJson(report(), `reporte-seguridad-${new Date().toISOString().split("T")[0]}`)
  }

  const handleExportMarkdown = () => {
    downloadMarkdown(exportReportToMarkdown(report()), `informe-ejecutivo-${new Date().toISOString().split("T")[0]}`)
  }

  const handleExportHtml = () => {
    downloadHtml(exportReportToHtml(report()), `informe-ejecutivo-${new Date().toISOString().split("T")[0]}`)
  }

  const handlePrint = () => {
    window.print()
  }

  /**
   * Pide al backend el entregable en el formato pedido y lo deja en disco.
   *
   * El render es server-side: el PDF sale con portada, índice, metadata y
   * hash del contenido, y los formatos de ingestión (SARIF, DefectDojo,
   * JUnit, SBOM, HAR) salen con el schema de su industria.
   */
  const handleExportArtifact = async (format: ExportFormat) => {
    const sessionIDs = sessions()
      .map((session) => session.id)
      .filter(Boolean)
    if (sessionIDs.length === 0) {
      showToast({ title: language.t("reports.export.noSessions") })
      return
    }
    if (!sdk) {
      showToast({ title: language.t("reports.export.failed") })
      return
    }

    setExporting(true)
    try {
      const response = await sdk.request(`/session/${encodeURIComponent(sessionIDs[0])}/report/export`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          format,
          sessionIDs,
          meta: {
            clientName: undefined,
            clientLegalName: meta.legalName || undefined,
            clientLogoDataUrl: meta.logoDataUrl || undefined,
            classification: meta.classification || undefined,
            leadAuditor: meta.leadAuditor || undefined,
            scope: "No indicado",
          },
        }),
      })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      const artifact = (await response.json()) as ExportArtifact

      const outcome = await persistArtifact(artifact, format)
      if (outcome === "saved") showToast({ title: language.t("reports.export.saved", { file: artifact.filename }) })
      if (outcome === "downloaded")
        showToast({ title: language.t("reports.export.downloaded", { file: artifact.filename }) })
    } catch (error) {
      showToast({
        title: language.t("reports.export.failed"),
        description: error instanceof Error ? error.message : String(error),
      })
    } finally {
      setExporting(false)
    }
  }

  const summary = () => report().summary
  const cvss = () => summary().averageCvss

  return (
    <div class="report-page-root flex h-full flex-col bg-bg-base text-text-primary">
      <PageHeader
        class="print:hidden"
        title={<>{language.t("reports.pageTitle")}</>}
        description={language.t(sessions().length === 1 ? "reports.pageSubtitle.one" : "reports.pageSubtitle.other", {
          count: sessions().length,
        })}
        actions={
          <div class="flex items-center gap-2 flex-wrap print:hidden">
            <Button size="small" variant="secondary" icon="settings" onClick={() => setMetaEditorOpen((v) => !v)}>
              {language.t("reports.meta.title")}
            </Button>
            <Button size="small" variant="secondary" icon="printer" onClick={handlePrint}>
              {language.t("reports.print")}
            </Button>
            <Button
              size="small"
              variant="primary"
              icon="download"
              disabled={!hasData() || exporting()}
              onClick={() => void handleExportArtifact("pdf")}
            >
              {language.t("reports.exportPdf")}
            </Button>
            <select
              value={exportFormat()}
              onChange={(event) => setExportFormat(event.currentTarget.value as ExportFormat)}
              aria-label={language.t("reports.exportFormat.label")}
              class="bg-bg-base border border-border-weaker-base rounded-sm px-2.5 py-1.5 text-xs text-text-primary focus:outline-none focus:border-border-strong transition-colors"
            >
              <For each={EXPORT_FORMATS}>
                {(format) => <option value={format}>{language.t(`reports.exportFormat.${format}`)}</option>}
              </For>
            </select>
            <Button
              size="small"
              variant="secondary"
              icon="download"
              disabled={!hasData() || exporting()}
              onClick={() => void handleExportArtifact(exportFormat())}
            >
              {language.t("reports.exportSelected")}
            </Button>
            <Button
              size="small"
              variant="secondary"
              icon="context"
              disabled={!hasData()}
              onClick={handleExportMarkdown}
            >
              {language.t("reports.exportMarkdown")}
            </Button>
            <Button
              size="small"
              variant="secondary"
              icon="magnifying-glass"
              disabled={!hasData()}
              onClick={handleExportHtml}
            >
              {language.t("reports.exportHtml")}
            </Button>
            <Button size="small" variant="secondary" icon="download" disabled={!hasData()} onClick={handleExportJson}>
              {language.t("reports.exportJson")}
            </Button>
          </div>
        }
      />

      <Show when={metaEditorOpen()}>
        <div class="mx-auto w-full max-w-5xl px-6 pt-4 print:hidden">
          <div class="rounded-sm border border-border-weaker-base bg-bg-surface p-4 shadow-xs">
            <div class="flex items-center justify-between">
              <h3 class="text-sm font-semibold text-text-primary">{language.t("reports.meta.heading")}</h3>
              <span
                class="text-xs text-text-tertiary transition-opacity"
                classList={{ "opacity-100": metaSaved(), "opacity-0": !metaSaved() }}
              >
                {language.t("reports.meta.saved")}
              </span>
            </div>
            <div class="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-3">
              <TextField
                value={meta.legalName}
                onChange={(v: string) => {
                  setMeta("legalName", v)
                  flashMetaSaved()
                }}
                placeholder={language.t("reports.meta.legalNamePlaceholder")}
                label={language.t("reports.meta.legalName")}
              />
              <TextField
                value={meta.classification}
                onChange={(v: string) => {
                  setMeta("classification", v)
                  flashMetaSaved()
                }}
                placeholder={language.t("reports.meta.classificationPlaceholder")}
                label={language.t("reports.meta.classification")}
              />
              <TextField
                value={meta.leadAuditor}
                onChange={(v: string) => {
                  setMeta("leadAuditor", v)
                  flashMetaSaved()
                }}
                placeholder={language.t("reports.meta.leadAuditorPlaceholder")}
                label={language.t("reports.meta.leadAuditor")}
              />
            </div>
            <div class="mt-3 flex items-center gap-3 flex-wrap">
              <input
                ref={logoInput}
                type="file"
                accept="image/*"
                class="hidden"
                onChange={(e) => {
                  void handleLogoSelect((e.target as HTMLInputElement).files?.[0])
                  ;(e.target as HTMLInputElement).value = ""
                }}
              />
              <Button size="small" variant="secondary" icon="upload" onClick={() => logoInput?.click()}>
                {language.t("reports.meta.logoUpload")}
              </Button>
              <Show when={meta.logoDataUrl}>
                <img src={meta.logoDataUrl} alt="" class="h-8 max-w-32 object-contain" />
                <Button
                  size="small"
                  variant="ghost"
                  onClick={() => {
                    setMeta("logoDataUrl", "")
                    flashMetaSaved()
                  }}
                >
                  {language.t("reports.meta.logoClear")}
                </Button>
              </Show>
              <span class="text-xs text-text-tertiary">{language.t("reports.meta.logoHint")}</span>
            </div>
          </div>
        </div>
      </Show>

      <Show
        when={hasData()}
        fallback={
          <EmptyState
            icon={<PixelIcon name="checklist" size={36} class="text-text-tertiary" />}
            title={language.t("reports.empty.title")}
            description={language.t("reports.empty.body")}
          />
        }
      >
        <div class="flex-1 overflow-y-auto px-6 pb-10 print:px-0 print:overflow-visible">
          <div class="report-container flex flex-col gap-6 max-w-220 mx-auto pt-6">
            {/* Portada para impresión / Banner de Confidencialidad */}
            <SurfaceCard class="report-cover flex flex-col gap-3 p-6 report-card shadow-xs rounded-sm">
              <div class="flex items-center justify-between">
                {/* audit-allow: pill de clasificación del informe (no es nivel de severidad: usa border-severity-border-critical en vez del border-border-strong de SEV_BADGE); migrarla a SeverityBadge cambiaría el borde */}
                <span class="inline-flex items-center gap-1 rounded-sm px-2.5 py-0.5 text-10-mono font-bold bg-severity-bg-critical text-severity-fg-critical border border-severity-border-critical tracking-wider uppercase">
                  {report().classification}
                </span>
                <span class="font-mono text-xs tabular-nums text-text-secondary">{report().generatedAt}</span>
              </div>

              <h1 class="font-display mt-2 text-3xl font-bold uppercase leading-[0.9] tracking-tight text-text-primary">
                {report().title}
              </h1>
              <p class="font-serif text-sm text-text-secondary">
                {language.t("reports.client")}: <strong>{report().clientName}</strong> · {language.t("reports.scope")}:{" "}
                <strong>{report().scope}</strong>
              </p>

              <div class="grid grid-cols-2 md:grid-cols-4 gap-3 pt-3 border-t border-border-weaker-base text-xs font-mono text-text-secondary">
                <div>
                  <span class="block uppercase text-10-mono text-text-tertiary font-bold">
                    {language.t("reports.approvals.leadAuditor")}
                  </span>
                  <span class="text-text-primary">{report().leadAuditor}</span>
                </div>
                <div>
                  <span class="block uppercase text-10-mono text-text-tertiary font-bold">
                    {language.t("reports.methodology")}
                  </span>
                  <span class="text-text-primary truncate block">{report().methodology}</span>
                </div>
                <div>
                  <span class="block uppercase text-10-mono text-text-tertiary font-bold">
                    {language.t("reports.globalRisk")}
                  </span>
                  <span class={`font-bold ${SEV_COLOR[summary().globalRiskLevel.toLowerCase() as Severity]}`}>
                    {summary().globalRiskLevel}
                  </span>
                </div>
                <div>
                  <span class="block uppercase text-10-mono text-text-tertiary font-bold">
                    {language.t("reports.metadata.version")}
                  </span>
                  <span class="text-text-primary">
                    v{report().metadata.version} ({report().metadata.engine})
                  </span>
                </div>
              </div>
            </SurfaceCard>

            {/* Resumen Ejecutivo Narrativo */}
            <div class="rounded-sm border border-border-weaker-base bg-bg-surface p-5 report-card flex flex-col gap-3 shadow-xs">
              <div class="flex items-center gap-3">
                <div class="flex h-9 w-9 shrink-0 items-center justify-center rounded-sm border border-border-weaker-base bg-bg-base text-accent">
                  <PixelIcon name="shield" size={24} />
                </div>
                <h2 class="font-display text-lg font-bold uppercase tracking-tight text-text-primary">
                  {language.t("reports.executiveSummary.title")}
                </h2>
              </div>
              <p class="font-serif text-sm text-text-primary leading-relaxed">{summary().executiveNarrative}</p>
            </div>

            {/* KPI Cards */}
            <div class="grid grid-cols-2 lg:grid-cols-4 gap-3">
              <KpiCard label={language.t("reports.kpi.findings")} value={summary().totalFindings} icon="shield" />
              <KpiCard
                label={language.t("reports.kpi.critical")}
                value={summary().criticalCount}
                accent="var(--severity-fg-critical)"
                icon="alert-circle"
              />
              <KpiCard label={language.t("reports.kpi.targets")} value={summary().totalTargets} icon="target" />
              <KpiCard label={language.t("reports.kpi.sessions")} value={report().sessionCount} icon="console" />
            </div>

            {/* CVSS basado en vectores explícitos + distribución de severidad */}
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-3">
              <SurfaceCard class="flex flex-col gap-2 p-4 report-card">
                <span class="text-sm font-medium text-text-primary">{language.t("reports.cvssAverageScore")}</span>
                <Show
                  when={cvss()}
                  fallback={<div class="text-sm text-text-secondary">{language.t("reports.cvssUnavailable")}</div>}
                >
                  {(average) => (
                    <>
                      <div class="flex-1 flex items-center">
                        <CvssBadge score={average().baseScore} severity={average().severity} />
                      </div>
                      <div class="text-xs font-mono text-text-secondary truncate mt-1">
                        {language.t("reports.cvssScoredFindings", { count: summary().cvssScoredFindings })}
                      </div>
                    </>
                  )}
                </Show>
              </SurfaceCard>

              <div class="lg:col-span-2">
                <SeverityBar distribution={counts()} total={allFindings().length} />
              </div>
            </div>

            {/* Plan de Remediación Priorizado (Roadmap) */}
            <div class="report-section-break flex flex-col gap-3">
              <div class="flex items-center gap-3">
                <div class="flex h-9 w-9 shrink-0 items-center justify-center rounded-[4px] border border-border-weaker-base bg-bg-base text-accent">
                  <PixelIcon name="checklist" size={24} />
                </div>
                <h2 class="font-display text-lg font-bold uppercase tracking-tight text-text-primary">
                  {language.t("reports.roadmap.title")}
                </h2>
              </div>
              <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
                <For each={summary().remediationRoadmap}>{(phase) => <RoadmapPhaseCard phase={phase} />}</For>
              </div>
            </div>

            {/* Vulnerabilidades más frecuentes y Objetivos Evaluados */}
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {/* Top Vulnerabilities */}
              <OpsCard
                class="overflow-hidden report-card"
                headerClass="px-4 py-3 border-b border-border-weaker-base"
                contentClass="p-2"
                title={
                  <span class="text-sm font-medium text-text-primary">{language.t("reports.topVulnerabilities")}</span>
                }
              >
                <Show
                  when={summary().topVulnerabilities.length > 0}
                  fallback={
                    <div class="py-6 text-center text-xs text-text-secondary">
                      {language.t("reports.noVulnerabilities")}
                    </div>
                  }
                >
                  <For each={summary().topVulnerabilities}>{(vuln) => <TopVulnRow vuln={vuln} />}</For>
                </Show>
              </OpsCard>

              {/* Targets / Endpoints */}
              <OpsCard
                class="overflow-hidden report-card"
                headerClass="px-4 py-3 border-b border-border-weaker-base"
                contentClass="p-2"
                title={
                  <span class="text-sm font-medium text-text-primary">
                    {language.t("reports.targetsEvaluated", { count: summary().targets.length })}
                  </span>
                }
              >
                <Show
                  when={summary().targets.length > 0}
                  fallback={
                    <div class="py-6 text-center text-xs text-text-secondary">{language.t("reports.noTargets")}</div>
                  }
                >
                  <For each={summary().targets}>{(target) => <TargetRow target={target} />}</For>
                </Show>
              </OpsCard>
            </div>

            {/* Detalle Técnico Extenso de Hallazgos */}
            <div class="report-section-break flex flex-col gap-4">
              <div class="flex items-center gap-3">
                <div class="flex h-9 w-9 shrink-0 items-center justify-center rounded-[4px] border border-border-weaker-base bg-bg-base text-accent">
                  <PixelIcon name="search" size={24} />
                </div>
                <h2 class="font-display text-lg font-bold uppercase tracking-tight text-text-primary">
                  {language.t("reports.technicalDetail")}
                </h2>
              </div>
              <div class="flex flex-col gap-4">
                <For each={report().findings}>{(finding) => <FindingDetailedCard finding={finding} />}</For>
              </div>
            </div>

            {/* Control de Aprobaciones y Emisión */}
            <div class="rounded-sm border border-border-weaker-base bg-bg-surface p-5 report-card flex flex-col gap-3 mt-4 shadow-xs">
              <span class="text-sm font-semibold text-text-primary">{language.t("reports.approvals.title")}</span>
              <p class="text-xs text-text-secondary">{language.t("reports.approvals.disclaimer")}</p>
              <div class="grid grid-cols-1 md:grid-cols-2 gap-3 pt-3 border-t border-border-weaker-base text-xs font-mono">
                <div>
                  <span class="text-text-tertiary font-bold uppercase text-10-mono block">
                    {language.t("reports.approvals.leadAuditor")}:
                  </span>
                  <div class="text-text-primary font-semibold mt-0.5">{report().leadAuditor}</div>
                  <div class="text-10-mono text-accent mt-0.5">{language.t("reports.approvals.verified")}</div>
                </div>
                <div>
                  <span class="text-text-tertiary font-bold uppercase text-10-mono block">
                    {language.t("reports.client")}:
                  </span>
                  <div class="text-text-primary font-semibold mt-0.5">{report().clientName}</div>
                  <div class="text-10-mono text-text-secondary mt-0.5">
                    {language.t("reports.date")}: {report().generatedAt}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </Show>
    </div>
  )
}

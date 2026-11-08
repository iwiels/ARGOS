import { createEffect, createMemo, createSignal, createUniqueId, For, Show } from "solid-js"
import { useCopyToClipboard } from "@argos/ui/hooks"
import { showToast } from "@/utils/toast"
import type { CockpitFinding } from "../cockpit-types"
import "@/pages/reports-print.css"

function getSeverityBadgeStyle(severity: string) {
  switch (severity) {
    case "critical":
    case "high":
      return { dot: "bg-severity-fg-high", text: "text-severity-fg-high" }
    case "medium":
      return { dot: "bg-severity-fg-medium", text: "text-severity-fg-medium" }
    case "low":
      return { dot: "bg-severity-fg-low", text: "text-severity-fg-low" }
    case "info":
    default:
      return { dot: "bg-severity-fg-info", text: "text-severity-fg-info" }
  }
}

export function ExecutiveReportCockpitTab(props: {
  findings: CockpitFinding[]
  onInspectFinding: (id: string) => void
  targetScope?: string
}) {
  const { copy: copyToClipboard } = useCopyToClipboard()
  const reportId = createUniqueId()

  const [scope, setScope] = createSignal(props.targetScope || "")
  const [auditor, setAuditor] = createSignal("")
  const [client, setClient] = createSignal("")
  const [tlp, setTlp] = createSignal("Sin clasificar")
  const [signed, setSigned] = createSignal(false)
  const [signedDate, setSignedDate] = createSignal<string | null>(null)
  const [clientSigned, setClientSigned] = createSignal(false)

  createEffect(() => {
    if (props.targetScope) {
      setScope(props.targetScope)
    }
  })

  const handleMarkReviewed = () => {
    setSigned(true)
    setSignedDate(new Date().toLocaleString("es-ES"))
    showToast({
      title: "Borrador revisado en esta ventana",
      description: "La revisión no se ha guardado ni representa una firma digital.",
    })
  }

  const handleClientSign = () => {
    setClientSigned(true)
    showToast({
      title: "Recepción marcada en esta ventana",
      description: "La marca es local y no se ha persistido como firma.",
    })
  }

  const escapeMd = (val: string) => val.replace(/\|/g, "\\|")

  const exportMarkdown = async () => {
    const md = [
      `# Informe ejecutivo de auditoría de seguridad — ${scope() || "Alcance no indicado"}`,
      `Clasificación: ${tlp()}`,
      `Auditor líder: ${auditor() || "No indicado"}`,
      `Cliente: ${client() || "No indicado"}`,
      `Fecha: ${new Date().toLocaleDateString("es-ES")}`,
      "",
      "## 01 Resumen ejecutivo y postura de riesgo",
      `Total de hallazgos evaluados: ${props.findings.length}`,
      "",
      "## 02 Matriz consolidada de hallazgos",
      "| ID | Severidad | CVSS | CWE | ATT&CK | Título | Estado |",
      "|---|---|---|---|---|---|---|",
      ...props.findings.map(
        (f) =>
          `| ${escapeMd(f.shortId)} | ${escapeMd(f.severityLabel)} | ${f.cvss?.toFixed(1) ?? "—"} | ${escapeMd(f.cwe ?? "—")} | ${escapeMd(f.mitre.map((m) => m.id).join(", ") || "—")} | ${escapeMd(f.title)} | ${escapeMd(f.status)} |`,
      ),
      "",
      "## 03 Revisión del borrador",
      `Auditor: ${auditor() || "No indicado"} (${signed() ? "Revisión local no persistida" : "Pendiente"})`,
      `Receptor: ${client() || "No indicado"} (${clientSigned() ? "Marca local no persistida" : "Pendiente"})`,
    ].join("\n")

    try {
      await copyToClipboard(md)
      showToast({ title: "Reporte Markdown copiado al portapapeles" })
    } catch {
      showToast({ title: "Error al exportar a Markdown" })
    }
  }

  const scoredFindings = createMemo(() => props.findings.flatMap((f) => f.cvss === undefined ? [] : [f.cvss]))
  const maxCvss = createMemo(() => scoredFindings().length > 0 ? Math.max(...scoredFindings()) : undefined)

  const avgCvss = createMemo(() => {
    if (scoredFindings().length === 0) return "—"
    const sum = scoredFindings().reduce((acc, score) => acc + score, 0)
    return (sum / scoredFindings().length).toFixed(1)
  })

  // Fases de remediación
  const phase1Findings = createMemo(() => props.findings.filter((f) => f.severity === "critical"))
  const phase2Findings = createMemo(() =>
    props.findings.filter((f) => f.severity === "high" || (f.severity === "medium" && f.cvss !== undefined && f.cvss >= 7.0)),
  )
  const phase3Findings = createMemo(() =>
    props.findings.filter((f) => f.severity === "low" || f.severity === "info" || (f.severity === "medium" && f.cvss !== undefined && f.cvss < 7.0)),
  )
  const unscoredFindings = createMemo(() => props.findings.filter((f) => f.cvss === undefined))
  const surfaceCount = createMemo(() => {
    const set = new Set(props.findings.map((f) => f.target).filter(Boolean))
    return set.size
  })

  return (
    <section class="flex-1 overflow-y-auto min-h-0 p-4 sm:p-6 print:overflow-visible print:h-auto print:p-0">
      <div class="max-w-4xl mx-auto space-y-6 pb-16 print:pb-0 print:space-y-4">
        {/* Banner de confirmación del borrador (no-print) */}
        <div class="no-print print:hidden rounded-sm border border-border-default bg-bg-surface px-4 py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-xs">
          <div>
            <p class="text-xs font-semibold text-text-primary">
            {signed() ? "Borrador revisado en esta ventana" : "Borrador — revisión y metadatos pendientes"}
            </p>
            <p class="mt-0.5 text-xs text-text-secondary">
              {signed()
                ? `Marcado como revisado el ${signedDate()}; esta marca no se ha guardado.`
                : `El borrador usa ${props.findings.length} hallazgos recibidos. Completa los metadatos antes de exportarlo.`}
            </p>
          </div>
          <button
            type="button"
            onClick={handleMarkReviewed}
            class={`shrink-0 self-start sm:self-auto px-3 py-1.5 rounded-sm border text-xs font-medium transition-colors ${
              signed()
                ? "border-severity-fg-low/50 text-severity-fg-low bg-bg-base"
                : "border-border-strong text-text-primary hover:bg-bg-elevated"
            }`}
          >
            {signed() ? "Revisado localmente ✓" : "Marcar borrador como revisado"}
          </button>
        </div>

        {/* Documento oficial pericial */}
        <article class="bg-bg-surface border border-border-weaker-base rounded-sm p-4 sm:p-8 space-y-8 shadow-sm print:border-none print:shadow-none print:p-0">
          {/* Cabecera y metadatos */}
          <div class="space-y-5">
            <div class="flex flex-wrap items-center justify-between gap-3">
              <div class="flex items-center gap-3">
                <span class="font-mono text-11-mono text-severity-fg-medium font-semibold">
                  {tlp()}
                </span>
                <span class="font-mono text-11-mono text-text-tertiary">
                  {"Borrador local · ID no asignado"}
                </span>
              </div>
              <div class="no-print flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => void exportMarkdown()}
                  class="px-2.5 py-1.5 rounded-sm border border-border-weaker-base text-xs text-text-secondary hover:text-text-primary hover:border-border-strong transition-colors"
                >
                  {"Exportar .MD"}
                </button>
                <button
                  type="button"
                  onClick={() => window.print()}
                  class="px-2.5 py-1.5 rounded-sm border border-border-weaker-base text-xs text-text-secondary hover:text-text-primary hover:border-border-strong transition-colors"
                >
                  {"Imprimir / PDF"}
                </button>
              </div>
            </div>

            <div>
              <h2 class="text-xl font-bold tracking-tight text-text-primary">
                {"Informe ejecutivo de auditoría de seguridad"}
              </h2>
              <p class="mt-1 text-sm text-text-secondary">
                {`${new Date().toLocaleDateString("es-ES", { day: "numeric", month: "long", year: "numeric" })} · ${scope()}`}
              </p>
            </div>

            {/* Cuadrícula de metadatos configurables */}
            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 pt-2">
              <div class="space-y-1">
                <label for={`${reportId}-scope`} class="text-11-mono text-text-tertiary block">{"Alcance auditado"}</label>
                <input
                  id={`${reportId}-scope`}
                  type="text"
                  value={scope()}
                  onInput={(e) => setScope((e.target as HTMLInputElement).value)}
                  class="w-full bg-bg-base border border-border-weaker-base rounded-sm px-2.5 py-1.5 text-xs text-text-primary focus:outline-none focus:border-border-strong transition-colors"
                />
              </div>
              <div class="space-y-1">
                <label for={`${reportId}-auditor`} class="text-11-mono text-text-tertiary block">{"Auditor líder"}</label>
                <input
                  id={`${reportId}-auditor`}
                  type="text"
                  value={auditor()}
                  onInput={(e) => setAuditor((e.target as HTMLInputElement).value)}
                  class="w-full bg-bg-base border border-border-weaker-base rounded-sm px-2.5 py-1.5 text-xs text-text-primary focus:outline-none focus:border-border-strong transition-colors"
                />
              </div>
              <div class="space-y-1">
                <label for={`${reportId}-client`} class="text-11-mono text-text-tertiary block">{"Razón social / Cliente"}</label>
                <input
                  id={`${reportId}-client`}
                  type="text"
                  value={client()}
                  onInput={(e) => setClient((e.target as HTMLInputElement).value)}
                  class="w-full bg-bg-base border border-border-weaker-base rounded-sm px-2.5 py-1.5 text-xs text-text-primary focus:outline-none focus:border-border-strong transition-colors"
                />
              </div>
              <div class="space-y-1">
                <label for={`${reportId}-classification`} class="text-11-mono text-text-tertiary block">{"Clasificación"}</label>
                <select
                  id={`${reportId}-classification`}
                  value={tlp()}
                  onChange={(e) => setTlp((e.target as HTMLSelectElement).value)}
                  class="w-full bg-bg-base border border-border-weaker-base rounded-sm px-2.5 py-1.5 text-xs text-text-primary focus:outline-none focus:border-border-strong transition-colors"
                >
                  <option value="Sin clasificar">{"Sin clasificar"}</option>
                  <option value="CONFIDENCIAL — TLP:AMBER">{"CONFIDENCIAL — TLP:AMBER"}</option>
                  <option value="ESTRICTO — TLP:RED">{"ESTRICTO — TLP:RED"}</option>
                  <option value="INTERNO — TLP:GREEN">{"INTERNO — TLP:GREEN"}</option>
                </select>
              </div>
            </div>
          </div>

          {/* 01 Resumen ejecutivo y postura de riesgo */}
          <div class="space-y-4">
            <h3 id={`${reportId}-matrix-heading`} class="pb-2 border-b border-border-weaker-base text-sm font-semibold text-text-primary">
              <span class="font-medium text-text-tertiary mr-2">{"01"}</span>
              {"Resumen ejecutivo y postura de riesgo"}
            </h3>
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div class="lg:col-span-2 space-y-3 text-sm text-text-secondary leading-relaxed">
                <p>
                  {"El expediente contiene "}
                  <strong class="font-medium text-text-primary">{`${phase1Findings().length + phase2Findings().length} hallazgos en prioridad 1 y 2`}</strong>
                  {` entre ${props.findings.length} hallazgos recibidos. Las prioridades se basan en la severidad y el CVSS que proporcionó cada fuente; no implican una reproducción independiente.`}
                </p>
                <p>
                  {`${scoredFindings().length} de ${props.findings.length} hallazgos incluyen una puntuación CVSS. Los campos que no aparecen en el expediente no se han inferido.`}
                </p>
              </div>

              {/* Métricas clave */}
              <div class="grid grid-cols-2 gap-px bg-border-weaker-base border border-border-weaker-base rounded-sm overflow-hidden">
                <div class="bg-bg-surface p-3.5">
                  <div class="text-10-mono text-text-tertiary uppercase">{"CVSS máx. (v3.1)"}</div>
                  <div class="mt-1 text-2xl font-bold tracking-tight text-severity-fg-high">
                    {maxCvss()?.toFixed(1) ?? "—"}
                  </div>
                  <div class="mt-0.5 text-[10px] text-text-tertiary">{`${scoredFindings().length} con puntuación`}</div>
                </div>
                <div class="bg-bg-surface p-3.5">
                  <div class="text-10-mono text-text-tertiary uppercase">{"CVSS promedio"}</div>
                  <div class="mt-1 text-2xl font-bold tracking-tight text-text-primary">
                    {avgCvss()}
                  </div>
                  <div class="mt-0.5 text-[10px] text-text-tertiary">{"Media aritmética de los puntuados"}</div>
                </div>
                <div class="bg-bg-surface p-3.5">
                  <div class="text-10-mono text-text-tertiary uppercase">{"Targets registrados"}</div>
                  <div class="mt-1 text-2xl font-bold tracking-tight text-text-primary">
                    {surfaceCount()}
                  </div>
                  <div class="mt-0.5 text-[10px] text-text-tertiary">{"Targets distintos informados"}</div>
                </div>
                <div class="bg-bg-surface p-3.5">
                  <div class="text-10-mono text-text-tertiary uppercase">{"Sin puntuación CVSS"}</div>
                  <div class="mt-1 text-2xl font-bold tracking-tight text-text-primary">
                    {unscoredFindings().length}
                  </div>
                  <div class="mt-0.5 text-[10px] text-text-tertiary">{"Requieren valoración"}</div>
                </div>
              </div>
            </div>
          </div>

          {/* 02 Plan de remediación priorizado */}
          <div class="space-y-4">
            <h3 class="pb-2 border-b border-border-weaker-base text-sm font-semibold text-text-primary">
              <span class="font-medium text-text-tertiary mr-2">{"02"}</span>
              {"Plan de remediación priorizado"}
            </h3>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
              {/* Fase 1 */}
              <div class="space-y-3">
                <div class="flex items-baseline justify-between gap-2">
                  <h4 class="text-sm font-medium text-text-primary">{"Prioridad 1 · Severidad crítica"}</h4>
                  <span class="text-11-mono text-text-tertiary">{`${phase1Findings().length} hallazgos`}</span>
                </div>
                <p class="text-xs text-text-secondary leading-relaxed">
                  {"Clasificación basada en la severidad registrada. Confirma evidencia y contexto antes de definir acciones o plazos."}
                </p>
                <Show
                  when={phase1Findings().length > 0}
                  fallback={
                    <div class="rounded-sm bg-bg-base border border-border-weaker-base p-2.5 text-xs text-text-secondary">
                      {"No hay hallazgos críticos registrados en el expediente."}
                    </div>
                  }
                >
                  <For each={phase1Findings()}>
                    {(f) => (
                      <button
                        type="button"
                        onClick={() => props.onInspectFinding(f.id)}
                        class="w-full text-left rounded-sm border border-border-weaker-base p-2.5 hover:border-border-strong transition-colors bg-bg-base/60"
                      >
                        <div class="flex items-center justify-between font-mono text-[10px] text-text-tertiary">
                          <span class="font-semibold text-severity-fg-high">{`CRÍTICA · ${f.cwe ?? "CWE no disponible"}`}</span>
                        </div>
                        <p class="mt-1 text-xs font-medium text-text-primary truncate">{f.title}</p>
                      </button>
                    )}
                  </For>
                </Show>
              </div>

              {/* Fase 2 */}
              <div class="space-y-3">
                <div class="flex items-baseline justify-between gap-2">
                  <h4 class="text-sm font-medium text-text-primary">{"Prioridad 2 · Alta o CVSS medio ≥ 7"}</h4>
                  <span class="text-11-mono text-severity-fg-high font-semibold">
                    {`${phase2Findings().length} prioritarios`}
                  </span>
                </div>
                <div class="space-y-2">
                  <For each={phase2Findings()}>
                    {(f) => (
                      <button
                        type="button"
                        onClick={() => props.onInspectFinding(f.id)}
                        class="w-full text-left rounded-sm border border-border-weaker-base p-2.5 hover:border-border-strong transition-colors bg-bg-base/60"
                      >
                        <div class="flex items-center justify-between font-mono text-[10px] text-text-tertiary">
                          <span class="font-semibold text-severity-fg-high">
                            {`${f.severityLabel} (CVSS ${f.cvss?.toFixed(1) ?? "—"}) · ${f.cwe ?? "CWE no disponible"}`}
                          </span>
                        </div>
                        <p class="mt-1 text-xs font-medium text-text-primary truncate">{f.title}</p>
                      </button>
                    )}
                  </For>
                </div>
              </div>

              {/* Fase 3 */}
              <div class="space-y-3">
                <div class="flex items-baseline justify-between gap-2">
                  <h4 class="text-sm font-medium text-text-primary">{"Prioridad 3 · Seguimiento"}</h4>
                  <span class="text-11-mono text-text-tertiary">{`${phase3Findings().length} hallazgos`}</span>
                </div>
                <div class="space-y-2">
                  <For each={phase3Findings().slice(0, 4)}>
                    {(f) => (
                      <button
                        type="button"
                        onClick={() => props.onInspectFinding(f.id)}
                        class="w-full text-left rounded-sm border border-border-weaker-base p-2.5 hover:border-border-strong transition-colors bg-bg-base/60"
                      >
                        <div class="flex items-center justify-between font-mono text-[10px] text-text-tertiary">
                          <span class="font-semibold text-text-secondary">
                            {`${f.severityLabel} · ${f.cwe ?? "CWE no disponible"}`}
                          </span>
                        </div>
                        <p class="mt-1 text-xs font-medium text-text-primary truncate">{f.title}</p>
                      </button>
                    )}
                  </For>
                </div>
              </div>
            </div>
            <Show when={unscoredFindings().length > 0}>
              <div class="rounded-sm border border-border-weaker-base bg-bg-base/50 p-3 space-y-2">
                <h4 class="text-xs font-medium text-text-primary">{"Hallazgos sin puntuación CVSS"}</h4>
                <p class="text-xs text-text-secondary">{"No se asigna una prioridad CVSS hasta que la fuente proporcione una puntuación."}</p>
                <For each={unscoredFindings()}>
                  {(finding) => (
                    <button type="button" onClick={() => props.onInspectFinding(finding.id)} class="block text-left text-xs text-text-secondary hover:text-text-primary">
                      {finding.title}
                    </button>
                  )}
                </For>
              </div>
            </Show>
          </div>

          {/* 03 Matriz consolidada de hallazgos */}
          <div class="space-y-4">
            <h3 class="pb-2 border-b border-border-weaker-base text-sm font-semibold text-text-primary">
              <span class="font-medium text-text-tertiary mr-2">{"03"}</span>
              {"Matriz consolidada de hallazgos"}
            </h3>
            <div class="overflow-x-auto">
              <table aria-labelledby={`${reportId}-matrix-heading`} class="w-full text-left border-collapse">
                <thead>
                  <tr class="border-b border-border-weaker-base">
                    <th class="py-2 px-3 text-10-mono uppercase font-medium text-text-tertiary">{"ID"}</th>
                    <th class="py-2 px-3 text-10-mono uppercase font-medium text-text-tertiary">{"Severidad"}</th>
                    <th class="py-2 px-3 text-10-mono uppercase font-medium text-text-tertiary">{"CVSS"}</th>
                    <th class="py-2 px-3 text-10-mono uppercase font-medium text-text-tertiary">{"CWE"}</th>
                    <th class="py-2 px-3 text-10-mono uppercase font-medium text-text-tertiary">{"ATT&CK"}</th>
                    <th class="py-2 px-3 text-10-mono uppercase font-medium text-text-tertiary">{"Título"}</th>
                    <th class="py-2 px-3 text-10-mono uppercase font-medium text-text-tertiary text-right">{"Estado"}</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-border-weaker-base font-mono text-xs">
                  <For each={props.findings}>
                    {(f) => {
                      const st = getSeverityBadgeStyle(f.severity)
                      return (
                        <tr class="hover:bg-bg-elevated transition-colors">
                          <td class="py-2.5 px-3 font-semibold text-text-primary">{f.shortId}</td>
                          <td class="py-2.5 px-3">
                            <span class={`inline-flex items-center gap-1.5 ${st.text}`}>
                              <span class={`size-1.5 rounded-full ${st.dot}`} />
                              {f.severityLabel}
                            </span>
                          </td>
                          <td class={`py-2.5 px-3 font-medium ${f.cvss !== undefined && f.cvss >= 7 ? "text-severity-fg-high" : "text-text-secondary"}`}>
                            {f.cvss?.toFixed(1) ?? "—"}
                          </td>
                          <td class="py-2.5 px-3 text-text-tertiary">{f.cwe ?? "—"}</td>
                          <td class="py-2.5 px-3 text-text-tertiary truncate max-w-28">
                            {f.mitre.map((m) => m.id).join(", ") || "—"}
                          </td>
                          <td class="py-2.5 px-3 font-sans text-xs text-text-primary max-w-xs">
                            <button
                              type="button"
                              onClick={() => props.onInspectFinding(f.id)}
                              aria-label={`Abrir hallazgo ${f.shortId}: ${f.title}`}
                              class="max-w-full truncate text-left hover:underline focus-visible:underline"
                            >
                              {f.title}
                            </button>
                          </td>
                          <td class="py-2.5 px-3 text-right text-text-secondary">{f.status || "—"}</td>
                        </tr>
                      )
                    }}
                  </For>
                </tbody>
              </table>
            </div>
          </div>

          {/* 04 Revisión local del borrador */}
          <div class="space-y-4">
            <h3 class="pb-2 border-b border-border-weaker-base text-sm font-semibold text-text-primary">
              <span class="font-medium text-text-tertiary mr-2">{"04"}</span>
              {"Revisión local del borrador"}
            </h3>
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div class="border border-border-weaker-base rounded-sm p-4 space-y-1 bg-bg-base/40">
                <div class="text-11-mono text-text-tertiary">{"Auditor responsable"}</div>
                <div class="text-sm font-medium text-text-primary">{auditor() || "No indicado"}</div>
                <div class="text-xs text-text-secondary">
                  {signedDate() || "Revisión pendiente"}
                </div>
                <span class="inline-block pt-1 font-mono text-10-mono text-text-tertiary font-semibold">
                  {signed() ? "Revisado en esta ventana; no guardado" : "Pendiente"}
                </span>
              </div>

              <div class="border border-border-weaker-base rounded-sm p-4 flex items-start justify-between gap-3 bg-bg-base/40">
                <div class="space-y-1 min-w-0">
                  <div class="text-11-mono text-text-tertiary">{"Receptor de seguridad"}</div>
                  <div class="text-sm font-medium text-text-primary break-words">{client() || "No indicado"}</div>
                  <div class="text-xs text-text-secondary">
                    {clientSigned() ? "Marca local; no guardada" : "Pendiente"}
                  </div>
                </div>
                <button
                  type="button"
                  onClick={handleClientSign}
                  disabled={clientSigned()}
                  class={`shrink-0 px-3 py-1.5 rounded-sm border text-xs font-medium transition-colors ${
                    clientSigned()
                      ? "border-severity-fg-low/50 text-severity-fg-low cursor-default"
                      : "border-border-strong text-text-primary hover:bg-bg-elevated"
                  }`}
                >
                  {clientSigned() ? "Marcado localmente" : "Marcar recepción local"}
                </button>
              </div>
            </div>
          </div>
        </article>
      </div>
    </section>
  )
}

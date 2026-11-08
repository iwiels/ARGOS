import { createMemo, createSignal, For, Show } from "solid-js"
import { NIST_DOMAINS, ISO_DOMAINS, deriveComplianceDomains } from "../cockpit-data"
import type { CockpitFinding, ComplianceFilter, ComplianceFramework, NistDomain } from "../cockpit-types"

function getSeverityBadgeStyle(status: NistDomain["status"]) {
  switch (status) {
    case "Deficiente":
      return { dot: "bg-severity-fg-high", text: "text-severity-fg-high" }
    case "Parcial":
    case "Requiere revisión":
      return { dot: "bg-severity-fg-medium", text: "text-severity-fg-medium" }
    case "Sin evaluar":
      return { dot: "bg-severity-fg-info", text: "text-severity-fg-info" }
    case "Cumple":
    default:
      return { dot: "bg-severity-fg-low", text: "text-severity-fg-low" }
  }
}

export function ComplianceCockpitTab(props: {
  findings: CockpitFinding[]
  onJumpToFinding: (shortId: string) => void
}) {
  const [framework, setFramework] = createSignal<ComplianceFramework>("NIST")
  const [statusFilter, setStatusFilter] = createSignal<ComplianceFilter>("all")
  const [activeDomain, setActiveDomain] = createSignal<string | null>(null)

  const currentDomains = createMemo<NistDomain[]>(() => {
    const rawDomains = framework() === "NIST" ? NIST_DOMAINS : ISO_DOMAINS
    return deriveComplianceDomains(rawDomains, props.findings)
  })

  const frameworkCounts = createMemo(() => {
    let review = 0
    let unassessed = 0
    for (const dom of currentDomains()) {
      for (const sub of dom.subcontrols) {
        if (sub.status === "Requiere revisión") review++
        else if (sub.status === "Sin evaluar") unassessed++
      }
    }
    return { review, unassessed }
  })

  const compliancePercentage = createMemo(() => {
    return frameworkCounts().review === 0 ? "Sin evaluar" : "Requiere revisión"
  })

  const totalsSummary = createMemo(() => {
    const { review, unassessed } = frameworkCounts()
    const total = currentDomains().reduce((acc, d) => acc + d.subcontrols.length, 0)
    return framework() === "NIST"
      ? `${review} controles con hallazgos vinculados requieren revisión; ${unassessed} de ${total} no tienen evidencia de evaluación.`
      : `${review} controles del Anexo A con hallazgos vinculados requieren revisión; ${unassessed} de ${total} no tienen evidencia de evaluación.`
  })

  const filteredSubcontrols = createMemo(() => {
    const list: { domain: NistDomain; sub: NistDomain["subcontrols"][number] }[] = []
    const selDomain = activeDomain()
    const filter = statusFilter()

    for (const dom of currentDomains()) {
      if (selDomain && dom.code !== selDomain) continue
      for (const sub of dom.subcontrols) {
        if (filter === "issues" && sub.status !== "Requiere revisión") continue
        if (filter !== "all" && filter !== "issues" && sub.status !== filter) continue
        list.push({ domain: dom, sub })
      }
    }
    return list
  })

  return (
    <section class="flex-1 overflow-y-auto min-h-0 p-4 sm:p-6">
      <div class="max-w-6xl mx-auto space-y-6 sm:space-y-8">
        {/* Cabecera del cumplimiento */}
        <div class="flex flex-wrap items-end justify-between gap-6">
          <div>
            <div class="flex items-baseline gap-2">
              <span class="text-3xl font-bold tracking-tight text-text-primary">
                {compliancePercentage()}
              </span>
              <span class="text-sm text-text-secondary">{"de cumplimiento normativo"}</span>
            </div>
            <p class="mt-1 text-sm text-text-secondary">
              {totalsSummary()}
            </p>
            <div class="mt-3 flex items-center gap-3 text-xs">
              <button
                type="button"
                onClick={() => {
                  setStatusFilter("Requiere revisión")
                  setActiveDomain(null)
                }}
                class="text-severity-fg-medium hover:underline underline-offset-2"
              >
                {`${frameworkCounts().review} requieren revisión`}
              </button>
              <span class="text-text-tertiary">·</span>
              <button
                type="button"
                onClick={() => {
                  setStatusFilter("Sin evaluar")
                  setActiveDomain(null)
                }}
                class="text-text-tertiary hover:underline underline-offset-2"
              >
                {`${frameworkCounts().unassessed} sin evaluar`}
              </button>
              <Show when={statusFilter() !== "all"}>
                <span class="text-text-tertiary">·</span>
                <button
                  type="button"
                  onClick={() => {
                    setStatusFilter("all")
                    setActiveDomain(null)
                  }}
                  class="text-text-primary underline underline-offset-2"
                >
                  {"Ver todos"}
                </button>
              </Show>
            </div>
          </div>

          <div class="flex items-center gap-3">
            {/* Selector de Marco */}
            <div class="inline-flex p-0.5 rounded-sm border border-border-weaker-base bg-bg-surface text-xs">
              <button
                type="button"
                onClick={() => {
                  setFramework("NIST")
                  setActiveDomain(null)
                }}
                class={`px-2.5 py-1 rounded-xs text-xs font-medium transition-colors ${
                  framework() === "NIST"
                    ? "bg-text-primary text-bg-base"
                    : "text-text-secondary hover:text-text-primary"
                }`}
              >
                {"NIST CSF 2.0"}
              </button>
              <button
                type="button"
                onClick={() => {
                  setFramework("ISO")
                  setActiveDomain(null)
                }}
                class={`px-2.5 py-1 rounded-xs text-xs font-medium transition-colors ${
                  framework() === "ISO"
                    ? "bg-text-primary text-bg-base"
                    : "text-text-secondary hover:text-text-primary"
                }`}
              >
                {"ISO 27001:2022"}
              </button>
            </div>

            <span class="text-xs text-text-tertiary">{"Catálogo local"}</span>
          </div>
        </div>

        {/* Cuadrícula de Pilares */}
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          <For each={currentDomains()}>
            {(dom) => {
              const st = getSeverityBadgeStyle(dom.status)
              const pct = dom.status === "Requiere revisión" ? 35 : 0
              const isActive = () => activeDomain() === dom.code

              return (
                <button
                  type="button"
                  onClick={() => setActiveDomain(isActive() ? null : dom.code)}
                  class={`text-left rounded-sm border p-4 transition-colors ${
                    isActive()
                      ? "border-text-primary bg-bg-elevated"
                      : "border-border-weaker-base bg-bg-surface hover:border-border-default"
                  }`}
                >
                  <div class="flex items-center justify-between">
                    <span class="font-mono text-xs font-semibold text-text-primary">{dom.code}</span>
                    <span class={`inline-flex items-center gap-1.5 text-xs ${st.text}`}>
                      <span class={`size-1.5 rounded-full ${st.dot}`} />
                      {dom.status}
                    </span>
                  </div>
                  <div class="mt-3 text-sm font-medium text-text-primary leading-snug">{dom.name}</div>
                  <div class="mt-0.5 text-xs text-text-secondary">{`${dom.score} subcategorías`}</div>
                  <div class="mt-3 h-1 rounded-full bg-bg-elevated overflow-hidden">
                    <div class={`${st.dot} h-full`} style={{ width: `${pct}%` }} />
                  </div>
                </button>
              )
            }}
          </For>
        </div>

        {/* Subcategorías y trazabilidad de hallazgos */}
        <div class="space-y-3">
          <div class="pb-2 flex flex-wrap items-center justify-between gap-2 border-b border-border-weaker-base">
            <h3 class="text-sm font-semibold text-text-primary">
              {"Subcategorías y trazabilidad de hallazgos"}
            </h3>
            <div class="flex items-center gap-4">
              <button
                type="button"
                onClick={() => setStatusFilter("all")}
                class={`text-xs ${
                  statusFilter() === "all"
                    ? "font-medium text-text-primary underline underline-offset-4"
                    : "text-text-tertiary hover:text-text-secondary"
                }`}
              >
                {`Todos (${currentDomains().reduce((acc, d) => acc + d.subcontrols.length, 0)})`}
              </button>
              <button
                type="button"
                onClick={() => setStatusFilter("issues")}
                class={`text-xs ${
                  statusFilter() === "issues"
                    ? "font-medium text-text-primary underline underline-offset-4"
                    : "text-text-tertiary hover:text-text-secondary"
                }`}
              >
                {"Solo brechas"}
              </button>
            </div>
          </div>

          <div class="divide-y divide-border-weaker-base border-t border-border-weaker-base">
            <For each={filteredSubcontrols()}>
              {({ sub }) => {
                const st = getSeverityBadgeStyle(sub.status)
                return (
                  <div class="py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div class="flex items-center gap-3 min-w-0">
                      <span class={`size-1.5 rounded-full shrink-0 ${st.dot}`} />
                      <span class="font-mono text-xs text-text-tertiary w-20 shrink-0">{sub.code}</span>
                      <span class="text-sm text-text-primary truncate">{sub.name}</span>
                    </div>

                    <div class="flex items-center gap-3 shrink-0">
                      <Show when={sub.findings.length > 0}>
                        <div class="flex items-center gap-1.5">
                          <For each={sub.findings}>
                            {(shortId) => (
                              <button
                                type="button"
                                onClick={() => props.onJumpToFinding(shortId)}
                                title={"Ver hallazgo pericial vinculado en Inspector"}
                                class="font-mono text-11-mono text-accent hover:text-accent/80 underline underline-offset-2 transition-colors px-1 py-0.5 rounded-xs bg-bg-elevated border border-border-weaker-base"
                              >
                                {shortId}
                              </button>
                            )}
                          </For>
                        </div>
                      </Show>
                      <span class={`text-xs w-20 text-right ${st.text}`}>{sub.status}</span>
                    </div>
                  </div>
                )
              }}
            </For>
            <Show when={filteredSubcontrols().length === 0}>
              <div class="py-10 text-center text-sm text-text-tertiary">
                {"Sin subcategorías para los filtros seleccionados."}
              </div>
            </Show>
          </div>
        </div>
      </div>
    </section>
  )
}

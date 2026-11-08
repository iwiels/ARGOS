import { createMemo, createSignal, For, Show } from "solid-js"
import { useLanguage } from "@/context/language"
import { useCopyToClipboard } from "@argos/ui/hooks"
import { showToast } from "@/utils/toast"
import { findingStatusLabelKey, nextLedgerStatus, type FeedbackVerdict } from "../../findings-data"
import type { CockpitFinding } from "./cockpit-types"

function getStatusBadgeStyle(status: string) {  const norm = status.toLowerCase().trim()
  switch (norm) {
    case "verified":
    case "validado":
    case "remediated":
    case "mitigado":
      return { dot: "bg-severity-fg-low", text: "text-severity-fg-low" }
    case "in-progress":
    case "sospechoso":
    case "suspected":
      return { dot: "bg-severity-fg-medium", text: "text-severity-fg-medium" }
    case "open":
    case "abierto":
      return { dot: "bg-severity-fg-high", text: "text-severity-fg-high" }
    case "false-positive":
    case "accepted-risk":
    case "observado":
    case "observed":
    default:
      return { dot: "bg-text-tertiary", text: "text-text-secondary" }
  }
}

const FEEDBACK_BUTTONS: { verdict: FeedbackVerdict; label: string; active: string }[] = [
  {
    verdict: "true-positive",
    label: "findings.feedback.truePositive",
    active: "border-severity-fg-low/60 bg-severity-fg-low/10 text-severity-fg-low",
  },
  {
    verdict: "false-positive",
    label: "findings.feedback.falsePositive",
    active: "border-text-tertiary/60 bg-bg-elevated text-text-secondary",
  },
  {
    verdict: "accepted-risk",
    label: "findings.feedback.acceptedRisk",
    active: "border-severity-fg-medium/60 bg-severity-fg-medium/10 text-severity-fg-medium",
  },
]

function feedbackTone(verdict: FeedbackVerdict) {
  switch (verdict) {
    case "true-positive":
      return "bg-severity-fg-low/10 text-severity-fg-low"
    case "false-positive":
      return "bg-bg-elevated text-text-tertiary"
    case "accepted-risk":
      return "bg-severity-fg-medium/10 text-severity-fg-medium"
  }
}

export function FindingInspector(props: {
  finding: CockpitFinding | undefined
  onStatusChange: (nextStatus: string) => void
  onFeedback?: (verdict: FeedbackVerdict) => Promise<void> | void
  feedbackPending?: boolean
  onReverify?: () => Promise<void> | void
  reverifying?: boolean
  reverifyMessage?: string
}) {
  const language = useLanguage()
  const { copy: copyToClipboard } = useCopyToClipboard()
  const [activeSubTab, setActiveSubTab] = createSignal<"poc" | "raw" | "curl">("poc")

  const f = () => props.finding

  const copyWithToast = async (text: string, label: string) => {
    try {
      await copyToClipboard(text)
      showToast({ title: label })
    } catch {
      showToast({ title: "Error al copiar al portapapeles" })
    }
  }

  const statusStyle = createMemo(() => (f() ? getStatusBadgeStyle(f()!.status) : { dot: "", text: "" }))
  const statusLabel = createMemo(() => {
    if (!f()) return ""
    const key = findingStatusLabelKey(f()!.status)
    return key ? language.t(key) : f()!.status
  })

  const feedbackLabel = (verdict: FeedbackVerdict) =>
    language.t(FEEDBACK_BUTTONS.find((option) => option.verdict === verdict)?.label ?? verdict)

  return (
    <Show
      when={f()}
      fallback={
        <div class="flex h-full items-center justify-center p-8 text-center text-text-tertiary">
          <p class="text-sm">{"Selecciona un hallazgo de la lista para inspeccionar la evidencia forense."}</p>
        </div>
      }
    >
      <div class="flex flex-col gap-6">
        {/* Encabezado pericial */}
        <div>
          <div class="flex items-center justify-between gap-2">
            <span class="font-mono text-xs text-text-secondary">
              {`${f()!.shortId} · ${f()!.cwe ?? "CWE no disponible"} · CVSS ${f()!.cvss?.toFixed(1) ?? "—"}`}
            </span>
            <button
              type="button"
              onClick={() => props.onStatusChange(nextLedgerStatus(f()!.status))}
              title={"Clic para avanzar el estado"}
              class="inline-flex items-center gap-1.5 text-xs transition-opacity hover:opacity-80"
            >
              <span class={`size-1.5 rounded-full ${statusStyle().dot}`} />
              <span class={statusStyle().text}>{statusLabel()}</span>
            </button>
          </div>

          <h3 class="mt-2 text-base font-semibold leading-snug text-text-primary">
            {f()!.title}
          </h3>

          <p class="mt-2 font-mono text-11-mono text-text-tertiary break-all">
            {f()!.vector ?? "Vector CVSS no disponible"}
          </p>

          <Show when={f()!.cvssImpactNote}>
            <p class="mt-1 text-xs text-text-secondary">
              {f()!.cvssImpactNote}
            </p>
          </Show>
        </div>

        {/* Triage del engagement (ARG-064): el veredicto vale para esta
            auditoría y no suprime la regla en otros engagements. */}
        <div class="rounded-sm border border-border-weaker-base bg-bg-surface/40 p-3 space-y-2">
          <div class="flex flex-wrap items-center justify-between gap-2">
            <h4 class="text-xs font-medium text-text-secondary">{language.t("findings.feedback.label")}</h4>
            <Show when={f()!.feedback}>
              {(feedback) => (
                <span
                  class={`inline-flex items-center gap-1.5 rounded-sm px-2 py-0.5 text-11-mono ${feedbackTone(feedback().verdict)}`}
                  title={feedback().reason}
                >
                  <span class="size-1.5 rounded-full bg-current" />
                  {feedbackLabel(feedback().verdict)}
                  <span class="text-text-tertiary">
                    {`· ${language.t(`findings.feedback.actor.${feedback().actor}`)}`}
                  </span>
                </span>
              )}
            </Show>
          </div>
          <div class="flex flex-wrap gap-1.5">
            <For each={FEEDBACK_BUTTONS}>
              {(option) => (
                <button
                  type="button"
                  disabled={!f()!.persisted || props.feedbackPending}
                  onClick={() => void props.onFeedback?.(option.verdict)}
                  class={`rounded-sm border px-2.5 py-1 text-xs transition-colors ${
                    f()!.feedback?.verdict === option.verdict
                      ? option.active
                      : "border-border-weaker-base bg-bg-base text-text-secondary hover:border-border-strong hover:text-text-primary"
                  } ${!f()!.persisted ? "cursor-not-allowed opacity-50" : ""}`}
                >
                  {language.t(option.label)}
                </button>
              )}
            </For>
          </div>
          <p class="text-10-mono text-text-tertiary">
            {f()!.persisted
              ? language.t("findings.feedback.hint")
              : language.t("findings.feedback.notPersisted")}
          </p>
        </div>

        {/* Alerta de explotación CISA KEV / EPSS */}
        <Show when={f()!.cisaKev || f()!.epssScore !== undefined || (f()!.cvss !== undefined && f()!.cvss! >= 9.0)}>
          <div class="rounded-sm border border-severity-fg-high/40 bg-severity-fg-high/10 p-3 text-xs">
            <div class="flex items-center gap-2 font-medium text-severity-fg-high">
              <span class="size-2 rounded-full bg-severity-fg-high" />
              <span>{"Prioridad de Explotación Activa"}</span>
            </div>
            <div class="mt-1 space-y-0.5 text-text-secondary">
              <Show when={f()!.cisaKev}>
                <p>{"Catalogada en CISA KEV (Known Exploited Vulnerabilities Catalog)."}</p>
              </Show>
              <Show when={f()!.epssScore !== undefined}>
                <p>{`Percentil de probabilidad EPSS: ${(f()!.epssScore! * 100).toFixed(1)}%`}</p>
              </Show>
              <Show when={f()!.cvss !== undefined && f()!.cvss! >= 9.0}>
                <p>{"Severidad crítica directa: riesgo inminente de compromiso del activo."}</p>
              </Show>
            </div>
          </div>
        </Show>

        {/* Indicadores de Compromiso (IoCs) */}
        <div class="space-y-2">
          <h4 class="text-xs font-medium text-text-secondary">{"Indicadores (IoCs)"}</h4>
          <div class="flex flex-wrap gap-1.5">
            <For each={f()!.iocs}>
              {(ioc) => (
                <button
                  type="button"
                  onClick={() => void copyWithToast(ioc.value, `IoC copiado: ${ioc.value}`)}
                  title={"Clic para copiar"}
                  class="inline-flex items-center gap-1.5 rounded-sm border border-border-weaker-base bg-bg-surface px-2 py-1 font-mono text-11-mono text-text-primary transition-colors hover:border-border-strong hover:bg-bg-elevated"
                >
                  <span class="text-[9px] text-text-tertiary">{ioc.type}</span>
                  <span>{ioc.value}</span>
                </button>
              )}
            </For>
            <Show when={f()!.iocs.length === 0}>
              <span class="text-xs text-text-tertiary">{"Sin IoCs específicos extraídos."}</span>
            </Show>
          </div>

          {/* Técnicas MITRE ATT&CK asociadas */}
          <Show when={f()!.mitre.length > 0}>
            <div class="pt-1 space-y-1">
              <For each={f()!.mitre}>
                {(m) => (
                  <div class="font-mono text-11-mono text-text-secondary">
                    <span class="font-semibold text-text-primary">{m.id}</span>
                    <span>{" — "}</span>
                    <span>{m.name}</span>
                    <Show when={m.tool}>
                      <span class="text-text-tertiary">{` · ${m.tool}`}</span>
                    </Show>
                  </div>
                )}
              </For>
            </div>
          </Show>
        </div>

        {/* Sub-pestañas forenses: PoC / RAW HTTP / cURL */}
        <div class="space-y-2">
          <div class="flex items-center justify-between border-b border-border-weaker-base pb-1">
            <div class="flex items-center gap-3">
              <button
                type="button"
                onClick={() => setActiveSubTab("poc")}
                class={`text-xs pb-1 transition-colors ${
                  activeSubTab() === "poc"
                    ? "font-medium text-text-primary border-b border-text-primary"
                    : "text-text-tertiary hover:text-text-secondary"
                }`}
              >
                {"Evidencia / PoC"}
              </button>
              <button
                type="button"
                onClick={() => setActiveSubTab("raw")}
                class={`text-xs pb-1 transition-colors ${
                  activeSubTab() === "raw"
                    ? "font-medium text-text-primary border-b border-text-primary"
                    : "text-text-tertiary hover:text-text-secondary"
                }`}
              >
                {"Tráfico HTTP RAW"}
              </button>
              <button
                type="button"
                onClick={() => setActiveSubTab("curl")}
                class={`text-xs pb-1 transition-colors ${
                  activeSubTab() === "curl"
                    ? "font-medium text-text-primary border-b border-text-primary"
                    : "text-text-tertiary hover:text-text-secondary"
                }`}
              >
                {"Comando cURL"}
              </button>
            </div>

            <button
              type="button"
              onClick={() => {
                const text =
                  activeSubTab() === "poc"
                    ? f()!.poc ?? ""
                    : activeSubTab() === "raw"
                      ? `${f()!.httpRequest ?? ""}\n\n${f()!.httpResponse ?? ""}`
                      : f()!.curlCommand ?? ""
                void copyWithToast(text, "Copiado al portapapeles")
              }}
              class="text-xs text-text-tertiary hover:text-text-primary underline underline-offset-2 transition-colors"
            >
              {"Copiar"}
            </button>
          </div>

          <Show when={activeSubTab() === "poc"}>
            <pre class="overflow-x-auto rounded-sm border border-border-weaker-base bg-bg-base/70 p-3 font-mono text-11-mono leading-relaxed text-text-secondary whitespace-pre-wrap">
              {f()!.poc ?? "No se adjuntó evidencia para este hallazgo."}
            </pre>
          </Show>

          <Show when={activeSubTab() === "raw"}>
            <div class="space-y-2">
              <Show when={f()!.httpRequest}>
                <div class="text-[10px] uppercase font-mono text-text-tertiary">{"Request:"}</div>
                <pre class="overflow-x-auto rounded-sm border border-border-weaker-base bg-bg-base/70 p-2.5 font-mono text-11-mono leading-relaxed text-text-secondary whitespace-pre-wrap">
                  {f()!.httpRequest}
                </pre>
              </Show>
              <Show when={f()!.httpResponse}>
                <div class="text-[10px] uppercase font-mono text-text-tertiary">{"Response:"}</div>
                <pre class="overflow-x-auto rounded-sm border border-border-weaker-base bg-bg-base/70 p-2.5 font-mono text-11-mono leading-relaxed text-text-secondary whitespace-pre-wrap">
                  {f()!.httpResponse}
                </pre>
              </Show>
            </div>
          </Show>

          <Show when={activeSubTab() === "curl"}>
            <pre class="overflow-x-auto rounded-sm border border-border-weaker-base bg-bg-base/70 p-3 font-mono text-11-mono leading-relaxed text-text-secondary whitespace-pre-wrap">
              {f()!.curlCommand ?? "No se registró un comando cURL para este hallazgo."}
            </pre>
          </Show>
        </div>

        {/* Remediación */}
        <div class="space-y-1.5">
          <div class="flex items-center justify-between">
            <h4 class="text-xs font-medium text-text-secondary">{"Remediación sugerida"}</h4>
            <button
              type="button"
              disabled={!f()!.remediation}
              onClick={() => f()!.remediation && void copyWithToast(f()!.remediation!, "Script de remediación copiado")}
              class="text-xs text-text-tertiary hover:text-text-primary underline underline-offset-2 transition-colors"
            >
              {"Copiar"}
            </button>
          </div>
          <pre class="overflow-x-auto rounded-sm border border-border-weaker-base bg-bg-base/70 p-3 font-mono text-11-mono leading-relaxed text-text-secondary whitespace-pre-wrap">
            {f()!.remediation ?? "No se proporcionó una recomendación de remediación."}
          </pre>
        </div>

        {/* Mensaje de re-verificación */}
        <Show when={props.reverifyMessage}>
          <div class="rounded-sm border border-border-default bg-bg-surface p-2.5 font-mono text-xs text-text-primary">
            {props.reverifyMessage}
          </div>
        </Show>

        {/* Acciones inferiores */}
        <div class="flex items-center gap-2 border-t border-border-weaker-base pt-4">
          <button
            type="button"
            disabled={!f()!.persisted || props.reverifying}
            onClick={() => props.onReverify?.()}
            class={`flex-1 rounded-sm px-3 py-2 text-xs font-medium transition-colors ${
              !f()!.persisted
                ? "cursor-not-allowed bg-bg-elevated text-text-tertiary"
                : props.reverifying
                  ? "cursor-wait bg-accent text-accent-contrast opacity-70"
                  : "bg-accent text-accent-contrast hover:bg-accent/90"
            }`}
          >
            {props.reverifying
              ? "Re-verificando sonda..."
              : f()!.persisted
                ? "Re-verificar endpoint"
                : "No persistido en base de datos"}
          </button>
          <button
            disabled={!f()!.remediation}
            type="button"
            onClick={() => f()!.remediation && void copyWithToast(f()!.remediation!, "Remediación copiada al portapapeles")}
            class="rounded-sm border border-border-weaker-base bg-bg-surface px-3 py-2 text-xs text-text-secondary transition-colors hover:border-border-strong hover:text-text-primary"
          >
            {"Copiar fix"}
          </button>
        </div>
      </div>
    </Show>
  )
}

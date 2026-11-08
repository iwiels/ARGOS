import { createMemo, Show } from "solid-js"
import { useLanguage } from "@/context/language"
import { findingStatusLabelKey, nextLedgerStatus } from "../../findings-data"
import type { CockpitFinding } from "./cockpit-types"

function getStatusBadgeStyle(status: string) {
  const norm = status.toLowerCase().trim()
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

export function FindingCompactCard(props: {
  finding: CockpitFinding
  isSelected: boolean
  onSelect: () => void
  onStatusChange: (nextStatus: string) => void
}) {
  const language = useLanguage()
  const f = () => props.finding

  const statusStyle = createMemo(() => getStatusBadgeStyle(f().status))
  const statusLabel = createMemo(() => {
    const key = findingStatusLabelKey(f().status)
    return key ? language.t(key) : f().status
  })

  const railColor = createMemo(() => `var(--severity-fg-${f().severity})`)

  const handleCycleStatus = (e: MouseEvent) => {
    e.stopPropagation()
    props.onStatusChange(nextLedgerStatus(f().status))
  }

  return (
    <article
      onClick={() => props.onSelect()}
      class={`group relative flex cursor-pointer flex-col gap-1.5 rounded-xs border p-3 transition-colors ${
        props.isSelected
          ? "border-border-default bg-bg-elevated shadow-xs"
          : "border-border-weaker-base bg-bg-surface hover:border-border-default hover:bg-bg-elevated/70"
      }`}
      style={{
        "border-left-width": "4px",
        "border-left-color": railColor(),
      }}
    >
      <div class="flex flex-wrap items-center gap-x-2 gap-y-1 font-mono text-11-mono text-text-tertiary">
        <span class={`font-semibold ${props.isSelected ? "text-text-primary" : "text-text-secondary"}`}>
          {f().shortId}
        </span>
        <span>·</span>
        <span class={f().cvss !== undefined && f().cvss! >= 7 ? "font-semibold text-severity-fg-high" : "text-text-secondary"}>
          {`CVSS ${f().cvss?.toFixed(1) ?? "—"}`}
        </span>
        <span>·</span>
        <span class="text-text-secondary">{f().cwe ?? "CWE no disponible"}</span>
        <span class="text-10-mono">
          {f().persisted ? (
            <span class="text-text-tertiary">{"[DB]"}</span>
          ) : (
            <span class="text-severity-fg-medium">{"[Caché local]"}</span>
          )}
        </span>
        <Show when={f().feedback}>
          {(feedback) => (
            <span
              class={`rounded-sm px-1.5 py-0.5 text-10-mono ${
                feedback().verdict === "true-positive"
                  ? "bg-severity-fg-low/10 text-severity-fg-low"
                  : feedback().verdict === "false-positive"
                    ? "bg-bg-elevated text-text-tertiary"
                    : "bg-severity-fg-medium/10 text-severity-fg-medium"
              }`}
              title={feedback().reason}
            >
              {feedback().verdict === "true-positive"
                ? language.t("findings.feedback.short.truePositive")
                : feedback().verdict === "false-positive"
                  ? language.t("findings.feedback.short.falsePositive")
                  : language.t("findings.feedback.short.acceptedRisk")}
            </span>
          )}
        </Show>
        <button
          type="button"
          onClick={handleCycleStatus}
          title={language.t("findings.status.changeTooltip")}
          class="ml-auto inline-flex items-center gap-1.5 text-xs transition-opacity hover:opacity-80"
        >
          <span class={`size-1.5 rounded-full ${statusStyle().dot}`} />
          <span class={statusStyle().text}>{statusLabel()}</span>
        </button>
      </div>

      <h4 class="text-sm font-medium leading-snug text-text-primary line-clamp-2">
        {f().title}
      </h4>

      <p class="font-mono text-11-mono text-text-tertiary truncate">
        {f().target ?? "Objetivo no disponible"}
        <Show when={f().mitre.length > 0}>
          <span class="text-text-secondary">{` · ${f().mitre.map((m) => m.id).join(" · ")}`}</span>
        </Show>
      </p>
    </article>
  )
}

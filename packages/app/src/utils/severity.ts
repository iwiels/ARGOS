import type { Severity } from "@/components/session/findings-data"

export const SEV_BADGE: Record<Severity, string> = {
  critical: "text-severity-fg-critical bg-severity-bg-critical border-border-strong",
  high: "text-severity-fg-high bg-severity-bg-high border-border-default",
  medium: "text-severity-fg-medium bg-severity-bg-medium border-border-default",
  low: "text-severity-fg-low bg-severity-bg-low border-border-default",
  info: "text-severity-fg-info bg-severity-bg-info border-border-default",
}

export const SEV_COLOR: Record<Severity, string> = {
  critical: "var(--severity-fg-critical)",
  high: "var(--severity-fg-high)",
  medium: "var(--severity-fg-medium)",
  low: "var(--severity-fg-low)",
  info: "var(--severity-fg-info)",
}

export const SEV_TEXT_CLASS: Record<Severity, string> = {
  critical: "text-severity-fg-critical",
  high: "text-severity-fg-high",
  medium: "text-severity-fg-medium",
  low: "text-severity-fg-low",
  info: "text-severity-fg-info",
}

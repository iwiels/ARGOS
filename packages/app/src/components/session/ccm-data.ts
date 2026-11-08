import type { ControlStatus } from "./ccm-api"

export const STATUS_ORDER: readonly ControlStatus[] = ["deficient", "partial", "compliant", "unassessed"]

export interface StatusMeta {
  labelKey: "ccm.status.deficient" | "ccm.status.partial" | "ccm.status.compliant" | "ccm.status.unassessed"
  badge: string
  bar: string
}

export const STATUS_META: Record<ControlStatus, StatusMeta> = {
  deficient: {
    labelKey: "ccm.status.deficient",
    badge: "text-severity-fg-critical bg-severity-bg-critical border-severity-border-critical",
    bar: "var(--severity-fg-critical)",
  },
  partial: {
    labelKey: "ccm.status.partial",
    badge: "text-severity-fg-medium bg-severity-bg-medium border-severity-border-medium",
    bar: "var(--severity-fg-medium)",
  },
  compliant: {
    labelKey: "ccm.status.compliant",
    badge: "text-severity-fg-low bg-severity-bg-low border-severity-border-low",
    bar: "var(--severity-fg-low)",
  },
  unassessed: {
    labelKey: "ccm.status.unassessed",
    badge: "text-text-tertiary bg-bg-elevated border-border-weaker-base",
    bar: "var(--text-tertiary)",
  },
}

export function statusMeta(status: string): StatusMeta {
  return STATUS_META[status as ControlStatus] ?? STATUS_META.unassessed
}

export function statusLabelKey(status: string): StatusMeta["labelKey"] {
  return statusMeta(status).labelKey
}

const DRIFT_RANK: Record<string, number> = { compliant: 1, partial: 2, deficient: 3, unassessed: 0 }

export function driftWorsened(from: string, to: string): boolean {
  return (DRIFT_RANK[to] ?? 0) > (DRIFT_RANK[from] ?? 0)
}

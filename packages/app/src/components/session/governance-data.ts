export const AGENT_LABELS = {
  analyst: "governance.agent.analyst",
  triage: "governance.agent.triage",
  hunter: "governance.agent.hunter",
  responder: "governance.agent.responder",
  general: "governance.agent.general",
  build: "governance.agent.build",
  plan: "governance.agent.plan",
  explore: "governance.agent.explore",
} as const

export const AGENT_COLORS: Record<string, string> = {
  analyst: "var(--severity-fg-low)",
  triage: "var(--severity-fg-medium)",
  hunter: "var(--severity-fg-critical)",
  responder: "var(--accent)",
}

export function agentLabelKey(name: string): (typeof AGENT_LABELS)[keyof typeof AGENT_LABELS] | undefined {
  return AGENT_LABELS[name as keyof typeof AGENT_LABELS]
}

export function agentColor(name: string): string {
  return AGENT_COLORS[name] ?? "var(--text-secondary)"
}

export const EVENT_LABELS = {
  "tool.executed": "governance.event.tool.executed",
  "tool.error": "governance.event.tool.error",
  "prompt.created": "governance.event.prompt.created",
  "message.completed": "governance.event.message.completed",
  "session.created": "governance.event.session.created",
  "session.deleted": "governance.event.session.deleted",
  "file.changed": "governance.event.file.changed",
  "part.removed": "governance.event.part.removed",
  "message.removed": "governance.event.message.removed",
} as const

export function eventLabelKey(name: string): (typeof EVENT_LABELS)[keyof typeof EVENT_LABELS] | undefined {
  return EVENT_LABELS[name as keyof typeof EVENT_LABELS]
}

export function eventColor(name: string): string {
  if (name.startsWith("tool.error") || name.includes("failed") || name.includes("reject")) {
    return "text-severity-fg-critical"
  }
  return "text-text-secondary"
}

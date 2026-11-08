import { describe, expect, test } from "bun:test"
import {
  AGENT_COLORS,
  AGENT_LABELS,
  EVENT_LABELS,
  agentColor,
  agentLabelKey,
  eventColor,
  eventLabelKey,
} from "./governance-data"

describe("AGENT_LABELS", () => {
  test("covers the four SecOps agents with i18n keys", () => {
    for (const agent of ["analyst", "triage", "hunter", "responder"] as const) {
      expect(AGENT_LABELS[agent]).toMatch(/^governance\.agent\./)
    }
  })

  test("agentLabelKey returns undefined for unknown agents (raw name fallback)", () => {
    expect(agentLabelKey("custom_agent")).toBeUndefined()
    expect(agentLabelKey("analyst")).toBe("governance.agent.analyst")
  })
})

describe("AGENT_COLORS", () => {
  test("assigns a distinct color to each core SecOps agent", () => {
    for (const agent of ["analyst", "triage", "hunter", "responder"]) {
      expect(AGENT_COLORS[agent]).toMatch(/^var\(/)
    }
  })

  test("agentColor falls back to a neutral token for unknown agents", () => {
    expect(agentColor("unknown")).toBe("var(--text-secondary)")
  })
})

describe("EVENT_LABELS", () => {
  test("maps known audit event types to i18n keys", () => {
    expect(eventLabelKey("tool.executed")).toBe("governance.event.tool.executed")
    expect(eventLabelKey("message.completed")).toBe("governance.event.message.completed")
    expect(eventLabelKey("session.deleted")).toBe("governance.event.session.deleted")
  })

  test("returns undefined for unknown event types (raw name fallback)", () => {
    expect(eventLabelKey("agent.thinking")).toBeUndefined()
  })
})

describe("eventColor", () => {
  test("flags tool errors and rejected/failed events as critical", () => {
    expect(eventColor("tool.error")).toBe("text-severity-fg-critical")
    expect(eventColor("approval.rejected")).toBe("text-severity-fg-critical")
    expect(eventColor("run.failed")).toBe("text-severity-fg-critical")
  })

  test("uses the neutral color for informational and non-response events", () => {
    expect(eventColor("prompt.created")).toBe("text-text-secondary")
    expect(eventColor("session.created")).toBe("text-text-secondary")
  })
})

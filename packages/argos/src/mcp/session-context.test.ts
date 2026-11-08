import { expect, test } from "bun:test"
import { addArgosSessionContext, extractArgosSessionContext } from "./session-context"

test("keeps controller session metadata out of tool arguments", () => {
  const input = { target: "https://example.test", __argos_run_id: "run_model_input" }
  const contextual = addArgosSessionContext(input, {
    sessionID: "ses_controller_123",
    runID: "run_controller_123",
    operationID: "call_123",
    scope: { domains: ["example.test"], maxRPS: 4, safeMode: true },
  })
  const extracted = extractArgosSessionContext(contextual)

  expect(input).toEqual({ target: "https://example.test", __argos_run_id: "run_model_input" })
  expect(extracted).toEqual({
    arguments: { target: "https://example.test" },
    sessionID: "ses_controller_123",
    runID: "run_controller_123",
    operationID: "call_123",
    scope: { domains: ["example.test"], maxRPS: 4, safeMode: true },
  })
})

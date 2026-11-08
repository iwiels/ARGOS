import { describe, expect, test } from "bun:test"
import { Effect, Exit } from "effect"
import * as ScopeService from "@argos/core/security/scope-service"
import { assertMcpToolScope } from "../../src/session/mcp-scope"

describe("MCP target scope enforcement", () => {
  test("blocks an out-of-scope web target before the MCP can send a request", async () => {
    let checked: { sessionID: string; target: string } | undefined
    let requests = 0
    const scope = {
      assertTarget: (sessionID: string, target: string) => {
        checked = { sessionID, target }
        return Effect.fail(
          new ScopeService.ScopeViolationError({
            target,
            reason: `SCOPE ENFORCEMENT: Target '${target}' is out of authorized scope`,
          }),
        )
      },
    } as unknown as ScopeService.Interface

    const result = await Effect.runPromiseExit(
      assertMcpToolScope(scope, "ses_scope_test", "argos_web_web_waf", {
        target: "http://127.0.0.1:5173/",
      }).pipe(Effect.andThen(Effect.sync(() => requests++))),
    )

    expect(Exit.isFailure(result)).toBe(true)
    expect(checked).toEqual({ sessionID: "ses_scope_test", target: "http://127.0.0.1:5173/" })
    expect(requests).toBe(0)
  })

  test("does not scope unrelated MCP tools", async () => {
    let checked = false
    const scope = {
      assertTarget: () => {
        checked = true
        return Effect.void
      },
    } as unknown as ScopeService.Interface

    await Effect.runPromise(assertMcpToolScope(scope, "ses_scope_test", "github_search", { query: "Argos" }))

    expect(checked).toBe(false)
  })
})

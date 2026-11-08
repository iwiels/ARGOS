import type * as ScopeService from "@argos/core/security/scope-service"
import { Effect } from "effect"

function targetFor(toolName: string, args: unknown) {
  if (!toolName.startsWith("argos_web_") || typeof args !== "object" || args === null) return undefined

  const input = args as Record<string, unknown>
  for (const key of ["target", "url", "domain", "host"]) {
    if (typeof input[key] === "string" && input[key].trim()) return input[key].trim()
  }
}

export function assertMcpToolScope(
  scope: ScopeService.Interface,
  sessionID: string,
  toolName: string,
  args: unknown,
) {
  const target = targetFor(toolName, args)
  if (!target) return Effect.void
  return scope.assertTarget(sessionID, target)
}

import { createHash } from "node:crypto"

const verifiedWebToolNames: Record<string, string> = {
  argos_web_web_scan: "web.scan",
  argos_web_web_waf: "web.waf",
  argos_web_web_csrf: "web.csrf",
  argos_web_web_graphql: "web.graphql",
  argos_web_web_jwt: "web.jwt",
  argos_web_web_oauth: "web.oauth",
  argos_web_web_prompt_injection: "web.prompt_injection",
  argos_web_web_ssti: "web.ssti",
  "argos-web_web_csrf": "web.csrf",
  "argos-web_web_scan": "web.scan",
  "argos-web_web_waf": "web.waf",
  "argos-web_web_graphql": "web.graphql",
  "argos-web_web_jwt": "web.jwt",
  "argos-web_web_oauth": "web.oauth",
  "argos-web_web_prompt_injection": "web.prompt_injection",
  "argos-web_web_ssti": "web.ssti",
}

export const runtimeProbeToolName = (toolName: string) => verifiedWebToolNames[toolName]

export type RuntimeProbeEvidence = {
  runtimeTool: string
  status: "executed" | "no-finding" | "blocked" | "inconclusive"
  findingCount: number
  evidenceHash: string
  evidenceRef: string
}

type RuntimeProbeEvidenceInput = {
  toolName: string
  sessionID: string
  messageID: string
  partID: string
}

const evidenceReference = (input: RuntimeProbeEvidenceInput) =>
  `/session/${encodeURIComponent(input.sessionID)}/message/${encodeURIComponent(input.messageID)}#part-${encodeURIComponent(input.partID)}`

export const runtimeProbeEvidence = (
  input: RuntimeProbeEvidenceInput & {
    output: string
    truncated: boolean
  },
): RuntimeProbeEvidence | undefined => {
  const runtimeTool = runtimeProbeToolName(input.toolName)
  if (!runtimeTool || input.truncated || input.output.length === 0 || input.output.length > 2 * 1024 * 1024) return

  let result: unknown
  try {
    result = JSON.parse(input.output)
  } catch {
    return
  }
  if (!result || typeof result !== "object" || Array.isArray(result)) return
  const value = result as Record<string, unknown>
  if (
    value.tool !== runtimeTool ||
    value.status !== "completed" ||
    value.aborted === true ||
    value.degraded === true ||
    value.truncated === true ||
    value.output_truncated === true
  ) {
    return
  }

  let findingCount: number
  let status: RuntimeProbeEvidence["status"]
  if (runtimeTool === "web.waf") {
    if (
      typeof value.waf_detected !== "boolean" ||
      !Array.isArray(value.wafs) ||
      !value.wafs.every((waf) => typeof waf === "string") ||
      !("evidence" in value) ||
      (value.evidence !== null && (typeof value.evidence !== "object" || Array.isArray(value.evidence)))
    ) {
      return
    }
    if (value.waf_assessment === "fingerprint_observed") {
      if (value.waf_detected !== true || value.wafs.length === 0) return
      status = "executed"
    } else if (value.waf_assessment === "inconclusive") {
      if (value.waf_detected !== false || value.wafs.length > 0) return
      status = "inconclusive"
    } else if (value.waf_assessment === undefined) {
      status = value.waf_detected ? "executed" : "inconclusive"
    } else {
      return
    }
    findingCount = 0
  } else {
    if (!Array.isArray(value.findings)) return
    findingCount = value.findings.length
    status = findingCount > 0 ? "executed" : "no-finding"
  }

  return {
    runtimeTool,
    status,
    findingCount,
    evidenceHash: createHash("sha256").update(input.output).digest("hex"),
    evidenceRef: evidenceReference(input),
  }
}

export const runtimeProbeFailureEvidence = (
  input: RuntimeProbeEvidenceInput & { error: string; blocked: boolean },
): RuntimeProbeEvidence | undefined => {
  const runtimeTool = runtimeProbeToolName(input.toolName)
  if (!runtimeTool || input.error.length === 0 || input.error.length > 2 * 1024 * 1024) return

  return {
    runtimeTool,
    status: input.blocked ? "blocked" : "inconclusive",
    findingCount: 0,
    evidenceHash: createHash("sha256").update(input.error).digest("hex"),
    evidenceRef: evidenceReference(input),
  }
}

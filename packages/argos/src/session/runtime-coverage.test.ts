import { createHash } from "node:crypto"
import { expect, test } from "bun:test"
import { runtimeProbeEvidence, runtimeProbeFailureEvidence, runtimeProbeToolName } from "./runtime-coverage"

const output = JSON.stringify({
  tool: "web.jwt",
  target: "https://app.example.test",
  status: "completed",
  findings: [{ rule_id: "jwt:weak-secret" }],
})

test("binds complete worker-probe evidence to its stored session part", () => {
  const evidence = runtimeProbeEvidence({
    toolName: "argos-web_web_jwt",
    sessionID: "ses_runtime_coverage",
    messageID: "msg_runtime_coverage",
    partID: "prt_runtime_coverage",
    output,
    truncated: false,
  })

  expect(evidence).toEqual({
    runtimeTool: "web.jwt",
    status: "executed",
    findingCount: 1,
    evidenceHash: createHash("sha256").update(output).digest("hex"),
    evidenceRef: "/session/ses_runtime_coverage/message/msg_runtime_coverage#part-prt_runtime_coverage",
  })
})

test("records an explicit no-finding result only for a complete worker response", () => {
  const noFindings = JSON.stringify({
    tool: "web.csrf",
    target: "https://app.example.test",
    status: "completed",
    findings: [],
  })

  expect(
    runtimeProbeEvidence({
      toolName: "argos-web_web_csrf",
      sessionID: "ses_runtime_coverage",
      messageID: "msg_runtime_coverage",
      partID: "prt_runtime_coverage",
      output: noFindings,
      truncated: false,
    }),
  ).toMatchObject({ runtimeTool: "web.csrf", status: "no-finding", findingCount: 0 })
})

test("classifies failed worker evidence as blocked or inconclusive", () => {
  const input = {
    toolName: "argos-web_web_jwt",
    sessionID: "ses_runtime_coverage",
    messageID: "msg_runtime_coverage",
    partID: "prt_runtime_coverage",
    error: "worker rejected the probe",
  }

  expect(runtimeProbeFailureEvidence({ ...input, blocked: true })).toMatchObject({
    runtimeTool: "web.jwt",
    status: "blocked",
    findingCount: 0,
    evidenceHash: createHash("sha256").update(input.error).digest("hex"),
    evidenceRef: "/session/ses_runtime_coverage/message/msg_runtime_coverage#part-prt_runtime_coverage",
  })
  expect(runtimeProbeFailureEvidence({ ...input, blocked: false })).toMatchObject({
    runtimeTool: "web.jwt",
    status: "inconclusive",
    findingCount: 0,
  })
  expect(runtimeProbeFailureEvidence({ ...input, toolName: "argos-lan_port_scan", blocked: true })).toBeUndefined()
})

test("attests complete Nuclei and WAF results from the isolated web runtime", () => {
  const input = {
    sessionID: "ses_runtime_coverage",
    messageID: "msg_runtime_coverage",
    partID: "prt_runtime_coverage",
    truncated: false,
  }
  const scan = JSON.stringify({
    tool: "web.scan",
    target: "https://app.example.test",
    status: "completed",
    findings: [{ rule_id: "nuclei:exposure" }],
    degraded: false,
    truncated: false,
    output_truncated: false,
  })
  const waf = JSON.stringify({
    tool: "web.waf",
    target: "https://app.example.test",
    status: "completed",
    waf_detected: true,
    waf_assessment: "fingerprint_observed",
    wafs: ["Example WAF"],
    evidence: { header: "server" },
  })
  const wafNoDetection = JSON.stringify({
    tool: "web.waf",
    target: "https://app.example.test",
    status: "completed",
    waf_detected: false,
    waf_assessment: "inconclusive",
    wafs: [],
    evidence: null,
  })
  const wafMissingEvidence = JSON.stringify({
    tool: "web.waf",
    target: "https://app.example.test",
    status: "completed",
    waf_detected: false,
    wafs: [],
  })

  expect(runtimeProbeEvidence({ ...input, toolName: "argos-web_web_scan", output: scan })).toMatchObject({
    runtimeTool: "web.scan",
    status: "executed",
    findingCount: 1,
    evidenceHash: createHash("sha256").update(scan).digest("hex"),
  })
  expect(runtimeProbeEvidence({ ...input, toolName: "argos-web_web_waf", output: waf })).toMatchObject({
    runtimeTool: "web.waf",
    status: "executed",
    findingCount: 0,
    evidenceHash: createHash("sha256").update(waf).digest("hex"),
  })
  expect(runtimeProbeEvidence({ ...input, toolName: "argos-web_web_waf", output: wafNoDetection })).toMatchObject({
    runtimeTool: "web.waf",
    status: "inconclusive",
    findingCount: 0,
  })
  expect(runtimeProbeEvidence({ ...input, toolName: "argos-web_web_waf", output: wafMissingEvidence })).toBeUndefined()
  expect(
    runtimeProbeEvidence({
      ...input,
      toolName: "argos-web_web_scan",
      output: scan.replace('"truncated":false', '"truncated":true'),
    }),
  ).toBeUndefined()
  expect(runtimeProbeToolName("argos-web_web_scan")).toBe("web.scan")
  expect(runtimeProbeToolName("argos-web_web_waf")).toBe("web.waf")
})

test("does not treat a missing passive WAF fingerprint as a no-finding result", () => {
	const output = JSON.stringify({
		tool: "web.waf",
		target: "https://app.example.test",
		status: "completed",
		waf_detected: false,
		waf_assessment: "inconclusive",
		wafs: [],
		evidence: {},
	})

	expect(
		runtimeProbeEvidence({
			toolName: "argos-web_web_waf",
			sessionID: "ses_runtime_coverage",
			messageID: "msg_runtime_coverage",
			partID: "prt_runtime_coverage",
			output,
			truncated: false,
		}),
	).toMatchObject({ runtimeTool: "web.waf", status: "inconclusive", findingCount: 0 })
})

test("rejects truncated, malformed, incomplete, mismatched, and non-worker outputs", () => {
  const input = {
    toolName: "argos-web_web_jwt",
    sessionID: "ses_runtime_coverage",
    messageID: "msg_runtime_coverage",
    partID: "prt_runtime_coverage",
    output,
    truncated: false,
  }

  expect(runtimeProbeEvidence({ ...input, truncated: true })).toBeUndefined()
  expect(runtimeProbeEvidence({ ...input, output: "{" })).toBeUndefined()
  expect(runtimeProbeEvidence({ ...input, output: output.replace('"completed"', '"incomplete"') })).toBeUndefined()
  expect(runtimeProbeEvidence({ ...input, output: output.replace('"web.jwt"', '"web.csrf"') })).toBeUndefined()
  expect(runtimeProbeEvidence({ ...input, toolName: "argos-web_web_scan" })).toBeUndefined()
  expect(runtimeProbeToolName("argos-web_web_jwt")).toBe("web.jwt")
  expect(runtimeProbeToolName("custom-web_web_jwt")).toBeUndefined()
})

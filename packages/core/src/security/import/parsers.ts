import type { FindingContract } from "../contract"
import { computeSummary, type ImportFormat, type ImportParserContract, type ParsedImportResult } from "./types"

const MAX_IMPORT_SIZE = 50 * 1024 * 1024 // 50MB
const MAX_IMPORT_DEPTH = 32

function checkContentLimits(content: string, format: string) {
  if (content.length > MAX_IMPORT_SIZE) {
    throw new Error(`Import payload exceeds maximum size limit of 50MB for ${format}`)
  }
}

// 1. SARIF 2.1 Parser
export const SarifParser: ImportParserContract = {
  format: "sarif",
  version: "2.1.0",
  maxSizeBytes: MAX_IMPORT_SIZE,
  maxDepth: MAX_IMPORT_DEPTH,
  parse(content: string, opts): ParsedImportResult {
    checkContentLimits(content, "SARIF")
    const doc = JSON.parse(content)
    const findings: FindingContract[] = []
    let scanner = "sarif"

    for (const run of doc.runs ?? []) {
      const toolName = run.tool?.driver?.name ?? "sarif"
      scanner = toolName
      const rules = new Map<string, any>()
      for (const rule of run.tool?.driver?.rules ?? []) {
        rules.set(rule.id, rule)
      }

      for (const res of run.results ?? []) {
        const ruleId = res.ruleId ?? "sarif-rule"
        const rule = rules.get(ruleId)
        const title = res.message?.text || rule?.shortDescription?.text || ruleId
        const level = res.level ?? rule?.defaultConfiguration?.level ?? "warning"
        const secSevScore = parseFloat(rule?.properties?.["security-severity"] ?? res.properties?.["security-severity"])
        let severity = level === "error" ? "high" : level === "warning" ? "medium" : "info"
        if (!isNaN(secSevScore)) {
          if (secSevScore >= 9.0) severity = "critical"
          else if (secSevScore >= 7.0) severity = "high"
          else if (secSevScore >= 4.0) severity = "medium"
          else if (secSevScore > 0) severity = "low"
        } else if (level === "error" && rule?.properties?.tags?.some((t: string) => /critical/i.test(t))) {
          severity = "critical"
        }

        const loc = res.locations?.[0]?.physicalLocation
        const artifactUri = loc?.artifactLocation?.uri ?? ""
        const line = loc?.region?.startLine
        const target = opts?.target ?? artifactUri ?? "source-code"
        const vector = line ? `${artifactUri}:${line}` : artifactUri

        const cweTag = (rule?.properties?.tags ?? []).find((t: string) => /^CWE-\d+/i.test(t))
        const cwe = cweTag ? cweTag.toUpperCase() : undefined

        findings.push({
          source: "import",
          source_tool: toolName,
          rule_id: ruleId,
          title,
          severity,
          cwe,
          target,
          vector,
          evidence: {
            sarifResult: res,
            rule,
          },
          remediation: rule?.help?.text,
          tags: rule?.properties?.tags ?? [],
        })
      }
    }

    return {
      format: "sarif",
      scanner,
      target: opts?.target,
      isCompleteScan: opts?.isCompleteScan ?? false,
      findings,
      summary: computeSummary(findings),
    }
  },
}

// 2. Nuclei JSONL Parser
export const NucleiParser: ImportParserContract = {
  format: "nuclei",
  version: "v3",
  maxSizeBytes: MAX_IMPORT_SIZE,
  maxDepth: MAX_IMPORT_DEPTH,
  parse(content: string, opts): ParsedImportResult {
    checkContentLimits(content, "Nuclei")
    const findings: FindingContract[] = []
    const lines = content.split(/\r?\n/).filter((l) => l.trim().length > 0)

    for (const line of lines) {
      try {
        const item = JSON.parse(line)
        const info = item.info ?? {}
        const templateId = item["template-id"] ?? item.templateID ?? "nuclei-template"
        const title = info.name ?? templateId
        const severity = info.severity ?? "info"
        const target = item.host ?? item.matched ?? opts?.target ?? "target"
        const vector = item["matched-at"] ?? item.matched ?? target

        const cweList = info.classification?.["cwe-id"]
        const cwe = Array.isArray(cweList) && cweList[0] ? `CWE-${cweList[0]}` : typeof cweList === "string" ? cweList : undefined

        findings.push({
          source: "import",
          source_tool: "nuclei",
          rule_id: templateId,
          title,
          severity,
          cwe,
          target,
          vector,
          evidence: {
            extractedResults: item["extracted-results"],
            curlCommand: item["curl-command"],
            matcherName: item["matcher-name"],
            type: item.type,
          },
          tags: Array.isArray(info.tags) ? info.tags : typeof info.tags === "string" ? info.tags.split(",") : [],
          references: info.reference ? (Array.isArray(info.reference) ? info.reference : [info.reference]) : [],
        })
      } catch {
        // Skip malformed lines
      }
    }

    return {
      format: "nuclei",
      scanner: "nuclei",
      target: opts?.target,
      isCompleteScan: opts?.isCompleteScan ?? false,
      findings,
      summary: computeSummary(findings),
    }
  },
}

// 3. Semgrep JSON Parser
export const SemgrepParser: ImportParserContract = {
  format: "semgrep",
  version: "1.0",
  maxSizeBytes: MAX_IMPORT_SIZE,
  maxDepth: MAX_IMPORT_DEPTH,
  parse(content: string, opts): ParsedImportResult {
    checkContentLimits(content, "Semgrep")
    const doc = JSON.parse(content)
    const findings: FindingContract[] = []

    for (const res of doc.results ?? []) {
      const checkId = res.check_id ?? "semgrep-rule"
      const meta = res.extra?.metadata ?? {}
      const sev = (res.extra?.severity ?? "WARNING").toLowerCase()
      const secSev = (meta.security_severity ?? "").toLowerCase()
      const severity =
        secSev === "critical" || sev === "critical"
          ? "critical"
          : secSev === "high" || sev === "error"
            ? "high"
            : secSev === "medium" || sev === "warning"
              ? "medium"
              : "low"
      const path = res.path ?? "file"
      const startLine = res.start?.line
      const vector = startLine ? `${path}:${startLine}` : path

      const cweVal = meta.cwe
      const cwe = Array.isArray(cweVal) ? cweVal[0] : typeof cweVal === "string" ? cweVal : undefined

      findings.push({
        source: "import",
        source_tool: "semgrep",
        rule_id: checkId,
        title: res.extra?.message?.split("\n")[0] || checkId,
        severity,
        cwe: cwe ? (cwe.toUpperCase().startsWith("CWE-") ? cwe.toUpperCase() : `CWE-${cwe}`) : undefined,
        target: opts?.target ?? path,
        vector,
        evidence: {
          code: res.extra?.lines,
          metavars: res.extra?.metavars,
        },
        remediation: meta.remediation,
        tags: meta.category ? [meta.category] : [],
        references: meta.references ?? [],
      })
    }

    return {
      format: "semgrep",
      scanner: "semgrep",
      target: opts?.target,
      isCompleteScan: opts?.isCompleteScan ?? false,
      findings,
      summary: computeSummary(findings),
    }
  },
}

// 4. Trivy JSON Parser
export const TrivyParser: ImportParserContract = {
  format: "trivy",
  version: "0.58",
  maxSizeBytes: MAX_IMPORT_SIZE,
  maxDepth: MAX_IMPORT_DEPTH,
  parse(content: string, opts): ParsedImportResult {
    checkContentLimits(content, "Trivy")
    const doc = JSON.parse(content)
    const findings: FindingContract[] = []

    for (const targetRes of doc.Results ?? []) {
      const targetName = targetRes.Target ?? opts?.target ?? "target"

      // Vulnerabilities (dependencies)
      for (const vuln of targetRes.Vulnerabilities ?? []) {
        const vulnId = vuln.VulnerabilityID ?? "CVE-UNKNOWN"
        const pkg = vuln.PkgName ?? "package"
        const installed = vuln.InstalledVersion ?? ""
        const fixed = vuln.FixedVersion ?? ""
        const severity = (vuln.Severity ?? "medium").toLowerCase()
        const cweList = vuln.CweIDs ?? []
        const cwe = cweList.length > 0 ? cweList[0] : undefined

        findings.push({
          source: "import",
          source_tool: "trivy",
          rule_id: `trivy:${vulnId}`,
          title: `${vulnId} in ${pkg} ${installed}`.trim(),
          severity,
          cwe,
          target: targetName,
          vector: `${pkg}@${installed}`,
          evidence: {
            vulnerability: vuln,
            installedVersion: installed,
            fixedVersion: fixed,
            description: vuln.Description,
          },
          remediation: fixed ? `Upgrade ${pkg} to version ${fixed} or higher.` : undefined,
          tags: ["dependency", "cve"],
          references: vuln.References ?? [],
        })
      }

      // Secrets
      for (const sec of targetRes.Secrets ?? []) {
        const ruleId = sec.RuleID ?? "secret"
        const title = sec.Title ?? `Exposed secret: ${ruleId}`
        const severity = (sec.Severity ?? "high").toLowerCase()
        const startLine = sec.StartLine

        findings.push({
          source: "import",
          source_tool: "trivy",
          rule_id: `trivy:secret:${ruleId}`,
          title,
          severity,
          cwe: "CWE-798",
          target: targetName,
          vector: startLine ? `${targetName}:${startLine}` : targetName,
          evidence: {
            ruleID: ruleId,
            category: sec.Category,
            lines: sec.Lines,
          },
          tags: ["secret", "credentials"],
        })
      }
    }

    return {
      format: "trivy",
      scanner: "trivy",
      target: opts?.target,
      isCompleteScan: opts?.isCompleteScan ?? false,
      findings,
      summary: computeSummary(findings),
    }
  },
}

// 5. Gitleaks JSON Parser
export const GitleaksParser: ImportParserContract = {
  format: "gitleaks",
  version: "8.0",
  maxSizeBytes: MAX_IMPORT_SIZE,
  maxDepth: MAX_IMPORT_DEPTH,
  parse(content: string, opts): ParsedImportResult {
    checkContentLimits(content, "Gitleaks")
    const list = JSON.parse(content)
    const findings: FindingContract[] = []

    for (const item of Array.isArray(list) ? list : []) {
      const ruleId = item.RuleID ?? item.Description ?? "gitleaks-secret"
      const file = item.File ?? opts?.target ?? "file"
      const startLine = item.StartLine
      const vector = startLine ? `${file}:${startLine}` : file

      findings.push({
        source: "import",
        source_tool: "gitleaks",
        rule_id: `gitleaks:${ruleId}`,
        title: `Credencial expuesta: ${item.Description || ruleId}`,
        severity: "high",
        cwe: "CWE-798",
        target: file,
        vector,
        evidence: {
          file,
          startLine,
          endLine: item.EndLine,
          commit: item.Commit,
          author: item.Author,
          date: item.Date,
          rule: ruleId,
        },
        remediation: "Revocar de inmediato la credencial expuesta y rotar los tokens de acceso.",
        tags: ["secret", "gitleaks", "credential-exposure"],
      })
    }

    return {
      format: "gitleaks",
      scanner: "gitleaks",
      target: opts?.target,
      isCompleteScan: opts?.isCompleteScan ?? false,
      findings,
      summary: computeSummary(findings),
    }
  },
}

// 6. OWASP ZAP JSON Parser
export const ZapParser: ImportParserContract = {
  format: "zap",
  version: "2.14",
  maxSizeBytes: MAX_IMPORT_SIZE,
  maxDepth: MAX_IMPORT_DEPTH,
  parse(content: string, opts): ParsedImportResult {
    checkContentLimits(content, "OWASP ZAP")
    const doc = JSON.parse(content)
    const findings: FindingContract[] = []

    const sites = doc.site ?? (Array.isArray(doc) ? doc : [doc])
    for (const site of sites) {
      const siteHost = site["@name"] ?? site.name ?? opts?.target ?? "web-target"
      for (const alert of site.alerts ?? []) {
        const pluginId = alert.pluginId ?? alert.alertId ?? "zap-alert"
        const title = alert.alert ?? alert.name ?? pluginId
        const riskcode = alert.riskcode
        const riskdesc = alert.riskdesc ?? ""
        let severity = "info"
        if (riskcode === "3" || /High/i.test(riskdesc)) severity = "high"
        else if (riskcode === "2" || /Medium/i.test(riskdesc)) severity = "medium"
        else if (riskcode === "1" || /Low/i.test(riskdesc)) severity = "low"

        const cweid = alert.cweid
        const cwe = cweid && cweid !== "0" && cweid !== "-1" ? `CWE-${cweid}` : undefined
        const instances = alert.instances ?? []
        const primaryUri = instances[0]?.uri ?? alert.url ?? siteHost
        const method = instances[0]?.method ?? ""
        const param = instances[0]?.param ?? alert.param ?? ""

        findings.push({
          source: "import",
          source_tool: "zap",
          rule_id: `zap:${pluginId}`,
          title,
          severity,
          cwe,
          target: siteHost,
          vector: param ? `${primaryUri} [${param}]` : primaryUri,
          evidence: {
            instancesCount: instances.length,
            sampleUri: primaryUri,
            method,
            param,
            description: alert.desc,
            solution: alert.solution,
            otherinfo: alert.otherinfo,
          },
          remediation: alert.solution,
          tags: ["zap", "dast"],
          references: alert.reference ? alert.reference.split("\n") : [],
        })
      }
    }

    return {
      format: "zap",
      scanner: "owasp-zap",
      target: opts?.target,
      isCompleteScan: opts?.isCompleteScan ?? false,
      findings,
      summary: computeSummary(findings),
    }
  },
}

// 7. Burp Suite XML Parser (Safe regex parser rejecting DOCTYPE/ENTITY to prevent XXE)
export const BurpParser: ImportParserContract = {
  format: "burp",
  version: "v2",
  maxSizeBytes: MAX_IMPORT_SIZE,
  maxDepth: MAX_IMPORT_DEPTH,
  parse(content: string, opts): ParsedImportResult {
    checkContentLimits(content, "Burp XML")

    // XXE Protection: strictly reject any DTD or entity declarations
    if (/<!DOCTYPE/i.test(content) || /<!ENTITY/i.test(content)) {
      throw new Error("XXE Security Violation: Burp XML with external DTD or entity declarations is strictly forbidden")
    }

    const findings: FindingContract[] = []
    const issueRegex = /<issue>([\s\S]*?)<\/issue>/gi
    let match: RegExpExecArray | null

    while ((match = issueRegex.exec(content)) !== null) {
      const block = match[1]
      const extractTag = (tag: string) => {
        const tagMatch = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`, "i").exec(block)
        return tagMatch ? tagMatch[1].replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1").trim() : ""
      }

      const typeId = extractTag("type") || "burp-issue"
      const name = extractTag("name") || typeId
      const host = extractTag("host")
      const path = extractTag("path")
      const sev = extractTag("severity").toLowerCase()
      const severity =
        sev === "critical" ? "critical" : sev === "high" ? "high" : sev === "medium" ? "medium" : sev === "low" ? "low" : "info"
      const target = host ? `${host}${path}` : opts?.target ?? path
      const vector = `${host}${path}`

      findings.push({
        source: "import",
        source_tool: "burp",
        rule_id: `burp:${typeId}`,
        title: name,
        severity,
        target,
        vector,
        evidence: {
          issueDetail: extractTag("issueDetail"),
          issueBackground: extractTag("issueBackground"),
          remediationDetail: extractTag("remediationDetail"),
        },
        remediation: extractTag("remediationBackground"),
        tags: ["burp", "dast"],
      })
    }

    return {
      format: "burp",
      scanner: "burp-suite",
      target: opts?.target,
      isCompleteScan: opts?.isCompleteScan ?? false,
      findings,
      summary: computeSummary(findings),
    }
  },
}

// 8. DefectDojo Generic JSON Parser
export const DefectDojoParser: ImportParserContract = {
  format: "defectdojo",
  version: "1.0",
  maxSizeBytes: MAX_IMPORT_SIZE,
  maxDepth: MAX_IMPORT_DEPTH,
  parse(content: string, opts): ParsedImportResult {
    checkContentLimits(content, "DefectDojo")
    const doc = JSON.parse(content)
    const findings: FindingContract[] = []
    const list = Array.isArray(doc.findings) ? doc.findings : Array.isArray(doc) ? doc : []

    for (const item of list) {
      const title = item.title ?? "Vulnerability"
      const sev = (item.severity ?? "Info").toLowerCase()
      const severity = sev === "critical" ? "critical" : sev === "high" ? "high" : sev === "medium" ? "medium" : sev === "low" ? "low" : "info"
      const target = item.file_path || item.url || item.endpoint || opts?.target || "target"
      const vector = item.line ? `${target}:${item.line}` : target
      const cwe = item.cwe ? (String(item.cwe).toUpperCase().startsWith("CWE-") ? String(item.cwe).toUpperCase() : `CWE-${item.cwe}`) : undefined

      findings.push({
        source: "import",
        source_tool: "defectdojo",
        rule_id: item.unique_id_from_tool || item.vuln_id_from_tool,
        title,
        severity,
        cwe,
        target,
        vector,
        evidence: {
          description: item.description,
          stepsToReproduce: item.steps_to_reproduce,
          references: item.references,
        },
        remediation: item.mitigation,
        tags: Array.isArray(item.tags) ? item.tags : [],
        references: item.references ? [item.references] : [],
      })
    }

    return {
      format: "defectdojo",
      scanner: "defectdojo-generic",
      target: opts?.target,
      isCompleteScan: opts?.isCompleteScan ?? false,
      findings,
      summary: computeSummary(findings),
    }
  },
}

export const PARSER_REGISTRY: Record<ImportFormat, ImportParserContract> = {
  sarif: SarifParser,
  nuclei: NucleiParser,
  semgrep: SemgrepParser,
  trivy: TrivyParser,
  gitleaks: GitleaksParser,
  zap: ZapParser,
  burp: BurpParser,
  defectdojo: DefectDojoParser,
}

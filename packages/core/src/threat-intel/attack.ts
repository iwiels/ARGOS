// MITRE ATT&CK Enterprise knowledge base (subset relevante para hallazgos de
// auditoría web/red/código). © 2024 MITRE — ATT&CK is a trademark of The MITRE
// Corporation. Técnicas referenciadas por ID/nombre con fines de mapeo; datos
// de uso libre con atribución (ver https://attack.mitre.org).

export type AttackTechnique = {
  /** ATT&CK technique ID, e.g. T1190 */
  id: string
  name: string
  tactics: string[]
  /** CWEs cuyos hallazgos suelen indicar esta técnica */
  cwes?: number[]
  /** Tags de hallazgo (findings.memory_save tags / metadata) */
  tags?: string[]
  /** Tools del motor que suelen producir evidencia de esta técnica */
  tools?: string[]
  keywords?: string[]
}

export const ATTACK_CATALOG: AttackTechnique[] = [
  // ── Initial Access ─────────────────────────────────────────────────────────
  { id: "T1190", name: "Exploit Public-Facing Application", tactics: ["Initial Access"], cwes: [89, 78, 79, 22, 434, 918, 611, 502, 94, 444], tags: ["sqli", "rce", "command-injection", "path-traversal", "xss", "upload", "ssrf", "xxe", "deserialization"] },
  { id: "T1133", name: "External Remote Services", tactics: ["Initial Access"], tags: ["vpn", "rdp", "exposed-service", "remote-access"] },
  { id: "T1078", name: "Valid Accounts", tactics: ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion", "Lateral Movement"], cwes: [287, 306, 862, 863, 798, 639, 347, 613], tags: ["auth", "authentication", "default-credentials", "hardcoded-credentials", "idor", "bola", "broken-access-control", "weak-auth", "jwt", "alg-none", "weak-secret", "broken-authentication"] },
  { id: "T1078.001", name: "Valid Accounts: Default Accounts", tactics: ["Initial Access"], tags: ["default-credentials", "default-account"] },
  { id: "T1195", name: "Supply Chain Compromise", tactics: ["Initial Access"], cwes: [1357, 1104], tags: ["supply-chain", "dependency", "malicious-package", "typosquatting"] },
  { id: "T1566", name: "Phishing", tactics: ["Initial Access"], cwes: [79, 601], tags: ["phishing", "open-redirect"] },
  { id: "T1189", name: "Drive-by Compromise", tactics: ["Initial Access"], cwes: [79], tags: ["xss", "waterhole"] },

  // ── Execution ──────────────────────────────────────────────────────────────
  { id: "T1059", name: "Command and Scripting Interpreter", tactics: ["Execution"], cwes: [78, 94, 77, 95], tags: ["rce", "command-injection", "code-injection", "os-command"] },
  { id: "T1203", name: "Exploitation for Client Execution", tactics: ["Execution"], cwes: [502, 787, 125, 416], tags: ["deserialization", "buffer-overflow", "use-after-free"] },
  { id: "T1053", name: "Scheduled Task/Job", tactics: ["Execution", "Persistence", "Privilege Escalation"], tags: ["cron", "scheduled-task", "persistence"] },

  // ── Persistence ────────────────────────────────────────────────────────────
  { id: "T1505.003", name: "Server Software Component: Web Shell", tactics: ["Persistence", "Execution"], cwes: [434, 22, 98], tags: ["webshell", "file-upload", "backdoor"] },
  { id: "T1136", name: "Create Account", tactics: ["Persistence"], tags: ["account-creation", "shadow-account"] },
  { id: "T1543", name: "Create or Modify System Process", tactics: ["Persistence", "Privilege Escalation"], tags: ["service-creation", "registry-run", "startup"] },

  // ── Privilege Escalation ───────────────────────────────────────────────────
  { id: "T1068", name: "Exploitation for Privilege Escalation", tactics: ["Privilege Escalation"], cwes: [787, 416, 269, 271], tags: ["privilege-escalation", "local-privilege", "sudo"] },
  { id: "T1548", name: "Abuse Elevation Control Mechanism", tactics: ["Privilege Escalation", "Defense Evasion"], cwes: [732], tags: ["sudo-misconfig", "setuid", "capability", "misconfig"] },
  { id: "T1611", name: "Escape to Host", tactics: ["Privilege Escalation", "Defense Evasion"], cwes: [250, 269], tags: ["container-escape", "privileged-container", "docker-socket", "host-mount"] },

  // ── Defense Evasion ────────────────────────────────────────────────────────
  { id: "T1070", name: "Indicator Removal on Host", tactics: ["Defense Evasion"], cwes: [117, 221], tags: ["log-tampering", "log-injection", "audit", "timestomp"] },
  { id: "T1027", name: "Obfuscated Files or Information", tactics: ["Defense Evasion"], tags: ["obfuscation", "base64", "encoded", "packed"] },
  { id: "T1574", name: "Hijack Execution Flow", tactics: ["Persistence", "Privilege Escalation", "Defense Evasion"], cwes: [427, 426], tags: ["dll-hijacking", "path-hijacking", "untrusted-search-path"] },
  { id: "T1562.001", name: "Impair Defenses: Disable or Modify Tools", tactics: ["Defense Evasion"], tags: ["disable-security", "kill-process", "defender-bypass"] },

  // ── Credential Access ──────────────────────────────────────────────────────
  { id: "T1110", name: "Brute Force", tactics: ["Credential Access"], cwes: [307, 521, 640], tags: ["brute-force", "weak-password", "password-spray", "rate-limit"] },
  { id: "T1110.001", name: "Brute Force: Password Guessing", tactics: ["Credential Access"], tags: ["weak-password", "password-guessing"] },
  { id: "T1552", name: "Unsecured Credentials", tactics: ["Credential Access"], cwes: [200, 522, 798, 256], tags: ["secret-exposure", "hardcoded-secret", "credentials", ".env", "api-key", "token", "aws-access-key", "service-account", "cloud-credential-exposure"] },
  { id: "T1111", name: "Multi-Factor Authentication Interception", tactics: ["Credential Access"], tags: ["mfa-bypass", "otp", "2fa"] },
  { id: "T1555", name: "Credentials from Password Stores", tactics: ["Credential Access"], tags: ["password-store", "keychain", "credential-dump"] },
  { id: "T1558.003", name: "Steal or Forge Kerberos Tickets: Kerberoasting", tactics: ["Credential Access"], tags: ["kerberoasting", "spn", "service-account", "kerberos"] },
  { id: "T1557.001", name: "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay", tactics: ["Credential Access", "Collection"], cwes: [300], tags: ["ntlm-relay", "smb-relay", "smb-signing", "llmnr", "nbns", "ldap-signing"] },

  // ── Discovery ──────────────────────────────────────────────────────────────
  { id: "T1046", name: "Network Service Discovery", tactics: ["Discovery"], tools: ["lan.port_scan", "lan.host_discovery", "web.probe"], tags: ["port-scan", "service-discovery", "open-ports"] },
  { id: "T1083", name: "File and Directory Discovery", tactics: ["Discovery"], cwes: [22, 552], tools: ["web.fuzz", "web.crawl"], tags: ["path-traversal", "directory-enum", "exposed-files"] },
  { id: "T1082", name: "System Information Discovery", tactics: ["Discovery"], tools: ["web.tech"], tags: ["fingerprint", "tech-stack", "banner"] },
  { id: "T1087", name: "Account Discovery", tactics: ["Discovery"], tags: ["user-enum", "account-enum"] },
  { id: "T1016", name: "System Network Configuration Discovery", tactics: ["Discovery"], tags: ["network-config", "dns", "subnet"] },
  { id: "T1135", name: "Network Share Discovery", tactics: ["Discovery"], cwes: [552, 284], tags: ["smb-share", "shared-folder", "open-share"] },
  { id: "T1596", name: "Search Open Technical Databases", tactics: ["Reconnaissance"], tools: ["web.subdomains"], tags: ["subdomain-enum", "osint", "certificate-transparency"] },
  { id: "T1595", name: "Active Scanning", tactics: ["Reconnaissance"], tools: ["web.scan", "web.crawl", "web.fuzz"], tags: ["scanning", "crawling", "recon"] },
  { id: "T1590", name: "Gather Victim Network Information", tactics: ["Reconnaissance"], tags: ["graphql-introspection", "schema-disclosure", "api-enumeration", "dns-recon", "dnssec"] },
  { id: "T1592", name: "Gather Victim Org Information", tactics: ["Reconnaissance"], tags: ["shadow-it", "saas-token-leak", "txt-record", "org-recon"] },
  { id: "T1589.002", name: "Gather Victim Identity Information: Email Addresses", tactics: ["Reconnaissance"], tags: ["email-harvesting", "employee-enumeration", "bec-surface"] },
  { id: "T1584.004", name: "Compromise Infrastructure: DNS Server", tactics: ["Resource Development"], cwes: [284], tags: ["subdomain-takeover", "dangling-dns", "dangling-cname"] },
  { id: "T1583.001", name: "Acquire Infrastructure: Domains", tactics: ["Resource Development"], tags: ["subdomain-takeover", "dangling-dns", "typosquat"] },
  { id: "T1586.002", name: "Compromise Accounts: Email Accounts", tactics: ["Resource Development"], cwes: [290], tags: ["dmarc-none", "spf-permissive", "spf-softfail", "bec", "email-spoofing"] },

  // ── Lateral Movement ───────────────────────────────────────────────────────
  { id: "T1021", name: "Remote Services", tactics: ["Lateral Movement"], tags: ["rdp", "ssh", "winrm", "vnc"] },
  { id: "T1570", name: "Lateral Tool Transfer", tactics: ["Lateral Movement"], tags: ["tool-transfer", "wget", "certutil"] },
  { id: "T1080", name: "Taint Shared Content", tactics: ["Lateral Movement"], tags: ["shared-content", "malicious-file"] },
  { id: "T1550", name: "Use Alternate Authentication Material", tactics: ["Lateral Movement", "Defense Evasion"], cwes: [287], tags: ["pass-the-hash", "token-reuse", "session-reuse"] },

  // ── Collection / Exfiltration ──────────────────────────────────────────────
  { id: "T1213", name: "Data from Information Repositories", tactics: ["Collection"], cwes: [200, 922], tags: ["data-exposure", "pii", "information-disclosure", "git-exposure"] },
  { id: "T1005", name: "Data from Local System", tactics: ["Collection"], cwes: [200, 522, 798], tags: ["data-exfiltration", "sensitive-files", "backup-exposed"] },
  { id: "T1041", name: "Exfiltration Over C2 Channel", tactics: ["Exfiltration"], cwes: [319, 311], tags: ["cleartext", "plaintext-transmission", "missing-tls"] },
  { id: "T1567", name: "Exfiltration Over Web Service", tactics: ["Exfiltration"], tags: ["data-exfil", "pastebin", "external-upload"] },

  // ── C2 / Proxy ─────────────────────────────────────────────────────────────
  { id: "T1071", name: "Application Layer Protocol", tactics: ["Command & Control"], tags: ["c2", "beacon", "webshell-c2"] },
  { id: "T1573", name: "Encrypted Channel", tactics: ["Command & Control", "Exfiltration"], cwes: [295, 326, 327], tags: ["weak-crypto", "self-signed", "invalid-cert", "tls"] },
  { id: "T1090", name: "Proxy", tactics: ["Command & Control", "Defense Evasion"], cwes: [918, 441], tags: ["ssrf", "proxy", "open-redirect"] },
  { id: "T1105", name: "Ingress Tool Transfer", tactics: ["Command & Control"], tags: ["download", "oob", "out-of-band"] },

  // ── Impact ─────────────────────────────────────────────────────────────────
  { id: "T1486", name: "Data Encrypted for Impact", tactics: ["Impact"], tags: ["ransomware", "encrypted-files", "ransom-note"] },
  { id: "T1490", name: "Inhibit System Recovery", tactics: ["Impact"], tags: ["backup-deletion", "shadow-copy", "vss"] },
  { id: "T1499", name: "Endpoint Denial of Service", tactics: ["Impact"], cwes: [400, 770, 799], tags: ["dos", "resource-exhaustion", "rate-limit"] },
  { id: "T1489", name: "Service Stop", tactics: ["Impact"], tags: ["service-stop", "kill-service"] },

  // ── Cloud / Container / Supply chain ───────────────────────────────────────
  { id: "T1526", name: "Cloud Service Discovery", tactics: ["Discovery"], tags: ["cloud-misconfig", "bucket-list", "aws", "azure", "gcp", "iam-overprivilege", "excessive-permissions", "wildcard-policy", "security-group", "0.0.0.0/0"] },
  { id: "T1530", name: "Data from Cloud Storage", tactics: ["Collection"], cwes: [200, 552], tags: ["open-bucket", "s3-exposure", "cloud-storage", "public-bucket", "unauthenticated-storage"] },
  { id: "T1610", name: "Deploy Container", tactics: ["Execution"], tags: ["container", "docker", "k8s", "kubernetes", "rbac", "cluster-admin"] },
  { id: "T1195.002", name: "Supply Chain Compromise: Compromise Software Dependencies", tactics: ["Initial Access"], tags: ["dependency-confusion", "malicious-dependency", "npm", "pypi"] },
]

const normalizedTags = (value: unknown) =>
  (Array.isArray(value) ? value : []).map((tag) => String(tag).toLowerCase())

const stringLike = (value: unknown) => (typeof value === "string" ? value.toLowerCase() : "")

export type FindingLike = {
  cwe?: string | number | null
  tags?: unknown
  sourceTool?: string | null
  title?: string | null
  vector?: string | null
}

export type AttackMatch = {
  id: string
  name: string
  tactics: string[]
  reason: string
}

function techniqueId(technique: AttackTechnique) {
  return technique.id.startsWith("T") ? technique.id : `T${technique.id}`
}

function matchCwe(technique: AttackTechnique, cwe: string) {
  if (!technique.cwes || !cwe) return false
  const normalized = cwe.replace(/^CWE-?/i, "")
  return technique.cwes.some((id) => normalized === String(id))
}

function matchTags(technique: AttackTechnique, tags: string[]) {
  if (!technique.tags) return false
  return technique.tags.some((tag) => tags.includes(tag))
}

function matchTools(technique: AttackTechnique, tool: string) {
  if (!technique.tools || !tool) return false
  return technique.tools.some((name) => tool === name || tool.startsWith(name))
}

function matchKeywords(technique: AttackTechnique, haystack: string) {
  if (!technique.keywords) return false
  return technique.keywords.some((keyword) => haystack.includes(keyword))
}

/**
 * Mapea un hallazgo a técnicas MITRE ATT&CK por heurísticas (CWE, tags, tool,
 * título/vector). Devuelve las técnicas con coincidencia, ordenadas por
 * número de señales, con la razón de cada coincidencia.
 */
export function mapFindingToAttack(finding: FindingLike): AttackMatch[] {
  const cwe = String(finding.cwe ?? "").toUpperCase()
  const tags = normalizedTags(finding.tags)
  const tool = stringLike(finding.sourceTool)
  const haystack = `${stringLike(finding.title)} ${stringLike(finding.vector)}`

  const matches: Array<{ technique: AttackTechnique; signals: string[] }> = []
  for (const technique of ATTACK_CATALOG) {
    const signals: string[] = []
    if (matchCwe(technique, cwe)) signals.push(`CWE ${cwe}`)
    if (matchTags(technique, tags)) {
      const hit = technique.tags!.find((tag) => tags.includes(tag))
      if (hit) signals.push(`tag:${hit}`)
    }
    if (matchTools(technique, tool)) signals.push(`tool:${tool}`)
    if (matchKeywords(technique, haystack)) signals.push("keyword")

    // El mapeo por tool/cwe genérico (T1190) no debe competir con un match más
    // específico por tag/tool si el hallazgo ya tiene señal explícita.
    if (signals.length > 0) matches.push({ technique, signals })
  }

  const deduped = new Map<string, { technique: AttackTechnique; signals: string[] }>()
  for (const match of matches) {
    const id = techniqueId(match.technique)
    const existing = deduped.get(id)
    if (!existing) {
      deduped.set(id, match)
      continue
    }
    // El más específico gana (sub-técnica con más señales).
    if (match.signals.length > existing.signals.length) deduped.set(id, match)
  }

  return Array.from(deduped.values())
    .sort((a, b) => b.signals.length - a.signals.length)
    .slice(0, 5)
    .map(({ technique, signals }) => ({
      id: techniqueId(technique),
      name: technique.name,
      tactics: [...technique.tactics],
      reason: signals.join(", "),
    }))
}

/** Devuelve el nombre de una técnica por ID (para UI). */
export function attackTechniqueName(id: string) {
  const technique = ATTACK_CATALOG.find((item) => techniqueId(item) === id)
  return technique?.name
}

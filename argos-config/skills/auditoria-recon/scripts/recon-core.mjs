import { parseArgs } from "util";
import dns from "dns/promises";
import { fileURLToPath } from "url";
function isEntryPoint() {
  try {
    return !!process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
  } catch {
    return false;
  }
}
async function fetchCrtSh(domain) {
  const url = `https://crt.sh/?q=%25.${domain}&output=json`;
  try {
    const controller = new AbortController();
    const tid = setTimeout(() => controller.abort(), 1e4);
    const res = await fetch(url, { signal: controller.signal });
    clearTimeout(tid);
    if (!res.ok) return [];
    const data = await res.json();
    const subdomains = /* @__PURE__ */ new Set();
    for (const entry of data) {
      if (entry.name_value) {
        for (const name of entry.name_value.split("\n")) {
          const cleanName = name.trim().toLowerCase();
          if (!cleanName.startsWith("*") && cleanName.endsWith(domain)) subdomains.add(cleanName);
        }
      }
    }
    return Array.from(subdomains);
  } catch {
    return [];
  }
}
function dmarcQueryName(target) {
  return `_dmarc.${target}`;
}
async function resolveSubdomains(subdomains, resolver = (hostname) => dns.resolve4(hostname)) {
  const CONCURRENCY = 20;
  const results = [];
  for (let i = 0; i < subdomains.length; i += CONCURRENCY) {
    const batch = subdomains.slice(i, i + CONCURRENCY);
    const batchResults = await Promise.all(
      batch.map(async (sub) => {
        try {
          const records = await resolver(sub);
          return { subdomain: sub, ips: records };
        } catch {
          return null;
        }
      })
    );
    for (const r of batchResults) if (r) results.push(r);
  }
  return results;
}
function main() {
  return {
    status: "blocked",
    coverage: "not-run",
    reason: "Live recon is disabled until Argos provides an isolated scope gateway for target and third-party requests."
  };
}
async function legacyMain() {
  const { positionals } = parseArgs({ args: process.argv.slice(2), strict: false });
  let target = positionals[0];
  if (!target) {
    console.error(JSON.stringify({ error: "No target provided. Usage: node recon-core.mjs <domain>" }));
    process.exit(1);
  }
  target = target.replace(/^https?:\/\//, "").split("/")[0];
  console.log(JSON.stringify({ status: "progress", message: `Iniciando reconocimiento OSINT para ${target}` }));
  const report = { target, timestamp: (/* @__PURE__ */ new Date()).toISOString(), findings: [], subdomains: [], mx_records: [], txt_records: [] };
  try {
    console.log(JSON.stringify({ status: "progress", message: `Buscando subdominios en crt.sh...` }));
    const rawSubdomains = await fetchCrtSh(target);
    if (rawSubdomains.length > 0) {
      console.log(JSON.stringify({ status: "progress", message: `${rawSubdomains.length} subdominios encontrados. Resolviendo IPs...` }));
      report.subdomains = await resolveSubdomains(rawSubdomains);
      report.findings.push({
        severity: "info",
        title: "Superficie de Ataque Expuesta",
        evidence: `${report.subdomains.length} subdominios activos con resoluci\xF3n DNS.`,
        remediation: "Revisar inventario de activos y dar de baja subdominios hu\xE9rfanos.",
        tags: ["subdomain-enum", "service-discovery", "information-disclosure"]
      });
    }
    try {
      const mx = await dns.resolveMx(target);
      report.mx_records = mx.map((m) => m.exchange);
    } catch {
    }
    try {
      const txt = await dns.resolveTxt(target);
      const flatTxt = txt.map((t) => t.join(""));
      report.txt_records = flatTxt;
      if (!flatTxt.some((t) => t.includes("v=spf1"))) {
        report.findings.push({
          severity: "medium",
          title: "Falta Registro SPF",
          evidence: "No se encontr\xF3 registro SPF.",
          remediation: "Configurar SPF para prevenir suplantaci\xF3n de correo.",
          tags: ["phishing", "spoof"]
        });
      }
    } catch {
    }
    try {
      const dmarcTxt = await dns.resolveTxt(dmarcQueryName(target));
      const flatDmarc = dmarcTxt.map((t) => t.join(""));
      if (!flatDmarc.some((t) => t.includes("v=DMARC1"))) {
        report.findings.push({
          severity: "low",
          title: "Pol\xEDtica DMARC D\xE9bil o Ausente",
          evidence: "El registro _dmarc existe pero no publica una pol\xEDtica v=DMARC1 v\xE1lida.",
          remediation: "Implementar DMARC (p=quarantine o p=reject) para monitorear y proteger el dominio.",
          tags: ["phishing", "spoof", "dmarc"]
        });
      }
    } catch {
      report.findings.push({
        severity: "low",
        title: "Falta Registro DMARC",
        evidence: `No se encontr\xF3 registro ${dmarcQueryName(target)}.`,
        remediation: "Implementar DMARC para monitorear y proteger el dominio contra suplantaci\xF3n.",
        tags: ["phishing", "spoof", "dmarc"]
      });
    }
    console.log(JSON.stringify({ status: "done", report }));
  } catch (error) {
    console.error(JSON.stringify({ error: String(error) }));
    process.exit(1);
  }
}
if (isEntryPoint()) {
  console.log(JSON.stringify(main()));
  process.exitCode = 3;
}
export {
  dmarcQueryName,
  main,
  resolveSubdomains
};

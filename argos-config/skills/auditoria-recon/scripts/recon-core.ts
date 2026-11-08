import { parseArgs } from "util";
import dns from "dns/promises";
import { fileURLToPath } from "url";

// import.meta.main es específico de Bun; bajo Node (como se ejecuta el .mjs
// compilado vía ELECTRON_RUN_AS_NODE, ver SKILL.md) es siempre undefined, así
// que se usa la comparación de argv[1] estándar, compatible con ambos runtimes.
function isEntryPoint(): boolean {
  try {
    return !!process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
  } catch {
    return false;
  }
}

interface SubdomainEntry {
  subdomain: string;
  ips: string[];
}

async function fetchCrtSh(domain: string): Promise<string[]> {
  const url = `https://crt.sh/?q=%25.${domain}&output=json`;
  try {
    const controller = new AbortController();
    const tid = setTimeout(() => controller.abort(), 10000);
    const res = await fetch(url, { signal: controller.signal });
    clearTimeout(tid);

    if (!res.ok) return [];

    const data: { name_value?: string }[] = await res.json();
    const subdomains = new Set<string>();

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

/** Nombre del registro TXT donde vive la política DMARC (nunca el dominio raíz). */
export function dmarcQueryName(target: string): string {
  return `_dmarc.${target}`;
}

export async function resolveSubdomains(
  subdomains: string[],
  resolver: (hostname: string) => Promise<string[]> = (hostname) => dns.resolve4(hostname),
): Promise<SubdomainEntry[]> {
  // Concurrencia acotada: resolver cientos de subdominios en serie puede tardar
  // minutos; en paralelo sin límite puede saturar el resolver DNS local.
  const CONCURRENCY = 20;
  const results: SubdomainEntry[] = [];

  for (let i = 0; i < subdomains.length; i += CONCURRENCY) {
    const batch = subdomains.slice(i, i + CONCURRENCY);
    const batchResults = await Promise.all(
      batch.map(async (sub) => {
        try {
          const records = await resolver(sub);
          return { subdomain: sub, ips: records };
        } catch {
          return null; // no resuelve, se ignora
        }
      }),
    );
    for (const r of batchResults) if (r) results.push(r);
  }
  return results;
}

export function main() {
  return {
    status: "blocked",
    coverage: "not-run",
    reason: "Live recon is disabled until Argos provides an isolated scope gateway for target and third-party requests.",
  } as const;
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

  const report: {
    target: string;
    timestamp: string;
    findings: { severity: string; title: string; evidence: string; remediation: string; tags: string[]; cwe?: string }[];
    subdomains: SubdomainEntry[];
    mx_records: string[];
    txt_records: string[];
  } = { target, timestamp: new Date().toISOString(), findings: [], subdomains: [], mx_records: [], txt_records: [] };

  try {
    console.log(JSON.stringify({ status: "progress", message: `Buscando subdominios en crt.sh...` }));
    const rawSubdomains = await fetchCrtSh(target);

    if (rawSubdomains.length > 0) {
      console.log(JSON.stringify({ status: "progress", message: `${rawSubdomains.length} subdominios encontrados. Resolviendo IPs...` }));
      report.subdomains = await resolveSubdomains(rawSubdomains);

      report.findings.push({
        severity: "info",
        title: "Superficie de Ataque Expuesta",
        evidence: `${report.subdomains.length} subdominios activos con resolución DNS.`,
        remediation: "Revisar inventario de activos y dar de baja subdominios huérfanos.",
        tags: ["subdomain-enum", "service-discovery", "information-disclosure"],
      });
    }

    try {
      const mx = await dns.resolveMx(target);
      report.mx_records = mx.map(m => m.exchange);
    } catch { /* no MX */ }

    // SPF vive en el TXT del dominio raíz.
    try {
      const txt = await dns.resolveTxt(target);
      const flatTxt = txt.map(t => t.join(""));
      report.txt_records = flatTxt;

      if (!flatTxt.some(t => t.includes("v=spf1"))) {
        report.findings.push({
          severity: "medium",
          title: "Falta Registro SPF",
          evidence: "No se encontró registro SPF.",
          remediation: "Configurar SPF para prevenir suplantación de correo.",
          tags: ["phishing", "spoof"],
        });
      }
    } catch { /* no TXT */ }

    // DMARC vive en _dmarc.<dominio>, no en el TXT del dominio raíz.
    try {
      const dmarcTxt = await dns.resolveTxt(dmarcQueryName(target));
      const flatDmarc = dmarcTxt.map(t => t.join(""));

      if (!flatDmarc.some(t => t.includes("v=DMARC1"))) {
        report.findings.push({
          severity: "low",
          title: "Política DMARC Débil o Ausente",
          evidence: "El registro _dmarc existe pero no publica una política v=DMARC1 válida.",
          remediation: "Implementar DMARC (p=quarantine o p=reject) para monitorear y proteger el dominio.",
          tags: ["phishing", "spoof", "dmarc"],
        });
      }
    } catch {
      // NXDOMAIN / sin registro _dmarc: DMARC no está configurado en absoluto.
      report.findings.push({
        severity: "low",
        title: "Falta Registro DMARC",
        evidence: `No se encontró registro ${dmarcQueryName(target)}.`,
        remediation: "Implementar DMARC para monitorear y proteger el dominio contra suplantación.",
        tags: ["phishing", "spoof", "dmarc"],
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

import { parseArgs } from "util";
import { readFileSync } from "fs";
import { join } from "path";
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

const WORDLIST: string[] = (() => {
  try {
    const wordlistPath = join(import.meta.dirname, "wordlists", "common.txt");
    const content = readFileSync(wordlistPath, "utf-8");
    const entries = content.split(/\r?\n/).filter(line => line.trim() && !line.startsWith("#"));
    console.log(JSON.stringify({ status: "info", message: `Wordlist cargado con ${entries.length} rutas.` }));
    return entries;
  } catch {
    return [
      ".env", ".git/config", "wp-config.php.bak", "backup.zip", "api/v1/users",
      "swagger.json", "swagger-ui.html", "graphql", "admin/", "server-status",
      ".htaccess", "robots.txt", "sitemap.xml", "phpinfo.php",
    ];
  }
})();

const SECURE_HEADERS = [
  "Strict-Transport-Security",
  "Content-Security-Policy",
  "X-Frame-Options",
  "X-Content-Type-Options",
];

const USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/604.1",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
];

function randomUA() {
  return USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
}

export function extractLinks(html: string, base: string): string[] {
  const linkRegex = /href=["'](https?:\/\/[^"']+|\/[^"']+)["']/g;
  const links = new Set<string>();
  let match;
  while ((match = linkRegex.exec(html)) !== null) {
    try {
      const resolved = new URL(match[1], base).toString();
      links.add(resolved);
    } catch { /* href inválido, se ignora */ }
  }
  return Array.from(links);
}

/** Crawl real de profundidad 1: sigue los enlaces del mismo origen encontrados en la página inicial. */
export async function shallowCrawl(target: string, maxPages = 20): Promise<{ crawledUrls: string[]; pagesVisited: number }> {
  const origin = new URL(target).origin;
  const visited = new Set<string>();
  const allLinks = new Set<string>();

  const fetchPage = async (url: string): Promise<string[]> => {
    try {
      const c = new AbortController();
      const tid = setTimeout(() => c.abort(), 6000);
      const res = await fetch(url, { headers: { "User-Agent": randomUA() }, signal: c.signal });
      clearTimeout(tid);
      if (!res.ok) return [];
      const html = await res.text();
      return extractLinks(html, url);
    } catch {
      return [];
    }
  };

  const rootLinks = await fetchPage(target);
  visited.add(target);
  for (const link of rootLinks) allLinks.add(link);

  const sameOriginToVisit = rootLinks
    .filter(link => { try { return new URL(link).origin === origin; } catch { return false; } })
    .filter(link => !visited.has(link))
    .slice(0, maxPages);

  const CONCURRENCY = 5;
  for (let i = 0; i < sameOriginToVisit.length; i += CONCURRENCY) {
    const batch = sameOriginToVisit.slice(i, i + CONCURRENCY);
    const results = await Promise.all(batch.map(fetchPage));
    for (const url of batch) visited.add(url);
    for (const links of results) for (const link of links) allLinks.add(link);
  }

  return { crawledUrls: Array.from(allLinks), pagesVisited: visited.size };
}

export async function batchFetch(urls: string[], concurrency = 20) {
  const results: { url: string; status: number }[] = [];
  for (let i = 0; i < urls.length; i += concurrency) {
    const batch = urls.slice(i, i + concurrency);
    const batchResults = await Promise.all(
      batch.map(async (url) => {
        try {
          const c = new AbortController();
          const tid = setTimeout(() => c.abort(), 5000);
          // manual: no seguir redirects automáticamente, un 301/302 a login
          // también es una señal de que la ruta existe.
          const r = await fetch(url, { method: "GET", headers: { "User-Agent": randomUA() }, signal: c.signal, redirect: "manual" });
          clearTimeout(tid);
          if (r.status === 200 || r.status === 301 || r.status === 302 || r.status === 403) {
            return { url, status: r.status };
          }
        } catch { /* ignore network errors */ }
        return null;
      })
    );
    for (const r of batchResults) {
      if (r) results.push(r);
    }
  }
  return results;
}

export function main() {
  return {
    status: "blocked",
    coverage: "not-run",
    reason: "Live web audits are disabled until Argos provides a pinned worker image and isolated scope gateway.",
  } as const;
}

async function legacyMain() {
  const { positionals } = parseArgs({ args: process.argv.slice(2), strict: false });
  let target = positionals[0];

  if (!target) {
    console.error(JSON.stringify({ error: "No target provided. Usage: node web-core.mjs <url>" }));
    process.exit(1);
  }

  if (!target.startsWith("http")) target = "http://" + target;
  target = target.replace(/\/$/, "");

  console.log(JSON.stringify({ status: "progress", message: `Iniciando auditoría web de ${target}` }));

  const report: {
    target: string;
    timestamp: string;
    findings: { severity: string; title: string; evidence: string; remediation: string; tags: string[]; cwe?: string }[];
    crawled_urls: string[];
    pages_visited: number;
    fuzzing_hits: { url: string; status: number }[];
  } = { target, timestamp: new Date().toISOString(), findings: [], crawled_urls: [], pages_visited: 0, fuzzing_hits: [] };

  try {
    console.log(JSON.stringify({ status: "progress", message: `Analizando cabeceras...` }));
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);

    const res = await fetch(target, { headers: { "User-Agent": randomUA() }, signal: controller.signal }).catch(() => null);
    clearTimeout(timeoutId);

    if (res) {
      const missingHeaders = SECURE_HEADERS.filter(h => !res.headers.get(h));
      if (missingHeaders.length > 0) {
        report.findings.push({
          severity: "low",
          title: "Cabeceras de Seguridad Faltantes",
          evidence: `Faltan: ${missingHeaders.join(", ")}`,
          remediation: "Configure las cabeceras de seguridad recomendadas por OWASP.",
          tags: missingHeaders.some(h => h === "Strict-Transport-Security") ? ["missing-hsts", "hsts"] : ["missing-tls"],
        });
      }

      const serverHeader = res.headers.get("server") || res.headers.get("x-powered-by");
      if (serverHeader) {
        report.findings.push({
          severity: "info",
          title: "Exposición de Tecnología del Servidor",
          evidence: `Header expuesto: ${serverHeader}`,
          remediation: "Oculte versiones del servidor para evitar perfilado tecnológico.",
          tags: ["information-disclosure", "fingerprint"],
          cwe: "200",
        });
      }

      const text = await res.text();
      if (text.includes("<form") && target.startsWith("http://")) {
        report.findings.push({
          severity: "medium",
          title: "Formularios sobre HTTP inseguro",
          evidence: "Se detectó un <form> en conexión sin encriptar.",
          remediation: "Migrar a HTTPS e implementar HSTS.",
          tags: ["cleartext", "plaintext", "missing-tls"],
          cwe: "319",
        });
      }
    } else {
      report.findings.push({
        severity: "high",
        title: "Objetivo Inalcanzable",
        evidence: `No se pudo conectar a ${target}`,
        remediation: "Verificar disponibilidad del objetivo o filtros de red.",
        tags: ["exposed-service"],
      });
    }

    console.log(JSON.stringify({ status: "progress", message: `Crawling (profundidad 1, hasta 20 páginas del mismo origen)...` }));
    const { crawledUrls, pagesVisited } = await shallowCrawl(target);
    report.crawled_urls = crawledUrls;
    report.pages_visited = pagesVisited;

    console.log(JSON.stringify({ status: "progress", message: `Fuzzing de rutas (${WORDLIST.length} payloads, concurrencia 20)...` }));
    const fuzzUrls = WORDLIST.map(path => `${target}/${path}`);
    report.fuzzing_hits = await batchFetch(fuzzUrls, 20);

    for (const hit of report.fuzzing_hits) {
      const isSensitiveFile = hit.url.includes(".env") || hit.url.includes(".git") || hit.url.includes("backup");
      const isAdminSurface = hit.url.includes("admin") || hit.url.includes("swagger") || hit.url.includes("graphql");

      let severity = "info";
      const tags = ["exposed-files", "directory-enum"];
      let cwe: string | undefined;

      if (isSensitiveFile) {
        severity = "high";
        tags.push("secret-exposure", "information-disclosure");
        if (hit.url.includes(".env")) tags.push(".env");
        if (hit.url.includes(".git")) tags.push("git-exposure");
        cwe = "200";
      } else if (isAdminSurface) {
        severity = "medium";
        tags.push("information-disclosure");
      }

      // Un 403/301/302 confirma que la ruta existe (protegida o redirigida),
      // no que esté abierta — se reporta con menor confianza que un 200.
      const statusNote = hit.status === 200 ? "accesible (HTTP 200)" : `existe, protegida/redirigida (HTTP ${hit.status})`;

      report.findings.push({
        severity: hit.status === 200 ? severity : (severity === "high" ? "medium" : "info"),
        title: "Ruta Sensible Expuesta",
        evidence: `Ruta ${statusNote}: ${hit.url}`,
        remediation: "Restringir acceso a directorios administrativos, .env y repositorios.",
        tags,
        cwe,
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

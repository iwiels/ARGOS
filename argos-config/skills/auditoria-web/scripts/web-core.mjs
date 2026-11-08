import { parseArgs } from "util";
import { readFileSync } from "fs";
import { join } from "path";
import { fileURLToPath } from "url";
function isEntryPoint() {
  try {
    return !!process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
  } catch {
    return false;
  }
}
const WORDLIST = (() => {
  try {
    const wordlistPath = join(import.meta.dirname, "wordlists", "common.txt");
    const content = readFileSync(wordlistPath, "utf-8");
    const entries = content.split(/\r?\n/).filter((line) => line.trim() && !line.startsWith("#"));
    console.log(JSON.stringify({ status: "info", message: `Wordlist cargado con ${entries.length} rutas.` }));
    return entries;
  } catch {
    return [
      ".env",
      ".git/config",
      "wp-config.php.bak",
      "backup.zip",
      "api/v1/users",
      "swagger.json",
      "swagger-ui.html",
      "graphql",
      "admin/",
      "server-status",
      ".htaccess",
      "robots.txt",
      "sitemap.xml",
      "phpinfo.php"
    ];
  }
})();
const SECURE_HEADERS = [
  "Strict-Transport-Security",
  "Content-Security-Policy",
  "X-Frame-Options",
  "X-Content-Type-Options"
];
const USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/604.1",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36"
];
function randomUA() {
  return USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
}
function extractLinks(html, base) {
  const linkRegex = /href=["'](https?:\/\/[^"']+|\/[^"']+)["']/g;
  const links = /* @__PURE__ */ new Set();
  let match;
  while ((match = linkRegex.exec(html)) !== null) {
    try {
      const resolved = new URL(match[1], base).toString();
      links.add(resolved);
    } catch {
    }
  }
  return Array.from(links);
}
async function shallowCrawl(target, maxPages = 20) {
  const origin = new URL(target).origin;
  const visited = /* @__PURE__ */ new Set();
  const allLinks = /* @__PURE__ */ new Set();
  const fetchPage = async (url) => {
    try {
      const c = new AbortController();
      const tid = setTimeout(() => c.abort(), 6e3);
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
  const sameOriginToVisit = rootLinks.filter((link) => {
    try {
      return new URL(link).origin === origin;
    } catch {
      return false;
    }
  }).filter((link) => !visited.has(link)).slice(0, maxPages);
  const CONCURRENCY = 5;
  for (let i = 0; i < sameOriginToVisit.length; i += CONCURRENCY) {
    const batch = sameOriginToVisit.slice(i, i + CONCURRENCY);
    const results = await Promise.all(batch.map(fetchPage));
    for (const url of batch) visited.add(url);
    for (const links of results) for (const link of links) allLinks.add(link);
  }
  return { crawledUrls: Array.from(allLinks), pagesVisited: visited.size };
}
async function batchFetch(urls, concurrency = 20) {
  const results = [];
  for (let i = 0; i < urls.length; i += concurrency) {
    const batch = urls.slice(i, i + concurrency);
    const batchResults = await Promise.all(
      batch.map(async (url) => {
        try {
          const c = new AbortController();
          const tid = setTimeout(() => c.abort(), 5e3);
          const r = await fetch(url, { method: "GET", headers: { "User-Agent": randomUA() }, signal: c.signal, redirect: "manual" });
          clearTimeout(tid);
          if (r.status === 200 || r.status === 301 || r.status === 302 || r.status === 403) {
            return { url, status: r.status };
          }
        } catch {
        }
        return null;
      })
    );
    for (const r of batchResults) {
      if (r) results.push(r);
    }
  }
  return results;
}
function main() {
  return {
    status: "blocked",
    coverage: "not-run",
    reason: "Live web audits are disabled until Argos provides a pinned worker image and isolated scope gateway."
  };
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
  console.log(JSON.stringify({ status: "progress", message: `Iniciando auditor\xEDa web de ${target}` }));
  const report = { target, timestamp: (/* @__PURE__ */ new Date()).toISOString(), findings: [], crawled_urls: [], pages_visited: 0, fuzzing_hits: [] };
  try {
    console.log(JSON.stringify({ status: "progress", message: `Analizando cabeceras...` }));
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 1e4);
    const res = await fetch(target, { headers: { "User-Agent": randomUA() }, signal: controller.signal }).catch(() => null);
    clearTimeout(timeoutId);
    if (res) {
      const missingHeaders = SECURE_HEADERS.filter((h) => !res.headers.get(h));
      if (missingHeaders.length > 0) {
        report.findings.push({
          severity: "low",
          title: "Cabeceras de Seguridad Faltantes",
          evidence: `Faltan: ${missingHeaders.join(", ")}`,
          remediation: "Configure las cabeceras de seguridad recomendadas por OWASP.",
          tags: missingHeaders.some((h) => h === "Strict-Transport-Security") ? ["missing-hsts", "hsts"] : ["missing-tls"]
        });
      }
      const serverHeader = res.headers.get("server") || res.headers.get("x-powered-by");
      if (serverHeader) {
        report.findings.push({
          severity: "info",
          title: "Exposici\xF3n de Tecnolog\xEDa del Servidor",
          evidence: `Header expuesto: ${serverHeader}`,
          remediation: "Oculte versiones del servidor para evitar perfilado tecnol\xF3gico.",
          tags: ["information-disclosure", "fingerprint"],
          cwe: "200"
        });
      }
      const text = await res.text();
      if (text.includes("<form") && target.startsWith("http://")) {
        report.findings.push({
          severity: "medium",
          title: "Formularios sobre HTTP inseguro",
          evidence: "Se detect\xF3 un <form> en conexi\xF3n sin encriptar.",
          remediation: "Migrar a HTTPS e implementar HSTS.",
          tags: ["cleartext", "plaintext", "missing-tls"],
          cwe: "319"
        });
      }
    } else {
      report.findings.push({
        severity: "high",
        title: "Objetivo Inalcanzable",
        evidence: `No se pudo conectar a ${target}`,
        remediation: "Verificar disponibilidad del objetivo o filtros de red.",
        tags: ["exposed-service"]
      });
    }
    console.log(JSON.stringify({ status: "progress", message: `Crawling (profundidad 1, hasta 20 p\xE1ginas del mismo origen)...` }));
    const { crawledUrls, pagesVisited } = await shallowCrawl(target);
    report.crawled_urls = crawledUrls;
    report.pages_visited = pagesVisited;
    console.log(JSON.stringify({ status: "progress", message: `Fuzzing de rutas (${WORDLIST.length} payloads, concurrencia 20)...` }));
    const fuzzUrls = WORDLIST.map((path) => `${target}/${path}`);
    report.fuzzing_hits = await batchFetch(fuzzUrls, 20);
    for (const hit of report.fuzzing_hits) {
      const isSensitiveFile = hit.url.includes(".env") || hit.url.includes(".git") || hit.url.includes("backup");
      const isAdminSurface = hit.url.includes("admin") || hit.url.includes("swagger") || hit.url.includes("graphql");
      let severity = "info";
      const tags = ["exposed-files", "directory-enum"];
      let cwe;
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
      const statusNote = hit.status === 200 ? "accesible (HTTP 200)" : `existe, protegida/redirigida (HTTP ${hit.status})`;
      report.findings.push({
        severity: hit.status === 200 ? severity : severity === "high" ? "medium" : "info",
        title: "Ruta Sensible Expuesta",
        evidence: `Ruta ${statusNote}: ${hit.url}`,
        remediation: "Restringir acceso a directorios administrativos, .env y repositorios.",
        tags,
        cwe
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
  batchFetch,
  extractLinks,
  main,
  shallowCrawl
};

/**
 * Export HTML autocontenido.
 *
 * Un único archivo: el CSS y el JS van embebidos y no hay una sola referencia
 * a un asset externo (ni fuentes, ni scripts, ni hojas de estilo remotas). El
 * logo del cliente llega como data URL, así que el informe se puede mandar por
 * email sin adjuntos sueltos y se ve igual en un visor sin red.
 *
 * El JS embebido sólo sirve para filtrar y plegar los hallazgos: el informe
 * completo se lee igual con el JavaScript deshabilitado.
 */

import { reportContentHash, toIsoDateTime, type ReportDocument, type ReportFinding, type ReportSeverity } from "./model"

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;")
}

const SEVERITY_LABEL: Record<ReportSeverity, string> = {
  critical: "Crítico",
  high: "Alto",
  medium: "Medio",
  low: "Bajo",
  info: "Informativo",
}

const STYLE = `
:root {
  --bg: #0b1020;
  --surface: #131a2e;
  --surface-2: #1b2440;
  --border: #2a3556;
  --text: #eef2ff;
  --muted: #9aa8c7;
  --accent: #38bdf8;
  --critical: #ef4444;
  --high: #f97316;
  --medium: #eab308;
  --low: #3b82f6;
  --info: #64748b;
}
@media (prefers-color-scheme: light) {
  :root {
    --bg: #f6f8fc;
    --surface: #ffffff;
    --surface-2: #f1f5f9;
    --border: #dbe3ef;
    --text: #0f172a;
    --muted: #5b6b85;
    --accent: #0369a1;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 2.5rem 1rem;
  background: var(--bg);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  line-height: 1.6;
}
.wrap { max-width: 62rem; margin: 0 auto; }
.banner {
  display: inline-block;
  padding: .3rem .8rem;
  border-radius: 999px;
  font: 700 .72rem/1.2 ui-monospace, SFMono-Regular, Menlo, monospace;
  letter-spacing: .08em;
  text-transform: uppercase;
  color: var(--critical);
  border: 1px solid var(--critical);
  background: color-mix(in srgb, var(--critical) 12%, transparent);
}
h1 { font-size: 1.9rem; line-height: 1.15; margin: .6rem 0 .3rem; }
h2 { font-size: 1.3rem; margin: 2.2rem 0 .8rem; padding-bottom: .4rem; border-bottom: 1px solid var(--border); }
h3 { font-size: 1.05rem; margin: 0 0 .4rem; }
p { margin: 0 0 .8rem; }
.muted { color: var(--muted); }
.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 1.1rem 1.25rem;
  margin-bottom: 1rem;
}
.meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(13rem, 1fr)); gap: .9rem; }
.meta dt { font-size: .72rem; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); }
.meta dd { margin: .15rem 0 0; font-weight: 600; }
.kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(8.5rem, 1fr)); gap: .8rem; }
.kpi { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: .9rem; text-align: center; }
.kpi b { display: block; font: 800 1.6rem/1.1 ui-monospace, SFMono-Regular, Menlo, monospace; }
.kpi span { font-size: .72rem; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); }
.badge {
  display: inline-block; padding: .15rem .55rem; border-radius: 999px;
  font: 700 .7rem/1.3 ui-monospace, SFMono-Regular, Menlo, monospace; text-transform: uppercase;
  border: 1px solid currentColor;
}
.sev-critical { color: var(--critical); } .sev-high { color: var(--high); }
.sev-medium { color: var(--medium); } .sev-low { color: var(--low); } .sev-info { color: var(--info); }
.finding { background: var(--surface); border: 1px solid var(--border); border-left: 4px solid var(--border); border-radius: 12px; padding: 1.1rem 1.25rem; margin-bottom: 1rem; }
.finding[data-severity="critical"] { border-left-color: var(--critical); }
.finding[data-severity="high"] { border-left-color: var(--high); }
.finding[data-severity="medium"] { border-left-color: var(--medium); }
.finding[data-severity="low"] { border-left-color: var(--low); }
.finding[data-severity="info"] { border-left-color: var(--info); }
.finding-head { display: flex; justify-content: space-between; gap: 1rem; align-items: flex-start; }
.meta-line { font: .78rem/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; color: var(--muted); margin: .5rem 0; }
pre {
  background: var(--surface-2); border: 1px solid var(--border); border-radius: 8px;
  padding: .7rem .8rem; overflow-x: auto; font: .8rem/1.5 ui-monospace, SFMono-Regular, Menlo, monospace;
  white-space: pre-wrap; word-break: break-word;
}
code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
table { width: 100%; border-collapse: collapse; font-size: .88rem; }
th, td { text-align: left; padding: .5rem .6rem; border-bottom: 1px solid var(--border); }
th { color: var(--muted); font-size: .74rem; text-transform: uppercase; letter-spacing: .05em; }
.toolbar { display: flex; flex-wrap: wrap; gap: .6rem; align-items: center; margin: 1rem 0 1.4rem; }
.toolbar input, .toolbar select {
  background: var(--surface); color: var(--text); border: 1px solid var(--border);
  border-radius: 8px; padding: .45rem .6rem; font: inherit; font-size: .85rem;
}
.toolbar input { min-width: 16rem; }
.count { margin-left: auto; font-size: .8rem; color: var(--muted); }
footer { margin-top: 2.5rem; padding-top: 1rem; border-top: 1px solid var(--border); font-size: .78rem; color: var(--muted); }
@media print {
  body { background: #fff; color: #000; padding: 0; }
  .toolbar { display: none; }
  .card, .finding, .kpi { border-color: #cbd5e1; background: #fff; break-inside: avoid; }
  .finding { page-break-inside: avoid; }
}
`

const SCRIPT = `
(function () {
  var input = document.getElementById("q");
  var select = document.getElementById("sev");
  var count = document.getElementById("count");
  var cards = Array.prototype.slice.call(document.querySelectorAll(".finding"));
  function apply() {
    var q = (input && input.value ? input.value : "").toLowerCase().trim();
    var sev = select ? select.value : "";
    var visible = 0;
    cards.forEach(function (card) {
      var okSev = !sev || card.getAttribute("data-severity") === sev;
      var okText = !q || (card.getAttribute("data-search") || "").indexOf(q) !== -1;
      var show = okSev && okText;
      card.style.display = show ? "" : "none";
      if (show) visible++;
    });
    if (count) count.textContent = visible + " / " + cards.length + " hallazgos visibles";
  }
  if (input) input.addEventListener("input", apply);
  if (select) select.addEventListener("change", apply);
  apply();
})();
`

function findingCard(finding: ReportFinding, index: number): string {
  const search = [finding.id, finding.title, finding.cwe, finding.target, finding.sourceTool, finding.evidence]
    .filter(Boolean)
    .join(" ")
    .toLowerCase()
  const attack = finding.attackTechniqueIds?.length
    ? `<div class="meta-line"><strong>MITRE ATT&amp;CK:</strong> ${escapeHtml(finding.attackTechniqueIds.join(", "))}</div>`
    : ""
  const evidence = finding.evidence
    ? `<h3>Evidencia técnica / PoC</h3><pre><code>${escapeHtml(finding.evidence)}</code></pre>`
    : ""
  const feedback = finding.feedback
    ? `<div class="meta-line"><strong>Triage:</strong> ${escapeHtml(finding.feedback.verdict)} (${escapeHtml(finding.feedback.actor)})${finding.feedback.reason ? ` — ${escapeHtml(finding.feedback.reason)}` : ""}</div>`
    : ""
  const curl = finding.curlCommand
    ? `<h3>Reproducción (cURL)</h3><pre><code>${escapeHtml(finding.curlCommand)}</code></pre>`
    : ""
  const request = finding.httpRequest
    ? `<h3>Petición HTTP</h3><pre><code>${escapeHtml(finding.httpRequest)}</code></pre>`
    : ""
  const response = finding.httpResponse
    ? `<h3>Respuesta HTTP</h3><pre><code>${escapeHtml(finding.httpResponse)}</code></pre>`
    : ""
  return `<article class="finding" data-severity="${escapeHtml(finding.severity)}" data-search="${escapeHtml(search)}">
  <div class="finding-head">
    <div>
      <div class="meta-line">${escapeHtml(finding.id)}</div>
      <h3>${index}. ${escapeHtml(finding.title)}</h3>
    </div>
    <div><span class="badge sev-${escapeHtml(finding.severity)}">${escapeHtml(SEVERITY_LABEL[finding.severity] ?? finding.severity)}</span>${finding.cvssScore !== undefined ? `<div class="meta-line">CVSS ${finding.cvssScore.toFixed(1)}</div>` : ""}</div>
  </div>
  <div class="meta-line">
    ${finding.cwe ? `<strong>CWE:</strong> ${escapeHtml(finding.cwe)} &nbsp;·&nbsp; ` : ""}
    ${finding.target ? `<strong>Objetivo:</strong> <code>${escapeHtml(finding.target)}</code> &nbsp;·&nbsp; ` : ""}
    <strong>Estado:</strong> ${escapeHtml(finding.status)}
  </div>
  ${feedback}${attack}
  ${evidence}${curl}${request}${response}
  <h3>Remediación</h3>
  <p>${escapeHtml(finding.remediation ?? "Aplicar controles defensivos, validación estricta de entradas y actualización de los componentes afectados.")}</p>
</article>`
}

export function exportHtml(document: ReportDocument): string {
  const { meta, summary, findings } = document
  const contentHash = reportContentHash(document)
  const logo = meta.clientLogoDataUrl
    ? `<img src="${escapeHtml(meta.clientLogoDataUrl)}" alt="Logo del cliente" style="max-height:72px;max-width:260px;object-fit:contain;margin:.8rem 0" />`
    : ""

  return `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta name="generator" content="argos-security-operations" />
<meta name="classification" content="${escapeHtml(meta.classification)}" />
<title>${escapeHtml(meta.title)}</title>
<style>${STYLE}</style>
</head>
<body>
<div class="wrap">
  <span class="banner">${escapeHtml(meta.classification)}</span>
  <h1>${escapeHtml(meta.title)}</h1>
  <p class="muted">Informe oficial de auditoría de seguridad y evaluación de vulnerabilidades</p>
  ${logo}

  <section class="card">
    <dl class="meta">
      <div><dt>Cliente</dt><dd>${escapeHtml(meta.clientName)}</dd></div>
      ${meta.clientLegalName ? `<div><dt>Razón social</dt><dd>${escapeHtml(meta.clientLegalName)}</dd></div>` : ""}
      <div><dt>Alcance autorizado</dt><dd>${escapeHtml(meta.scope)}</dd></div>
      <div><dt>Auditor responsable</dt><dd>${escapeHtml(meta.leadAuditor)}</dd></div>
      <div><dt>Metodología</dt><dd>${escapeHtml(meta.methodology)}</dd></div>
      <div><dt>Fecha de emisión</dt><dd>${escapeHtml(toIsoDateTime(meta.generatedAt))}</dd></div>
      <div><dt>Sesión</dt><dd><code>${escapeHtml(meta.sessionID)}</code></dd></div>
      <div><dt>Hash del contenido</dt><dd><code>${escapeHtml(contentHash)}</code></dd></div>
    </dl>
  </section>

  <h2>1. Resumen ejecutivo</h2>
  <section class="card">
    <p><strong>Riesgo global:</strong> <span class="badge sev-${escapeHtml(summary.globalRisk)}">${escapeHtml(summary.globalRisk.toUpperCase())}</span></p>
    <p class="muted">${summary.totalFindings} hallazgos sobre ${summary.targets.length} objetivo(s) evaluados.</p>
  </section>

  <section class="kpis">
    <div class="kpi"><b>${summary.totalFindings}</b><span>Hallazgos</span></div>
    <div class="kpi"><b style="color:var(--critical)">${summary.counts.critical}</b><span>Críticos</span></div>
    <div class="kpi"><b style="color:var(--high)">${summary.counts.high}</b><span>Altos</span></div>
    <div class="kpi"><b style="color:var(--medium)">${summary.counts.medium}</b><span>Medios</span></div>
    <div class="kpi"><b>${summary.averageCvss.toFixed(1)}</b><span>CVSS promedio</span></div>
  </section>

  <h2>2. Objetivos evaluados</h2>
  <section class="card">
    <table>
      <thead><tr><th>Objetivo</th><th>Total</th><th>Críticos</th><th>Altos</th><th>Medios</th><th>Bajos</th></tr></thead>
      <tbody>
        ${summary.targets
          .map(
            (target) =>
              `<tr><td><code>${escapeHtml(target.url)}</code></td><td>${target.total}</td><td>${target.counts.critical}</td><td>${target.counts.high}</td><td>${target.counts.medium}</td><td>${target.counts.low}</td></tr>`,
          )
          .join("")}
      </tbody>
    </table>
  </section>

  <h2>3. Detalle de vulnerabilidades</h2>
  <div class="toolbar">
    <input id="q" type="search" placeholder="Buscar por título, CWE, objetivo o evidencia" aria-label="Buscar hallazgos" />
    <select id="sev" aria-label="Filtrar por severidad">
      <option value="">Todas las severidades</option>
      <option value="critical">Crítico</option>
      <option value="high">Alto</option>
      <option value="medium">Medio</option>
      <option value="low">Bajo</option>
      <option value="info">Informativo</option>
    </select>
    <span class="count" id="count"></span>
  </div>
  ${findings.length === 0 ? `<section class="card muted">No se identificaron hallazgos en esta auditoría.</section>` : ""}
  ${findings.map((finding, index) => findingCard(finding, index + 1)).join("\n")}

  <h2>4. Control de emisión y aprobaciones</h2>
  <section class="card">
    <table>
      <thead><tr><th>Rol</th><th>Responsable</th><th>Fecha</th><th>Estado</th></tr></thead>
      <tbody>
        <tr><td>Auditor responsable</td><td>${escapeHtml(meta.leadAuditor)}</td><td>${escapeHtml(toIsoDateTime(meta.generatedAt))}</td><td><code>[VERIFICADO - AI CORE]</code></td></tr>
        <tr><td>Receptor de seguridad</td><td>${escapeHtml(meta.clientName)}</td><td></td><td></td></tr>
      </tbody>
    </table>
  </section>

  <footer>
    Documento generado por ${escapeHtml(meta.engine ?? "argos-security-operations")}${meta.engineVersion ? ` v${escapeHtml(meta.engineVersion)}` : ""}.
    Hash del contenido: <code>${escapeHtml(contentHash)}</code> · Clasificación: ${escapeHtml(meta.classification)}.
  </footer>
</div>
<script>${SCRIPT}</script>
</body>
</html>`
}

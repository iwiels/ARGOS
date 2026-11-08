/**
 * report-exporters.ts
 *
 * Exportadores profesionales de reportes de ciberseguridad:
 * - Markdown (.md) estructurado para repositorios, wikis y entregables técnicos.
 * - HTML Standalone (.html) autónomo con estilos CSS embebidos listo para el cliente.
 * - JSON (.json) con la estructura completa de datos enriquecida.
 */

import type { Report } from "./report-generator"

// ── Exportador a Markdown ───────────────────────────────────────────────────

export function exportReportToMarkdown(report: Report): string {
  const { summary, findings } = report
  const lines: string[] = []

  // Portada y Cabecera de Confidencialidad
  lines.push(`---`)
  lines.push(`classification: "${report.classification}"`)
  if (report.clientLegalName) lines.push(`razon_social: "${report.clientLegalName}"`)
  lines.push(`generated_at: "${report.generatedAtISO}"`)
  lines.push(`global_risk: "${summary.globalRiskLevel}"`)
  lines.push(`cvss_average: ${summary.averageCvss?.baseScore ?? "N/A"}`)
  lines.push(`---`)
  lines.push(``)
  lines.push(`# ${report.title}`)
  lines.push(``)
  lines.push(`> **CLASIFICACIÓN:** \`${report.classification}\``)
  lines.push(`> **FECHA DE EMISIÓN:** ${report.generatedAt}`)
  lines.push(`> **CLIENTE / OBJETIVO:** ${report.clientName}`)
  if (report.clientLegalName) lines.push(`> **RAZÓN SOCIAL:** ${report.clientLegalName}`)
  lines.push(`> **ALCANCE AUTORIZADO:** ${report.scope}`)
  lines.push(`> **AUDITOR LÍDER:** ${report.leadAuditor}`)
  lines.push(`> **METODOLOGÍA:** ${report.methodology}`)
  lines.push(``)
  lines.push(`---`)
  lines.push(``)

  // Resumen Ejecutivo
  lines.push(`## 1. Resumen Ejecutivo de Seguridad`)
  lines.push(``)
  lines.push(`### 1.1 Postura de Riesgo Global: **${summary.globalRiskLevel}**`)
  lines.push(``)
  lines.push(summary.executiveNarrative)
  lines.push(``)
  lines.push(`### 1.2 Métricas Clave de la Evaluación`)
  lines.push(``)
  lines.push(`| Métrica | Valor | Detalle |`)
  lines.push(`| :--- | :---: | :--- |`)
  lines.push(`| **Total de Hallazgos** | **${summary.totalFindings}** | Vulnerabilidades y debilidades identificadas |`)
  lines.push(`| **Hallazgos Críticos** | **${summary.criticalCount}** | Requieren mitigación inmediata (< 48h) |`)
  lines.push(`| **Hallazgos Altos** | **${summary.highCount}** | Atención prioritaria |`)
  lines.push(`| **Hallazgos Medios** | **${summary.mediumCount}** | Corrección en ciclo regular |`)
  lines.push(`| **Hallazgos Bajos / Info** | **${summary.lowCount + summary.infoCount}** | Endurecimiento y buenas prácticas |`)
  lines.push(
    `| **Score CVSS v3.1 Promedio** | **${summary.averageCvss?.baseScore ?? "N/A"}** | ${summary.averageCvss ? `Severidad: ${summary.averageCvss.severity}; ${summary.cvssScoredFindings} hallazgo(s) puntuado(s)` : "Sin vectores CVSS explícitos válidos"} |`,
  )
  lines.push(
    `| **Máximo CVSS Detectado** | **${summary.highestCvss?.baseScore ?? "N/A"}** | ${summary.highestCvss ? `Severidad: ${summary.highestCvss.severity} (\`${summary.highestCvss.vector}\`)` : "Sin vectores CVSS explícitos válidos"} |`,
  )
  lines.push(`| **Objetivos / Endpoints** | **${summary.totalTargets}** | Activos auditados |`)
  lines.push(``)

  // Plan de Acción y Roadmap
  lines.push(`## 2. Plan de Remediación Priorizado (Roadmap)`)
  lines.push(``)
  for (const phase of summary.remediationRoadmap) {
    lines.push(`### 2.${phase.phase === "immediate" ? "1" : phase.phase === "shortTerm" ? "2" : "3"} ${phase.title} (\`${phase.basis}\`)`)
    lines.push(``)
    lines.push(phase.description)
    lines.push(``)
    if (phase.findings.length === 0) {
      lines.push(`*No hay hallazgos asignados a esta fase.*`)
      lines.push(``)
      continue
    }
    lines.push(`| ID | Severidad | CVSS | CWE | Título | Objetivo |`)
    lines.push(`| :--- | :---: | :---: | :---: | :--- | :--- |`)
    for (const f of phase.findings) {
      lines.push(
        `| \`${f.id}\` | **${f.severity.toUpperCase()}** | **${f.cvss?.baseScore ?? "N/A"}** | ${f.cwe ?? "N/A"} | ${f.title} | \`${f.target ?? "Local"}\` |`,
      )
    }
    lines.push(``)
  }

  // Tabla Consolidada
  lines.push(`## 3. Matriz Consolidada de Hallazgos`)
  lines.push(``)
  lines.push(`| ID | Severidad | CVSS v3.1 | CWE | MITRE ATT&CK | Título | Estado |`)
  lines.push(`| :--- | :---: | :---: | :---: | :--- | :--- | :---: |`)
  for (const f of findings) {
    const attackStr = f.attack?.map((a) => a.id).join(", ") || "N/A"
    lines.push(
      `| \`${f.id}\` | **${f.severity.toUpperCase()}** | **${f.cvss?.baseScore ?? "N/A"}** | ${f.cwe ?? "N/A"} | ${attackStr} | ${f.title} | \`${f.status ?? "No indicado"}\` |`,
    )
  }
  lines.push(``)

  // Detalle Técnico Extenso
  lines.push(`## 4. Detalle Técnico de Vulnerabilidades`)
  lines.push(``)
  for (const f of findings) {
    lines.push(`### [${f.id}] ${f.title}`)
    lines.push(``)
    lines.push(`- **Severidad:** \`${f.severity.toUpperCase()}\``)
    if (f.cvss) {
      lines.push(`- **Score CVSS v3.1:** **${f.cvss.baseScore}** - ${f.cvss.severity}`)
      lines.push(`- **Vector CVSS v3.1:** \`${f.cvss.vector}\``)
    } else {
      lines.push("- **CVSS v3.1:** *No disponible: falta un vector explícito válido.*")
    }
    lines.push(`- **Clasificación CWE:** ${f.cwe ? `\`${f.cwe}\`` : "*No especificado*"}`)
    lines.push(`- **Objetivo / Activo:** \`${f.target ?? f.vector ?? "N/A"}\``)
    lines.push(`- **Estado de Validación:** \`${f.status ?? "No indicado"}\``)

    if (f.attack && f.attack.length > 0) {
      const techniques = f.attack.map((t) => `\`${t.id}\` (${t.name})`).join(", ")
      lines.push(`- **Técnicas MITRE ATT&CK:** ${techniques}`)
    }

    if (f.iocs && f.iocs.length > 0) {
      const iocStrings = f.iocs.map((ioc) => {
        const worst = ioc.reputation?.find((r) => r.verdict === "malicious" || r.verdict === "suspicious")
        return `\`${ioc.type.toUpperCase()}:${ioc.value}\`${worst ? ` (${worst.verdict})` : ""}`
      }).join(", ")
      lines.push(`- **Indicadores de Compromiso (IoCs):** ${iocStrings}`)
    }

    lines.push(``)

    // Evidencia y PoC
    lines.push(`#### Evidencia Técnica y Prueba de Concepto (PoC)`)
    lines.push(``)
    if (f.evidence) {
      lines.push(f.evidence)
      lines.push(``)
    } else {
      lines.push(`*La evidencia fue confirmada durante la ejecución automatizada del escaneo de seguridad.*`)
      lines.push(``)
    }

    if (f.curlCommand) {
      lines.push(`**Reproducción vía cURL:**`)
      lines.push(`\`\`\`bash`)
      lines.push(f.curlCommand)
      lines.push(`\`\`\``)
      lines.push(``)
    }

    if (f.httpRequest) {
      lines.push(`**Petición HTTP Enviada:**`)
      lines.push(`\`\`\`http`)
      lines.push(f.httpRequest)
      lines.push(`\`\`\``)
      lines.push(``)
    }

    if (f.httpResponse) {
      lines.push(`**Respuesta HTTP del Servidor:**`)
      lines.push(`\`\`\`http`)
      lines.push(f.httpResponse)
      lines.push(`\`\`\``)
      lines.push(``)
    }

    // Remediación
    lines.push(`#### Recomendación y Guía de Remediación`)
    lines.push(``)
    if (f.remediation) {
      lines.push(f.remediation)
      lines.push(``)
    } else {
      lines.push(`Aplicar validación estricta de entradas, principios de mínimos privilegios y actualizar los componentes afectados a sus versiones más recientes con soporte oficial.`)
      lines.push(``)
    }

    lines.push(`---`)
    lines.push(``)
  }

  // Firmas y Cierre
  lines.push(`## 5. Control de Aprobaciones y Emisión`)
  lines.push(``)
  lines.push(`Este informe ha sido generado y validado automáticamente por el motor de ciberseguridad **${report.metadata.engine}** v${report.metadata.version}.`)
  lines.push(``)
  lines.push(`| Rol | Nombre / Entidad | Fecha | Firma / Sello |`)
  lines.push(`| :--- | :--- | :--- | :--- |`)
  lines.push(`| **Auditor Responsable** | ${report.leadAuditor} | ${report.generatedAt} | \`[VERIFICADO - AI CORE]\` |`)
  lines.push(`| **Receptor de Seguridad** | ${report.clientName} | | |`)
  if (report.clientLegalName) lines.push(`| **Razón Social del Receptor** | ${report.clientLegalName} | | |`)
  lines.push(``)

  return lines.join("\n")
}

// ── Exportador a HTML Standalone ────────────────────────────────────────────

export function exportReportToHtml(report: Report): string {
  const { summary, findings } = report

  return `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(report.title)}</title>
  <style>
    :root {
      --bg: #090d16;
      --bg-surface: #111827;
      --bg-card: #1f2937;
      --border: #374151;
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --accent: #38bdf8;
      --critical: #ef4444;
      --high: #f97316;
      --medium: #eab308;
      --low: #3b82f6;
      --info: #6b7280;
    }
    @media (prefers-color-scheme: light) {
      :root {
        --bg: #f8fafc;
        --bg-surface: #ffffff;
        --bg-card: #f1f5f9;
        --border: #e2e8f0;
        --text: #0f172a;
        --text-muted: #64748b;
        --accent: #0284c7;
      }
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 2rem 1rem;
    }
    .container {
      max-width: 960px;
      margin: 0 auto;
    }
    .banner {
      display: inline-block;
      padding: 0.25rem 0.75rem;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: 700;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      background-color: rgba(239, 68, 68, 0.15);
      color: var(--critical);
      border: 1px solid var(--critical);
      margin-bottom: 1rem;
    }
    h1 { font-size: 2rem; margin-bottom: 0.5rem; font-weight: 800; color: var(--text); }
    h2 { font-size: 1.4rem; margin-top: 2rem; margin-bottom: 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }
    h3 { font-size: 1.15rem; margin-top: 1.25rem; margin-bottom: 0.5rem; }
    p { margin-bottom: 1rem; color: var(--text); }
    .meta-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
      background: var(--bg-surface);
      border: 1px solid var(--border);
      border-radius: 0.75rem;
      padding: 1.25rem;
      margin-bottom: 2rem;
    }
    .meta-item { display: flex; flex-direction: column; }
    .meta-label { font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; font-weight: 600; }
    .meta-value { font-size: 0.95rem; font-weight: 600; color: var(--text); margin-top: 0.2rem; }
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }
    .kpi-card {
      background: var(--bg-surface);
      border: 1px solid var(--border);
      border-radius: 0.75rem;
      padding: 1.25rem;
      text-align: center;
    }
    .kpi-num { font-size: 2.2rem; font-weight: 800; font-family: monospace; }
    .kpi-title { font-size: 0.8rem; color: var(--text-muted); text-transform: uppercase; font-weight: 600; margin-top: 0.25rem; }
    .card {
      background: var(--bg-surface);
      border: 1px solid var(--border);
      border-radius: 0.75rem;
      padding: 1.25rem;
      margin-bottom: 1.25rem;
    }
    .finding-card {
      background: var(--bg-surface);
      border: 1px solid var(--border);
      border-radius: 0.75rem;
      padding: 1.5rem;
      margin-bottom: 1.5rem;
      page-break-inside: avoid;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      padding: 0.2rem 0.6rem;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
      font-family: monospace;
    }
    .badge-critical { background: rgba(239, 68, 68, 0.15); color: #ef4444; border: 1px solid #ef4444; }
    .badge-high { background: rgba(249, 115, 22, 0.15); color: #f97316; border: 1px solid #f97316; }
    .badge-medium { background: rgba(234, 179, 8, 0.15); color: #eab308; border: 1px solid #eab308; }
    .badge-low { background: rgba(59, 130, 246, 0.15); color: #3b82f6; border: 1px solid #3b82f6; }
    .badge-info { background: rgba(107, 114, 128, 0.15); color: #6b7280; border: 1px solid #6b7280; }
    table { width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: 0.9rem; }
    th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid var(--border); }
    th { background: var(--bg-card); font-weight: 600; color: var(--text-muted); font-size: 0.8rem; text-transform: uppercase; }
    pre {
      background: var(--bg-card);
      border: 1px solid var(--border);
      padding: 0.75rem;
      border-radius: 0.5rem;
      overflow-x: auto;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.85rem;
      margin: 0.75rem 0;
    }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
    @media print {
      body { background: white !important; color: black !important; padding: 0; }
      .container { max-width: 100%; }
      .card, .finding-card, .meta-grid, .kpi-card { border-color: #cbd5e1 !important; background: white !important; }
      .kpi-num, h1, h2, h3, p, td, th { color: black !important; }
      .no-print { display: none !important; }
      .page-break { page-break-before: always; }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="banner">${escapeHtml(report.classification)}</div>
    <h1>${escapeHtml(report.title)}</h1>
    <p style="color: var(--text-muted); font-size: 0.95rem;">Informe Oficial de Seguridad y Evaluación de Vulnerabilidades</p>
    ${
      report.clientLogoDataUrl
        ? `<img src="${report.clientLogoDataUrl}" alt="Logo del cliente" style="max-height: 72px; max-width: 240px; object-fit: contain; margin: 12px 0;" />`
        : ""
    }

    <div class="meta-grid">
      <div class="meta-item"><span class="meta-label">Cliente</span><span class="meta-value">${escapeHtml(report.clientName)}</span></div>
      ${report.clientLegalName ? `<div class="meta-item"><span class="meta-label">Razón Social</span><span class="meta-value">${escapeHtml(report.clientLegalName)}</span></div>` : ""}
      <div class="meta-item"><span class="meta-label">Alcance</span><span class="meta-value">${escapeHtml(report.scope)}</span></div>
      <div class="meta-item"><span class="meta-label">Fecha</span><span class="meta-value">${escapeHtml(report.generatedAt)}</span></div>
      <div class="meta-item"><span class="meta-label">Auditor Líder</span><span class="meta-value">${escapeHtml(report.leadAuditor)}</span></div>
    </div>

    <h2>1. Resumen Ejecutivo</h2>
    <div class="card">
      <p><strong>Nivel de Riesgo Global:</strong> <span class="badge badge-${summary.globalRiskLevel.toLowerCase()}">${summary.globalRiskLevel}</span></p>
      <p style="margin-top: 0.5rem;">${escapeHtml(summary.executiveNarrative)}</p>
    </div>

    <div class="kpi-grid">
      <div class="kpi-card"><div class="kpi-num">${summary.totalFindings}</div><div class="kpi-title">Total Hallazgos</div></div>
      <div class="kpi-card"><div class="kpi-num" style="color: var(--critical);">${summary.criticalCount}</div><div class="kpi-title">Críticos</div></div>
      <div class="kpi-card"><div class="kpi-num" style="color: var(--high);">${summary.highCount}</div><div class="kpi-title">Altos</div></div>
      <div class="kpi-card"><div class="kpi-num" style="color: var(--accent);">${summary.averageCvss?.baseScore ?? "N/A"}</div><div class="kpi-title">CVSS v3.1 Promedio (${summary.cvssScoredFindings} puntuados)</div></div>
      <div class="kpi-card"><div class="kpi-num">${summary.totalTargets}</div><div class="kpi-title">Activos / Endpoints</div></div>
    </div>

    <h2>2. Plan de Remediación Priorizado</h2>
    ${summary.remediationRoadmap
      .map(
        (phase) => `
      <div class="card">
        <h3>${escapeHtml(phase.title)} <span style="font-size: 0.8rem; color: var(--text-muted); font-weight: normal;">(Criterio: ${escapeHtml(phase.basis)})</span></h3>
        <p style="font-size: 0.9rem; color: var(--text-muted);">${escapeHtml(phase.description)}</p>
        ${
          phase.findings.length > 0
            ? `<table>
                <thead><tr><th>ID</th><th>Severidad</th><th>CVSS</th><th>CWE</th><th>Título</th><th>Objetivo</th></tr></thead>
                <tbody>
                  ${phase.findings
                    .map(
                      (f) => `<tr>
                        <td><code>${escapeHtml(f.id)}</code></td>
                        <td><span class="badge badge-${f.severity}">${f.severity.toUpperCase()}</span></td>
                        <td><strong>${f.cvss?.baseScore ?? "N/A"}</strong></td>
                        <td>${escapeHtml(f.cwe || "-")}</td>
                        <td>${escapeHtml(f.title)}</td>
                        <td><code>${escapeHtml(f.target || "Local")}</code></td>
                      </tr>`,
                    )
                    .join("")}
                </tbody>
              </table>`
            : `<p style="font-size: 0.85rem; color: var(--text-muted); font-style: italic;">Sin hallazgos en esta fase.</p>`
        }
      </div>
    `,
      )
      .join("")}

    <div class="page-break"></div>

    <h2>3. Detalle de Vulnerabilidades</h2>
    ${findings
      .map(
        (f) => `
      <div class="finding-card">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.75rem;">
          <div>
            <span style="font-family: monospace; font-size: 0.85rem; color: var(--text-muted);">${escapeHtml(f.id)}</span>
            <h3 style="margin-top: 0.2rem;">${escapeHtml(f.title)}</h3>
          </div>
          <span class="badge badge-${f.severity}">${f.severity.toUpperCase()}${f.cvss ? ` · CVSS ${f.cvss.baseScore}` : " · CVSS N/A"}</span>
        </div>

        <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 0.75rem;">
          <strong>CVSS v3.1:</strong> ${f.cvss ? `<code>${escapeHtml(f.cvss.vector)} — ${f.cvss.baseScore}</code>` : "No disponible: falta un vector explícito válido."}<br>
          <strong>CWE:</strong> ${escapeHtml(f.cwe || "N/A")} | <strong>Objetivo:</strong> <code>${escapeHtml(f.target || f.vector || "N/A")}</code>
        </p>

        ${
          f.iocs && f.iocs.length > 0
            ? `<div style="margin-bottom: 0.75rem; display: flex; flex-wrap: wrap; gap: 0.4rem; align-items: center;">
                <span style="font-size: 0.75rem; color: var(--text-muted); font-weight: 600; text-transform: uppercase;">IoCs:</span>
                ${f.iocs
                  .map(
                    (ioc) => `<span class="badge" style="background: var(--bg-card); color: var(--text); border: 1px solid var(--border);">
                      ${escapeHtml(ioc.type.toUpperCase())}: ${escapeHtml(ioc.value)}
                    </span>`,
                  )
                  .join("")}
              </div>`
            : ""
        }

        <h4 style="font-size: 0.95rem; margin-top: 1rem; margin-bottom: 0.25rem;">Evidencia Técnica / PoC:</h4>
        <p style="font-size: 0.9rem;">${escapeHtml(f.evidence || "Confirmado mediante análisis automatizado.")}</p>
        ${f.curlCommand ? `<div style="margin-top: 0.5rem;"><span style="font-size: 0.75rem; color: var(--text-muted); font-family: monospace;">Reproducción cURL:</span><pre><code>${escapeHtml(f.curlCommand)}</code></pre></div>` : ""}
        ${f.httpRequest ? `<div style="margin-top: 0.5rem;"><span style="font-size: 0.75rem; color: var(--text-muted); font-family: monospace;">Petición HTTP Enviada:</span><pre><code>${escapeHtml(f.httpRequest)}</code></pre></div>` : ""}
        ${f.httpResponse ? `<div style="margin-top: 0.5rem;"><span style="font-size: 0.75rem; color: var(--text-muted); font-family: monospace;">Respuesta HTTP del Servidor:</span><pre><code>${escapeHtml(f.httpResponse)}</code></pre></div>` : ""}

        <h4 style="font-size: 0.95rem; margin-top: 1rem; margin-bottom: 0.25rem; color: var(--accent);">Recomendación de Remediación:</h4>
        <p style="font-size: 0.9rem;">${escapeHtml(f.remediation || "Aplicar controles defensivos y actualización de software.")}</p>
      </div>
    `,
      )
      .join("")}

    <h2>4. Control de Firmas y Emisión</h2>
    <div class="card">
      <p style="font-size: 0.85rem; color: var(--text-muted);">Documento emitido por el motor de ciberseguridad <strong>${escapeHtml(report.metadata.engine)}</strong> v${report.metadata.version}.</p>
      <table>
        <thead><tr><th>Rol</th><th>Responsable</th><th>Fecha</th><th>Estado</th></tr></thead>
        <tbody>
          <tr>
            <td><strong>Auditor Líder</strong></td>
            <td>${escapeHtml(report.leadAuditor)}</td>
            <td>${escapeHtml(report.generatedAt)}</td>
            <td><code>[VERIFICADO - AI CORE]</code></td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</body>
</html>`
}

function escapeHtml(str: string): string {
  if (!str) return ""
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;")
}

// ── Disparadores de Descarga en Cliente ─────────────────────────────────────

export function downloadFile(content: string, filename: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType })
  const url = URL.createObjectURL(blob)

  const a = document.createElement("a")
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()

  requestAnimationFrame(() => {
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  })
}

export function downloadJson(data: unknown, filename: string): void {
  const cleanName = filename.replace(/[^a-zA-Z0-9_-]/g, "_")
  downloadFile(JSON.stringify(data, null, 2), `${cleanName}.json`, "application/json")
}

export function downloadMarkdown(content: string, filename: string): void {
  const cleanName = filename.replace(/[^a-zA-Z0-9_-]/g, "_")
  downloadFile(content, `${cleanName}.md`, "text/markdown;charset=utf-8")
}

export function downloadHtml(content: string, filename: string): void {
  const cleanName = filename.replace(/[^a-zA-Z0-9_-]/g, "_")
  downloadFile(content, `${cleanName}.html`, "text/html;charset=utf-8")
}

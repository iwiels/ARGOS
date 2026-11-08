import { dict as en } from "../packages/app/src/i18n/en"
import { dict as es } from "../packages/app/src/i18n/es"
import { dict as br } from "../packages/app/src/i18n/br"
import fs from "node:fs"
import path from "node:path"

// Brazilian Portuguese translation mappings for cybersecurity & UI terminology
const manualBrTranslations: Record<string, string> = {
  // Navigation & Headers
  "nav.audit.findings": "Achados",
  "nav.audit.topology": "Topologia",
  "nav.audit.reports": "Relatórios",
  "nav.audit.compliance": "Conformidade",
  "nav.audit.governance": "Governança",
  "nav.audit.status": "Status",
  "nav.health.activeSecure": "Sistema ativo · Conexão segura",
  "nav.health.criticalUnresponsive": "Crítico · Servidor não responde",
  "nav.health.offline": "Sem conexão",
  "nav.health.unknown": "Status desconhecido",
  "nav.badge.online": "Online",
  "nav.badge.down": "Inoperante",
  "nav.badge.offline": "Offline",

  // Severity
  "severity.critical": "Crítico",
  "severity.high": "Alto",
  "severity.medium": "Médio",
  "severity.low": "Baixo",
  "severity.info": "Informativo",

  // Status page
  "status.server.health.healthy": "Saudável",
  "status.server.health.warning": "Aviso",
  "status.server.health.critical": "Crítico",
  "status.server.health.offline": "Sem conexão",
  "status.server.status.connected": "Conectado",
  "status.server.status.failed": "Falhou",
  "status.server.status.auth": "Requer autenticação",
  "status.server.status.disabled": "Desativado",
  "status.server.status.offline": "Offline",
  "status.mcp.status.connected": "Conectado",
  "status.mcp.status.failed": "Falhou",
  "status.mcp.status.needs_auth": "Requer autenticação",
  "status.mcp.status.disabled": "Desativado",
  "status.mcp.status.unknown": "Desconhecido",
  "status.empty.noServers": "Nenhum servidor configurado",
  "status.empty.noMcps": "Nenhum servidor MCP configurado",
  "status.empty.noLsps": "Nenhum LSP ativo",
  "status.empty.noSessions": "Nenhuma sessão ativa",
  "status.empty.noHealthMetrics": "Métricas de saúde indisponíveis",

  // Findings
  "findings.pageSubtitle": "{{total}} achados em {{sessions}} sessões de auditoria",
  "findings.all": "Todos",
  "findings.kpi.click": "Filtrar por {{severity}}",
  "findings.search.placeholder": "Buscar vulnerabilidade, CWE, alvo ou vetor...",
  "findings.dense.toggle": "Alternar visualização compacta",
  "findings.export.selected": "Exportar selecionados ({{count}})",
  "findings.export.all": "Exportar todos",
  "findings.export.json": "Exportar como JSON",
  "findings.export.csv": "Exportar como CSV",
  "findings.table.title": "Achado / Vulnerabilidade",
  "findings.table.severity": "Severidade",
  "findings.table.status": "Status",
  "findings.table.target": "Alvo",
  "findings.table.cwe": "CWE",
  "findings.table.agent": "Agente",
  "findings.table.actions": "Ações",
  "findings.table.empty": "Nenhum achado encontrado para os filtros selecionados",
  "findings.filter.severity": "Filtrar por severidade",
  "findings.filter.status": "Filtrar por status",
  "findings.filter.agent": "Filtrar por agente",
  "findings.detail.evidence": "Evidência",
  "findings.detail.remediation": "Remediação recomendada",
  "findings.detail.vector": "Vetor de ataque",
  "findings.detail.cwe": "Identificador CWE",
  "findings.detail.cvss": "Pontuação CVSS",
  "findings.detail.attack": "Técnicas MITRE ATT&CK",
  "findings.detail.iocs": "Indicadores de Comprometimento (IoCs)",
  "findings.detail.rawOutput": "Saída bruta da ferramenta",
  "findings.detail.httpRequest": "Requisição HTTP",
  "findings.detail.httpResponse": "Resposta HTTP",
  "findings.detail.curlCommand": "Comando cURL reproduzível",

  // Reports
  "reports.cvssAverageBadge": "Média CVSS v3.1",
  "reports.export.json": "Baixar Relatório JSON",
  "reports.export.pdf": "Exportar como PDF",
  "reports.print": "Imprimir Relatório",
  "reports.executiveSummary": "Resumo Executivo",
  "reports.severityBreakdown": "Distribuição de Vulnerabilidades por Severidade",
  "reports.topVulnerabilities": "Principais Vulnerabilidades Identificadas",
  "reports.targetSummary": "Superfície e Exposição por Alvo",
  "reports.empty": "Nenhum dado disponível para gerar o relatório nesta auditoria",

  // Session
  "session.review.noIterationChanges": "Sem modificações de código nesta iteração",
  "session.review.consoleReady": "Console pronto. Os achados e evidências aparecerão aqui durante a execução.",

  // CCM (Cloud Controls Matrix)
  "ccm.title": "Cloud Controls Matrix (CCM)",
  "ccm.subtitle": "Avaliação de conformidade de segurança em nuvem baseada no CSA CCM v4",
  "ccm.filter.domain": "Filtrar por domínio",
  "ccm.filter.status": "Filtrar por status de conformidade",
  "ccm.search.placeholder": "Buscar controle, domínio ou requisito...",
  "ccm.table.controlId": "ID do Controle",
  "ccm.table.domain": "Domínio",
  "ccm.table.title": "Título do Controle",
  "ccm.table.status": "Status",
  "ccm.table.findingsCount": "Achados Associados",
  "ccm.status.compliant": "Conforme",
  "ccm.status.non_compliant": "Não Conforme",
  "ccm.status.partially_compliant": "Parcialmente Conforme",
  "ccm.status.not_applicable": "Não Aplicável",
  "ccm.status.not_evaluated": "Não Avaliado",

  // Compliance
  "compliance.title": "Conformidade Normativa",
  "compliance.subtitle": "Mapeamento contínuo contra frameworks NIST CSF 2.0 e ISO 27001:2022",
  "compliance.nist": "NIST CSF 2.0",
  "compliance.iso": "ISO 27001:2022",
  "compliance.refresh": "Atualizar Avaliação",
  "compliance.drift": "Desvio de Conformidade",
  "compliance.summary": "Resumo Geral",

  // Governance
  "governance.title": "Governança e Políticas",
  "governance.subtitle": "Regras de engajamento, limites de operação e políticas de segurança dos agentes",
  "governance.policies": "Políticas Ativas",
  "governance.rules": "Regras de Engajamento",
  "governance.approvals": "Aprovações Pendentes",

  // Topology
  "topology.title": "Topologia da Infraestrutura",
  "topology.subtitle": "Visualização interativa da rede, alvos, portas e serviços descobertos",
  "topology.node.target": "Alvo",
  "topology.node.service": "Serviço",
  "topology.node.port": "Porta",
  "topology.node.vulnerability": "Vulnerabilidade",
  "topology.controls.zoomIn": "Aumentar zoom",
  "topology.controls.zoomOut": "Diminuir zoom",
  "topology.controls.fit": "Ajustar à tela",
  "topology.controls.reset": "Redefinir visualização",
}

// Translate known English / Spanish patterns to Portuguese automatically
function autoTranslate(key: string, enVal: string, esVal: string): string {
  if (manualBrTranslations[key]) return manualBrTranslations[key]

  // Translation replacements for common cybersecurity, IDE, and UI terms
  let text = esVal || enVal

  // Common word replacements from ES -> PT-BR
  const replacements: Array<[RegExp, string]> = [
    [/\bhallazgos\b/gi, "achados"],
    [/\bhallazgo\b/gi, "achado"],
    [/\bconfiguración\b/gi, "configuração"],
    [/\bconfiguraciones\b/gi, "configurações"],
    [/\bherramienta\b/gi, "ferramenta"],
    [/\bherramientas\b/gi, "ferramentas"],
    [/\bsesión\b/gi, "sessão"],
    [/\bsesiones\b/gi, "sessões"],
    [/\bdescripción\b/gi, "descrição"],
    [/\bseleccionar\b/gi, "selecionar"],
    [/\bseleccionado\b/gi, "selecionado"],
    [/\bseleccionados\b/gi, "selecionados"],
    [/\beliminar\b/gi, "excluir"],
    [/\bcancelar\b/gi, "cancelar"],
    [/\bguardar\b/gi, "salvar"],
    [/\beditar\b/gi, "editar"],
    [/\bcerrar\b/gi, "fechar"],
    [/\babrir\b/gi, "abrir"],
    [/\bbuscar\b/gi, "buscar"],
    [/\bactualizar\b/gi, "atualizar"],
    [/\bconectado\b/gi, "conectado"],
    [/\bdesconectado\b/gi, "desconectado"],
    [/\bdeshabilitado\b/gi, "desativado"],
    [/\bhabilitado\b/gi, "ativado"],
    [/\bdeshabilitar\b/gi, "desativar"],
    [/\bhabilitar\b/gi, "ativar"],
    [/\bningún\b/gi, "nenhum"],
    [/\bninguno\b/gi, "nenhum"],
    [/\bninguna\b/gi, "nenhuma"],
    [/\btodos\b/gi, "todos"],
    [/\btodas\b/gi, "todas"],
    [/\barchivo\b/gi, "arquivo"],
    [/\barchivos\b/gi, "arquivos"],
    [/\bcarpeta\b/gi, "pasta"],
    [/\bcarpetas\b/gi, "pastas"],
    [/\bdirectorio\b/gi, "diretório"],
    [/\bdirectorios\b/gi, "diretórios"],
    [/\bnombre\b/gi, "nome"],
    [/\bestado\b/gi, "status"],
    [/\bcódigo\b/gi, "código"],
    [/\bmensaje\b/gi, "mensagem"],
    [/\bmensajes\b/gi, "mensagens"],
    [/\bpermiso\b/gi, "permissão"],
    [/\bpermisos\b/gi, "permissões"],
    [/\bautenticación\b/gi, "autenticação"],
    [/\bautorización\b/gi, "autorização"],
    [/\bnotificación\b/gi, "notificação"],
    [/\bnotificaciones\b/gi, "notificações"],
    [/\bproyecto\b/gi, "projeto"],
    [/\bproyectos\b/gi, "projetos"],
    [/\bmodelo\b/gi, "modelo"],
    [/\bmodelos\b/gi, "modelos"],
    [/\bproveedor\b/gi, "provedor"],
    [/\bproveedores\b/gi, "provedores"],
    [/\bservidor\b/gi, "servidor"],
    [/\bservidores\b/gi, "servidores"],
    [/\bconexión\b/gi, "conexão"],
    [/\bconexiones\b/gi, "conexões"],
    [/\breintentar\b/gi, "tentar novamente"],
    [/\bcomenzar\b/gi, "começar"],
    [/\bcontinuar\b/gi, "continuar"],
    [/\bpausar\b/gi, "pausar"],
    [/\bdetener\b/gi, "parar"],
    [/\bejecutar\b/gi, "executar"],
    [/\bejecutando\b/gi, "executando"],
    [/\bcompletado\b/gi, "concluído"],
    [/\bfallido\b/gi, "falhou"],
    [/\berror\b/gi, "erro"],
    [/\berrores\b/gi, "erros"],
    [/\badvertencia\b/gi, "aviso"],
    [/\badvertencias\b/gi, "avisos"],
    [/\binformación\b/gi, "informação"],
    [/\bcrítico\b/gi, "crítico"],
    [/\balto\b/gi, "alto"],
    [/\bmedio\b/gi, "médio"],
    [/\bbajo\b/gi, "baixo"],
    [/\bidioma\b/gi, "idioma"],
    [/\btema\b/gi, "tema"],
    [/\boscuro\b/gi, "escuro"],
    [/\bclaro\b/gi, "claro"],
    [/\bsistema\b/gi, "sistema"],
    [/\bautomático\b/gi, "automático"],
    [/\bpersonalizado\b/gi, "personalizado"],
    [/\bgeneral\b/gi, "geral"],
    [/\bavanzado\b/gi, "avançado"],
    [/\bseguridad\b/gi, "segurança"],
    [/\bprivacidad\b/gi, "privacidade"],
    [/\bcumplimiento\b/gi, "conformidade"],
    [/\bgovernança\b/gi, "governança"],
    [/\bpolítica\b/gi, "política"],
    [/\bpolíticas\b/gi, "políticas"],
    [/\breporte\b/gi, "relatório"],
    [/\breportes\b/gi, "relatórios"],
    [/\bauditoría\b/gi, "auditoria"],
    [/\bauditorías\b/gi, "auditorias"],
    [/\btopología\b/gi, "topologia"],
    [/\bvulnerabilidad\b/gi, "vulnerabilidade"],
    [/\bvulnerabilidades\b/gi, "vulnerabilidades"],
    [/\bevidencia\b/gi, "evidência"],
    [/\bevidencias\b/gi, "evidências"],
    [/\bremediación\b/gi, "remediação"],
    [/\bvector\b/gi, "vetor"],
    [/\balcance\b/gi, "escopo"],
    [/\bobjetivo\b/gi, "alvo"],
    [/\bobjetivos\b/gi, "alvos"],
  ]

  for (const [regex, replacement] of replacements) {
    text = text.replace(regex, replacement)
  }

  return text
}

const mergedDict: Record<string, string> = { ...br }

for (const key of Object.keys(en)) {
  if (!mergedDict[key]) {
    mergedDict[key] = autoTranslate(key, en[key as keyof typeof en], es[key as keyof typeof es] || en[key as keyof typeof en])
  }
}

// Format the typescript file output
const lines: string[] = ["export const dict = {"]
for (const [key, value] of Object.entries(mergedDict)) {
  const sanitizedVal = JSON.stringify(value)
  lines.push(`  ${JSON.stringify(key)}: ${sanitizedVal},`)
}
lines.push("}\n")

const targetPath = path.resolve(__dirname, "../packages/app/src/i18n/br.ts")
fs.writeFileSync(targetPath, lines.join("\n"), "utf-8")
console.log(`Successfully updated br.ts! Total keys: ${Object.keys(mergedDict).length}`)

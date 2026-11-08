/**
 * compliance-i18n.ts
 *
 * Mapeos de localización multilenguaje para títulos de funciones, categorías
 * y controles de NIST CSF 2.0 e ISO 27001:2022, así como estados de hallazgos.
 */

const NIST_CSF_TITLES: Record<string, Record<string, string>> = {
  // Functions
  GV: {
    es: "GOBERNANZA",
    en: "GOVERN",
    br: "GOVERNANÇA",
  },
  ID: {
    es: "IDENTIFICACIÓN",
    en: "IDENTIFY",
    br: "IDENTIFICAÇÃO",
  },
  PR: {
    es: "PROTECCIÓN",
    en: "PROTECT",
    br: "PROTEÇÃO",
  },
  DE: {
    es: "DETECCIÓN",
    en: "DETECT",
    br: "DETECÇÃO",
  },
  RS: {
    es: "RESPUESTA",
    en: "RESPOND",
    br: "RESPOSTA",
  },
  RC: {
    es: "RECUPERACIÓN",
    en: "RECOVER",
    br: "RECUPERAÇÃO",
  },

  // Categories
  "GV.OC": {
    es: "Contexto Organizacional",
    en: "Organizational Context",
    br: "Contexto Organizacional",
  },
  "GV.RM": {
    es: "Estrategia de Gestión de Riesgos",
    en: "Risk Management Strategy",
    br: "Estratégia de Gestão de Riscos",
  },
  "GV.RR": {
    es: "Roles, Responsabilidades y Autoridades",
    en: "Roles, Responsibilities, and Authorities",
    br: "Papéis, Responsabilidades e Autoridades",
  },
  "GV.PO": {
    es: "Políticas",
    en: "Policy",
    br: "Políticas",
  },
  "GV.OV": {
    es: "Supervisión y Control",
    en: "Oversight",
    br: "Supervisão",
  },
  "GV.SC": {
    es: "Gestión de Riesgos en Cadena de Suministro",
    en: "Cybersecurity Supply Chain Risk Management",
    br: "Gestão de Riscos na Cadeia de Suprimentos",
  },
  "ID.AM": {
    es: "Gestión de Activos",
    en: "Asset Management",
    br: "Gestão de Ativos",
  },
  "ID.RA": {
    es: "Evaluación de Riesgos",
    en: "Risk Assessment",
    br: "Avaliação de Riscos",
  },
  "ID.IM": {
    es: "Mejora Continua",
    en: "Improvement",
    br: "Melhoria Contínua",
  },
  "PR.AA": {
    es: "Gestión de Identidad, Autenticación y Control de Acceso",
    en: "Identity Management, Authentication, and Access Control",
    br: "Gestão de Identidade, Autenticação e Controle de Acesso",
  },
  "PR.AT": {
    es: "Concienciación y Capacitación",
    en: "Awareness and Training",
    br: "Conscientização e Treinamento",
  },
  "PR.DS": {
    es: "Seguridad de los Datos",
    en: "Data Security",
    br: "Segurança de Dados",
  },
  "PR.PS": {
    es: "Seguridad de Plataformas y Servicios",
    en: "Platform Security",
    br: "Segurança de Plataformas",
  },
  "PR.IR": {
    es: "Resiliencia de la Infraestructura Tecnológica",
    en: "Technology Infrastructure Resilience",
    br: "Resiliência da Infraestrutura Tecnológica",
  },
  "DE.CM": {
    es: "Monitoreo Continuo de Seguridad",
    en: "Continuous Monitoring",
    br: "Monitoramento Contínuo",
  },
  "DE.AE": {
    es: "Análisis de Eventos Adversos",
    en: "Adverse Event Analysis",
    br: "Análise de Eventos Adversos",
  },
  "RS.MA": {
    es: "Gestión de Incidentes",
    en: "Incident Management",
    br: "Gestão de Incidentes",
  },
  "RS.AN": {
    es: "Análisis de Incidentes",
    en: "Incident Analysis",
    br: "Análise de Incidentes",
  },
  "RS.CO": {
    es: "Reportes y Comunicación de Incidentes",
    en: "Incident Response Reporting and Communication",
    br: "Relatórios e Comunicação de Incidentes",
  },
  "RS.MI": {
    es: "Mitigación de Incidentes",
    en: "Incident Mitigation",
    br: "Mitigação de Incidentes",
  },
  "RC.RP": {
    es: "Ejecución del Plan de Recuperación",
    en: "Incident Recovery Plan Execution",
    br: "Execução do Plano de Recuperação",
  },
  "RC.CO": {
    es: "Comunicación de Recuperación",
    en: "Incident Recovery Communication",
    br: "Comunicação de Recuperação",
  },
}

const ISO27001_TITLES: Record<string, Record<string, string>> = {
  // Main Clauses
  "A.5": {
    es: "Controles organizacionales",
    en: "Organizational controls",
    br: "Controles organizacionais",
  },
  "A.6": {
    es: "Controles de personas",
    en: "People controls",
    br: "Controles de pessoas",
  },
  "A.7": {
    es: "Controles físicos",
    en: "Physical controls",
    br: "Controles físicos",
  },
  "A.8": {
    es: "Controles tecnológicos",
    en: "Technological controls",
    br: "Controles tecnológicos",
  },

  // Key Subcontrols
  "A.5.1": { es: "Políticas para la seguridad de la información", en: "Policies for information security", br: "Políticas de segurança da informação" },
  "A.5.2": { es: "Roles y responsabilidades de seguridad", en: "Information security roles and responsibilities", br: "Papéis e responsabilidades de segurança" },
  "A.5.3": { es: "Segregación de funciones", en: "Segregation of duties", br: "Segregação de funções" },
  "A.5.4": { es: "Responsabilidades de la dirección", en: "Management responsibilities", br: "Responsabilidades da direção" },
  "A.5.7": { es: "Inteligencia de amenazas", en: "Threat intelligence", br: "Inteligência de ameaças" },
  "A.5.8": { es: "Seguridad de la información en proyectos", en: "Information security in project management", br: "Segurança da informação em projetos" },
  "A.5.9": { es: "Inventario de información y activos", en: "Inventory of information and other associated assets", br: "Inventário de informações e ativos" },
  "A.5.10": { es: "Uso aceptable de información y activos", en: "Acceptable use of information and other associated assets", br: "Uso aceitável de informações e ativos" },
  "A.5.15": { es: "Control de acceso", en: "Access control", br: "Controle de acesso" },
  "A.5.16": { es: "Gestión de identidades", en: "Identity management", br: "Gestão de identidades" },
  "A.5.17": { es: "Información de autenticación", en: "Authentication information", br: "Informações de autenticação" },
  "A.5.18": { es: "Derechos de acceso", en: "Access rights", br: "Direitos de acesso" },
  "A.5.19": { es: "Seguridad en relaciones con proveedores", en: "Information security in supplier relationships", br: "Segurança em relacionamentos com fornecedores" },
  "A.5.23": { es: "Seguridad de servicios en la nube", en: "Information security for use of cloud services", br: "Segurança de serviços em nuvem" },
  "A.5.24": { es: "Planificación de gestión de incidentes", en: "Information security incident management planning and preparation", br: "Planejamento de gestão de incidentes" },
  "A.5.25": { es: "Evaluación de eventos de seguridad", en: "Assessment and decision on information security events", br: "Avaliação de eventos de segurança" },
  "A.5.26": { es: "Respuesta a incidentes de seguridad", en: "Response to information security incidents", br: "Resposta a incidentes de segurança" },
  "A.5.28": { es: "Recopilación de evidencias", en: "Collection of evidence", br: "Coleta de evidências" },
  "A.5.29": { es: "Seguridad durante interrupciones", en: "Information security during disruption", br: "Segurança durante interrupções" },
  "A.5.30": { es: "Preparación de TIC para continuidad", en: "ICT readiness for business continuity", br: "Prontidão de TIC para continuidade" },
  "A.5.31": { es: "Requisitos legales y contractuales", en: "Legal, statutory, regulatory and contractual requirements", br: "Requisitos legais e contratuais" },
  "A.5.32": { es: "Derechos de propiedad intelectual", en: "Intellectual property rights", br: "Direitos de propriedade intelectual" },
  "A.5.33": { es: "Protección de registros", en: "Protection of records", br: "Proteção de registros" },
  "A.5.34": { es: "Privacidad y protección de datos personales", en: "Privacy and protection of PII", br: "Privacidade e proteção de dados pessoais" },
  "A.5.36": { es: "Cumplimiento con políticas de seguridad", en: "Compliance with policies and standards for information security", br: "Conformidade com políticas de segurança" },
  "A.5.37": { es: "Procedimientos operativos documentados", en: "Documented operating procedures", br: "Procedimentos operacionais documentados" },
  "A.6.1": { es: "Selección de personal", en: "Screening", br: "Seleção de pessoal" },
  "A.6.2": { es: "Términos y condiciones de empleo", en: "Terms and conditions of employment", br: "Termos e condições de contratação" },
  "A.6.3": { es: "Concienciación y capacitación en seguridad", en: "Information security awareness, education and training", br: "Conscientização e treinamento em segurança" },
  "A.6.4": { es: "Proceso disciplinario", en: "Disciplinary process", br: "Processo disciplinar" },
  "A.6.5": { es: "Responsabilidades tras cese o cambio", en: "Responsibilities after termination or change of employment", br: "Responsabilidades após rescisão ou mudança" },
  "A.6.6": { es: "Acuerdos de confidencialidad", en: "Confidentiality or non-disclosure agreements", br: "Acordos de confidencialidade" },
  "A.6.7": { es: "Trabajo remoto", en: "Remote working", br: "Trabalho remoto" },
  "A.6.8": { es: "Notificación de eventos de seguridad", en: "Information security event reporting", br: "Notificação de eventos de segurança" },
  "A.7.1": { es: "Perímetros de seguridad física", en: "Physical security perimeters", br: "Perímetros de segurança física" },
  "A.7.2": { es: "Entrada física", en: "Physical entry", br: "Entrada física" },
  "A.7.3": { es: "Seguridad de oficinas e instalaciones", en: "Securing offices, rooms and facilities", br: "Segurança de escritórios e instalações" },
  "A.7.4": { es: "Monitoreo de seguridad física", en: "Physical security monitoring", br: "Monitoramento de segurança física" },
  "A.7.8": { es: "Escritorio despejado y pantalla limpia", en: "Clear desk and clear screen", br: "Mesa limpa e tela limpa" },
  "A.7.9": { es: "Seguridad de equipos fuera de instalaciones", en: "Security of assets off-premises", br: "Segurança de ativos fora das instalações" },
  "A.7.10": { es: "Medios de almacenamiento", en: "Storage media", br: "Mídias de armazenamento" },
  "A.7.14": { es: "Eliminación segura o reutilización de equipos", en: "Secure disposal or re-use of equipment", br: "Descarte seguro ou reutilização de equipamentos" },
  "A.8.1": { es: "Dispositivos de punto final de usuario", en: "User endpoint devices", br: "Dispositivos de endpoint do usuário" },
  "A.8.2": { es: "Derechos de acceso privilegiados", en: "Privileged access rights", br: "Direitos de acesso privilegiado" },
  "A.8.3": { es: "Restricción de acceso a la información", en: "Information access restriction", br: "Restrição de acesso a informações" },
  "A.8.4": { es: "Acceso al código fuente", en: "Access to source code", br: "Acesso ao código-fonte" },
  "A.8.5": { es: "Autenticación segura", en: "Secure authentication", br: "Autenticação segura" },
  "A.8.6": { es: "Gestión de capacidad", en: "Capacity management", br: "Gestão de capacidade" },
  "A.8.7": { es: "Protección contra malware", en: "Protection against malware", br: "Proteção contra malware" },
  "A.8.8": { es: "Gestión de vulnerabilidades técnicas", en: "Management of technical vulnerabilities", br: "Gestão de vulnerabilidades técnicas" },
  "A.8.9": { es: "Gestión de configuraciones", en: "Configuration management", br: "Gestão de configuração" },
  "A.8.10": { es: "Eliminación de información", en: "Information deletion", br: "Exclusão de informações" },
  "A.8.11": { es: "Enmascaramiento de datos", en: "Data masking", br: "Mascaramento de dados" },
  "A.8.12": { es: "Prevención de fuga de datos (DLP)", en: "Data leakage prevention", br: "Prevenção de vazamento de dados" },
  "A.8.13": { es: "Copias de seguridad de la información", en: "Information backup", br: "Backup de informações" },
  "A.8.14": { es: "Redundancia de instalaciones de procesamiento", en: "Redundancy of information processing facilities", br: "Redundância de instalações" },
  "A.8.15": { es: "Registro y auditoría de eventos (Logs)", en: "Logging", br: "Registro de logs" },
  "A.8.16": { es: "Actividades de monitoreo", en: "Monitoring activities", br: "Atividades de monitoramento" },
  "A.8.17": { es: "Sincronización del reloj (NTP)", en: "Clock synchronization", br: "Sincronização de relógio" },
  "A.8.18": { es: "Uso de programas de utilidades privilegiadas", en: "Use of privileged utility programs", br: "Uso de programas utilitários privilegiados" },
  "A.8.19": { es: "Instalación de software en sistemas operativos", en: "Installation of software on operational systems", br: "Instalação de software em sistemas operacionais" },
  "A.8.20": { es: "Seguridad de redes", en: "Networks security", br: "Segurança de redes" },
  "A.8.21": { es: "Seguridad de servicios de red", en: "Security of network services", br: "Segurança de serviços de rede" },
  "A.8.22": { es: "Segregación de redes", en: "Segregation of networks", br: "Segregação de redes" },
  "A.8.23": { es: "Filtrado web", en: "Web filtering", br: "Filtragem web" },
  "A.8.24": { es: "Uso de criptografía", en: "Use of cryptography", br: "Uso de criptografia" },
  "A.8.25": { es: "Ciclo de vida de desarrollo seguro", en: "Secure development life cycle", br: "Ciclo de vida de desenvolvimento seguro" },
  "A.8.26": { es: "Requisitos de seguridad de aplicaciones", en: "Application security requirements", br: "Requisitos de segurança de aplicações" },
  "A.8.27": { es: "Arquitectura e ingeniería de sistemas seguros", en: "Secure system architecture and engineering principles", br: "Arquitetura e engenharia de sistemas seguros" },
  "A.8.28": { es: "Codificación segura", en: "Secure coding", br: "Codificação segura" },
  "A.8.29": { es: "Pruebas de seguridad en desarrollo y aceptación", en: "Security testing in development and acceptance", br: "Testes de segurança em desenvolvimento e aceitação" },
  "A.8.30": { es: "Desarrollo subcontratado", en: "Outsourced development", br: "Desenvolvimento terceirizado" },
  "A.8.31": { es: "Separación de entornos de desarrollo, prueba y producción", en: "Separation of development, test and production environments", br: "Separação de ambientes de desenvolvimento, teste e produção" },
  "A.8.32": { es: "Gestión del cambio", en: "Change management", br: "Gestão de mudanças" },
  "A.8.33": { es: "Información de prueba", en: "Test information", br: "Informações de teste" },
  "A.8.34": { es: "Protección de sistemas durante auditorías", en: "Protection of information systems during audit testing", br: "Proteção de sistemas durante auditorias" },
}

export function localizeComplianceTitle(id: string, rawTitle: string, locale: string): string {
  const normId = id.trim().toUpperCase()
  const lang = locale === "es" ? "es" : locale === "br" ? "br" : "en"

  if (lang === "en") return rawTitle

  // Check NIST CSF
  if (NIST_CSF_TITLES[normId]?.[lang]) {
    return NIST_CSF_TITLES[normId][lang]
  }

  // Check ISO 27001
  const isoKey = id.trim()
  if (ISO27001_TITLES[isoKey]?.[lang]) {
    return ISO27001_TITLES[isoKey][lang]
  }

  return rawTitle
}

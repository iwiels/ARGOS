---
name: "remediation-timeline-prioritization"
description: "Estructura las recomendaciones del reporte final en tres horizontes (P0 inmediato, P1 30 días, P2 90 días) por criterio de urgencia, no por severidad cruda del hallazgo — evita reportes donde todo aparece 'crítico' o donde lo urgente se pierde entre lo importante."
domain: cybersecurity
subdomain: reporting
tags: ["remediation", "prioritization", "executive-summary", "reporting"]
mitre_attack: ["T1595"]
nist_csf: ["RS.MI-01", "RS.MI-02"]
iso_27001: ["A.5.24", "A.8.8"]
source_adapted_from: "remediation-plan-prioritizer (adaptación local, consolidada desde Anthropic-Cybersecurity-Skills, Apache-2.0) — a diferencia de las demás skills de esta biblioteca, no es una skill de detección: es de síntesis, para el agente security-report."
---

# Skill: Priorización temporal del plan de remediación

Distinta en naturaleza a las demás skills de esta biblioteca: no detecta
hallazgos, estructura cómo se presentan una vez detectados. Es la skill que
convierte una lista plana de hallazgos por severidad en un plan de acción
que un cliente no técnico puede ejecutar.

## Cuándo usar esta skill

- Al redactar la sección de remediación del reporte final — trabajo de
  `security-report` sobre los hallazgos ya consolidados de todo el equipo.

## Por qué "severidad" no es lo mismo que "prioridad temporal"

Un hallazgo `crítico` con explotación compleja y baja probabilidad de ser el
vector real de ataque no necesariamente va antes en el tiempo que un
hallazgo `alto` con explotación trivial y evidencia de estar ya indexado
públicamente (Shodan, Google dorking). Esta skill ordena por **urgencia de
acción**, que combina severidad, facilidad de explotación, y visibilidad
externa — no solo el campo `severity` del hallazgo.

## Criterios de clasificación

### 🔴 P0 — Inmediato (24-48 horas)
Riesgo inminente de explotación, impacto reputacional severo, o fallo
criptográfico crítico ya en producción. Ejemplos del propio corpus de
auditorías de Argos: reinstalar un certificado wildcard vigente en el
binding incorrecto (split-brain SSL, se resuelve en minutos y el fix ya
existe), cerrar puertos de gestión expuestos directamente a internet,
bloquear acceso a paneles con credenciales por defecto.

### 🟠 P1 — Corto plazo (30 días)
Endurecimiento de configuración base, mitigación de riesgo de suplantación,
remediación de software con CVEs públicas conocidas. Ejemplos: actualizar
CMS/plugins a versión soportada, configurar DKIM + escalar política DMARC
(`quarantine` → `reject`), colocar portales internos detrás de VPN/MFA.

### 🟡 P2 — Mediano plazo (90 días)
Endurecimiento de arquitectura y gobernanza estructural. Ejemplos:
despliegue de WAF con reglas específicas, MTA-STS/TLS-RPT/DNSSEC/CAA,
publicación de `security.txt` y política de divulgación coordinada,
micro-segmentación de red.

## Procedimiento

1. **Clasificar cada hallazgo consolidado en uno de los tres horizontes**,
   no solo por su `severity` sino evaluando: ¿el fix es de bajo esfuerzo y
   alto impacto (sube a P0 aunque la severidad sea media)? ¿Requiere cambio
   de arquitectura que no puede resolverse en días (baja a P2 aunque la
   severidad sea alta)?
2. **Agrupar hallazgos relacionados bajo una sola acción de remediación**
   cuando comparten causa raíz — p. ej. varios headers de seguridad
   ausentes son una sola línea de acción de configuración de servidor, no
   N líneas separadas en el plan.
3. **Justificar cada horizonte con una frase de retorno de seguridad**, no
   solo listar la acción — el cliente necesita entender por qué P0 y no
   P1, especialmente si el equipo interno tiene que priorizar contra otro
   trabajo.
4. **Presentar en bloque ordenado**, P0 primero, con viñetas concisas — es
   la sección que un ejecutivo no técnico realmente lee completa.

## Salida

No persiste hallazgos nuevos — estructura la sección de remediación del
reporte generado por `security-report`, referenciando los hallazgos ya
persistidos por `id`/`fingerprint`.

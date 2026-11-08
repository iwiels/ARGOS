---
name: "agentic-pipeline-hardening-review"
description: "Evalúa la madurez de gobernanza del propio pipeline agéntico/MCP del cliente (aislamiento de subagentes, validación de schema, principio de solo-lectura) — distinta de mcp-server-tool-poisoning (audita servidores MCP de terceros) y prompt-injection-in-llm-integrations (prueba inyección activa)."
domain: cybersecurity
subdomain: ai-security
tags: ["ai-security", "agentic-governance", "mcp-hardening", "subagent-isolation", "schema-validation"]
mitre_atlas: ["AML.T0051", "AML.T0043", "AML.T0054"]
nist_ai_rmf: ["GOVERN-1.1", "MAP-1.5", "MEASURE-2.6"]
source_adapted_from: "agentic-mcp-security (adaptación local, consolidada desde Anthropic-Cybersecurity-Skills, Apache-2.0) — reescrita de reglas de gobernanza INTERNA (cómo debe comportarse un agente) a checklist de AUDITORÍA de la gobernanza agéntica de un cliente."
---

# Skill: Revisión de hardening del pipeline agéntico del cliente

Distinta de las otras dos skills de `ai-security/`: no prueba una
vulnerabilidad específica contra la aplicación del cliente — evalúa si su
**arquitectura de gobernanza agéntica** (cómo diseñaron el control de sus
propios agentes/pipelines MCP) sigue prácticas maduras. Es la skill correcta
cuando el cliente construyó su propia plataforma de agentes de IA (no solo
integró un chatbot de terceros) y el engagement incluye revisar esa
arquitectura, no solo probarla desde fuera.

## Cuándo usar esta skill

- El cliente tiene su propia infraestructura de agentes/MCP (documentación
  de arquitectura, acceso a configuración de permisos de sus agentes, o
  código fuente del orquestador en el alcance de `security-code`).
- Complementa, no reemplaza: `mcp-server-tool-poisoning` (para servidores
  MCP específicos de terceros) y `prompt-injection-in-llm-integrations`
  (para probar inyección activa contra una aplicación ya desplegada).

## Checklist de gobernanza a evaluar

1. **Principio de solo-lectura por defecto.** ¿Las herramientas de
   reconocimiento/consulta del cliente operan en modo no-destructivo salvo
   confirmación explícita del operador humano? Si el diseño del cliente
   permite que un agente ejecute acciones con efecto secundario
   (escritura, borrado, envío) sin ese punto de confirmación, es un
   hallazgo de arquitectura — independientemente de si algún ataque
   específico ya lo explotó.

2. **Sanitización de contenido no confiable.** ¿El pipeline del cliente
   trata el texto proveniente de fuentes externas (respuestas HTTP,
   documentos subidos, resultados de búsqueda) como **datos**, nunca como
   instrucciones? Revisar si hay algún punto donde contenido externo se
   concatena directamente al prompt del sistema sin demarcación — esa
   ausencia de demarcación es la causa raíz estructural detrás de la
   mayoría de casos de inyección indirecta.

3. **Validación estricta de schema en cada tool call.** ¿Las llamadas a
   herramientas del cliente validan contra un schema tipado (JSON Schema,
   Zod, Effect Schema) antes de ejecutar, o confían en que el modelo
   generó parámetros bien formados? Sin validación de schema, un modelo
   comprometido por inyección de prompt tiene más superficie para pasar
   parámetros inesperados a una tool con efectos reales.

4. **Aislamiento de permisos entre subagentes.** Si el cliente usa una
   arquitectura multi-agente (como la propia Argos), ¿cada subagente
   tiene acceso limitado al dominio específico de su tarea, o todos los
   subagentes comparten el mismo conjunto de permisos/herramientas? Un
   subagente de "solo lectura de logs" con acceso de escritura a producción
   por defecto es sobre-privilegio de arquitectura, mismo patrón que
   `cloud-iam-overprivilege` pero a nivel de agente en vez de cuenta cloud.

5. **Registro de gobernanza (audit log) de decisiones del agente.** ¿Existe
   un log de qué herramientas se invocaron, con qué parámetros, y qué
   confirmaciones humanas se solicitaron/recibieron? Sin esto, un incidente
   causado por un agente (acción incorrecta, dato filtrado) no es
   investigable después del hecho.

## Mapeo de framework

Nota: MITRE ATLAS y NIST AI RMF (citados en el frontmatter) son frameworks
distintos de ATT&CK Enterprise/NIST CSF, sin catálogo consultable en código
todavía en Argos — se citan aquí como referencia textual únicamente
(mismo tratamiento que en `mcp-server-tool-poisoning`, ver `NOTICE.md`).

## Salida

Persistir con `argos_memory_save`, `kind: "finding"` con
`cwe: "CWE-284"` (Improper Access Control) para ausencia de aislamiento de
permisos entre subagentes, o como observación de arquitectura si no hay un
CWE que aplique directamente — documentar igual, con `severity: "medium"`
por defecto salvo evidencia de que la brecha ya fue explotada o es
trivialmente explotable.

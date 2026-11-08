---
name: "mcp-server-tool-poisoning"
description: "Audita servidores MCP (Model Context Protocol) de terceros en el alcance del cliente en busca de descripciones de tool engañosas, actualización silenciosa de definiciones (rug pull), y exfiltración de datos vía parámetros de tool."
domain: cybersecurity
subdomain: ai-security
tags: ["mcp", "ai-security", "tool-poisoning", "prompt-injection", "llm-supply-chain", "rug-pull"]
mitre_attack: ["T1195"]
nist_csf: ["PR.PS-06", "GV.SC-05"]
source_adapted_from: "auditing-mcp-servers-for-tool-poisoning (Anthropic-Cybersecurity-Skills, Apache-2.0) — adaptada al contexto en que Argos mismo consume MCP: se aplica a servidores de TERCEROS en el alcance del cliente, no a la infraestructura propia de Argos."
---

# Skill: Envenenamiento de tools en servidores MCP

MCP (Model Context Protocol) es una superficie de ataque nueva y poco
auditada: un servidor MCP puede describir sus tools de forma engañosa para
manipular al agente que las consume, o cambiar su comportamiento después de
que el operador humano ya aprobó su uso. Argos consume MCP para sus
propias tools — esta skill audita servidores MCP **de terceros** en el
alcance del engagement (p. ej. si el cliente expone o integra servidores MCP
propios), no la infraestructura de Argos.

## Cuándo usar esta skill

- El alcance del engagement incluye una aplicación o infraestructura del
  cliente que integra servidores MCP (propios o de terceros) como parte de
  un flujo agéntico de IA.
- El cliente pregunta específicamente por riesgo de "supply chain de
  herramientas de IA" o "seguridad de integraciones MCP".

## Alcance y límites

Es revisión de configuración/definición de tools, no explotación activa
contra el modelo de IA del cliente. El objetivo es identificar
**definiciones de tool** que podrían manipular a un agente, no ejecutar un
ataque de prompt injection real contra un sistema en producción sin
autorización explícita para esa prueba específica.

## Procedimiento

1. **Revisar las descripciones de cada tool expuesta por el servidor MCP.**
   Buscar instrucciones dirigidas al *modelo* (no al usuario humano)
   embebidas en el campo `description` — texto como "always call this tool
   first", "do not tell the user about this parameter", o instrucciones
   condicionales que solo tendrían sentido si están destinadas a manipular
   el razonamiento del agente en vez de documentar la tool para un
   desarrollador humano.

2. **Comparar el schema de parámetros contra el propósito declarado de la
   tool.** Una tool cuyo nombre sugiere una función acotada (`get_weather`)
   pero cuyo schema acepta parámetros no relacionados (`user_credentials`,
   `file_path`, `system_prompt`) es indicio de exfiltración: el servidor
   podría estar diseñado para que el agente le pase datos sensibles del
   contexto de la conversación bajo la apariencia de un parámetro legítimo.

3. **Verificar si las definiciones de tool son estables entre invocaciones**
   (rug pull). Si es posible observar el servidor en dos momentos distintos
   (antes y después de que el cliente ya lo aprobó/confió en él), comparar
   las descripciones — un servidor que cambia su comportamiento después de
   la aprobación inicial del usuario es el patrón de ataque "tool rug
   pull": aprobado con una descripción benigna, modificado después.

4. **Revisar aislamiento entre servidores MCP en el mismo cliente/agente.**
   Si el cliente conecta múltiples servidores MCP al mismo agente, un
   servidor malicioso podría intentar "shadowing" — describir sus tools de
   forma que el agente las prefiera sobre las de un servidor legítimo con
   nombre similar, o inyectar instrucciones que afecten cómo el agente usa
   las tools de *otros* servidores en el mismo contexto.

5. **Revisar el canal de transporte y autenticación del servidor MCP.** Un
   servidor MCP expuesto sobre HTTP sin autenticación, alcanzable por
   cualquiera en la red del cliente, permite que un actor no autorizado
   registre tools maliciosas en el mismo espacio que las legítimas.

## Mapeo MITRE ATT&CK

MITRE ATLAS (framework separado para amenazas a sistemas de IA/ML, distinto
de ATT&CK Enterprise) tiene técnicas más específicas para este dominio
(p. ej. `AML.T0051` Prompt Injection); no está integrado como catálogo
consultable en Argos aún (ver `NOTICE.md`). Como aproximación con
ATT&CK Enterprise:

| ID | Técnica | Táctica |
|---|---|---|
| T1195 | Supply Chain Compromise | Initial Access |

## Salida

Persistir con `argos_memory_save`, `cwe: "CWE-1426"` (Improper
Validation of Generative AI Output) si aplica, o `CWE-506` (Embedded
Malicious Code) para instrucciones dirigidas al modelo embebidas en
descripciones. `evidence` debe citar el texto exacto de la descripción de
tool sospechosa. `needs_followup_by: ["security-code"]` si el servidor MCP
sospechoso es parte del propio código del cliente en el repositorio en
scope.

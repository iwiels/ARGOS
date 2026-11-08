# Biblioteca de skills de conocimiento

Este directorio complementa las skills operativas de Argos (`auditoria-web`,
`auditoria-red`, `auditoria-recon` — cada una con su propio script ejecutable)
con **skills de conocimiento**: procedimientos de razonamiento que le dan a los
agentes técnica y contexto MITRE ATT&CK / NIST CSF más allá de lo que una tool
envuelta puede producir por sí sola.

Se descubren automáticamente (glob `skills/**/SKILL.md`, ver
`packages/argos/src/skill/index.ts`) y ya son accesibles por todos los
agentes `security-*`, cuyo frontmatter tiene `skill: "*": allow` — no requieren
wiring adicional.

## Diferencia con las skills operativas existentes

| | `auditoria-web` / `auditoria-red` / `auditoria-recon` | Esta biblioteca |
|---|---|---|
| Qué son | Procedimiento + **script propio** (`scripts/*.mjs`) que el agente ejecuta | Procedimiento **sin script propio** — razonamiento y checklist |
| Cuándo actuar | Siempre, en cada auditoría del tipo correspondiente | Cuando el alcance del engagement toca ese dominio (cloud, API, AD, IA…) |
| Herramientas que asume | Las que Argos ya envuelve (`web.*`, `lan.*`, `es.*`) | Las mismas — **nunca** asume tools externas que no tenemos (Mimikatz, SharpDPAPI, BloodHound, Sliver C2…) |

Esa última fila es la adaptación más importante frente a la fuente original.

## Procedencia y licencia

Curado y adaptado a partir de
[mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills)
(Apache License 2.0, 817 skills, formato `agentskills.io`). Ver `NOTICE.md` en
este mismo directorio para la atribución completa requerida por la licencia.

**Adaptación, no copia.** El repo fuente son skills *operativas* de red team
(asumen Mimikatz, SharpDPAPI, BloodHound, Sliver C2 — herramientas que
Argos no envuelve). Cada skill de esta biblioteca fue **reescrita** como
skill de *detección/auditoría*: razona sobre evidencia que nuestras tools
(`web.*`, `lan.*`, `es.*`) sí pueden producir, o sobre configuración que el
cliente entrega (exports de IAM, manifiestos de Kubernetes). Ninguna skill de
aquí le pide al agente ejecutar un binario que no está en nuestro motor MCP.

## Estado: dos tandas consolidadas, no el catálogo completo

**28 skills** en 10 categorías. Primero 18, eligiendo los huecos de mayor
prioridad identificados durante la curación (cloud/contenedores/API/IA — cobertura cero previa)
más profundización en dominios que ya cubríamos (web, detección en
red/AD). Después 10 más, consolidadas desde una segunda tanda de trabajo
independiente sobre el mismo repositorio fuente (ver `NOTICE.md`, sección
"Segunda fuente consolidada") — fusionando en vez de duplicar donde había
solape. Esto sigue siendo una **fundación de calidad verificable**, no un
volcado: mejor 28 skills técnicamente correctas, con IDs de framework
verificados contra nuestros propios catálogos, que 120 genéricas.

| Categoría | Skills | Por qué esta prioridad |
|---|---:|---|
| `cloud-security/` | 4 | Cobertura cero previa; una de las necesidades prioritarias identificadas |
| `container-security/` | 3 | Cobertura cero previa |
| `api-security/` | 5 | Descubrimiento de superficie + BOLA, JWT, GraphQL, rate limiting sobre lo que `web.*` ya detecta |
| `ai-security/` | 4 | Diferenciador de bajo-competencia; **directamente relevante** — Argos mismo es consumidor MCP |
| `active-directory-detection/` | 3 | Profundiza lo que `lan.*` ya detecta, sin asumir tooling de explotación AD |
| `web-hardening/` | 3 | Headers/CSP, certificados TLS, y CMS — los tres patrones más citados en el corpus real de auditorías |
| `compliance-mapping/` | 2 | Crosswalk directo a NIST CSF/ISO 27001 + correlación ATT&CK↔D3FEND — refuerza el panel de Cumplimiento |
| `dns-security/` | 2 | DNS (DNSSEC/CAA/takeover) + autenticación de correo (SPF/DKIM/DMARC/MTA-STS) |
| `network-security/` | 1 | Exposición perimetral no-cloud + contigüidad de bloques `/24` |
| `reporting/` | 1 | Priorización temporal de remediación (P0/P1/P2) — skill de síntesis para `security-report`, no de detección |

## Mapeo de framework — integración real, no decorativa

Cada `SKILL.md` de esta biblioteca lleva `mitre_attack: [...]` en el
frontmatter. Las técnicas nuevas que no existían en nuestro catálogo se
añadieron a `packages/core/src/threat-intel/attack.ts` (`ATTACK_CATALOG`) —
el mismo catálogo que ya usa `mapFindingToAttack()` para etiquetar hallazgos
reales en los paneles de Hallazgos y Cumplimiento. Esto es lo que hace que
"razonar con las técnicas" sea cierto: un hallazgo que coincide con los tags
de una skill de aquí (p. ej. `container-escape`, `jwt`, `kerberoasting`)
ahora se clasifica correctamente en el panel, no solo en el texto de la skill.

Ver el detalle técnico de las técnicas añadidas en el propio diff de
`attack.ts` y sus tests (`attack.test.ts`).

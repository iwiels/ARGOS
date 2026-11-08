---
name: "nist-iso-finding-crosswalk"
description: "Traduce categorías técnicas de hallazgo (TLS, DMARC, headers, software EOL, puertos expuestos, gobernanza) a controles NIST CSF 2.0 e ISO/IEC 27001:2022, para que la evidencia entre correctamente al panel de Cumplimiento."
domain: cybersecurity
subdomain: compliance-mapping
tags: ["compliance", "nist-csf", "iso-27001", "framework-mapping", "crosswalk"]
mitre_attack: ["T1592"]
nist_csf: ["GV.OC-01", "ID.RA-01", "PR.DS-01", "PR.AA-01", "DE.CM-01"]
iso_27001: ["A.5.1", "A.8.8", "A.8.20", "A.8.24"]
source_adapted_from: "compliance-nist-iso-mapper (adaptación local, consolidada desde Anthropic-Cybersecurity-Skills, Apache-2.0) — reescrita para citar el control exacto que ya existe en nuestro catálogo bundled en vez de solo describirlo en prosa."
---

# Skill: Crosswalk de hallazgo técnico a NIST CSF / ISO 27001

Argos ya tiene el catálogo de controles NIST CSF 2.0 e ISO/IEC 27001:2022
cargado (`packages/core/src/compliance/bundled/`), y el panel de Cumplimiento
deriva su estado (`Cumple`/`Deficiente`) directamente de los hallazgos
persistidos — no de una evaluación manual aparte. Esta skill es la tabla de
traducción para que un hallazgo técnico llegue con el control correcto desde
el momento en que se persiste, en vez de quedar sin mapear.

## Cuándo usar esta skill

- Siempre, en el momento de persistir cualquier hallazgo con
  `argos_memory_save` — es el último paso antes de guardar, no una
  revisión posterior.
- Especialmente relevante para `security-report`, que sintetiza la evidencia
  de todo el equipo hacia el reporte final y el panel de Cumplimiento.

## Matriz de correspondencia

| Categoría técnica del hallazgo | Control NIST CSF 2.0 | Control ISO/IEC 27001:2022 |
|---|---|---|
| Certificados TLS vencidos / split-brain SSL | `PR.DS-01` (cifrado de datos en tránsito) | `A.8.24` (uso de criptografía) |
| DMARC `p=none` / SPF permisivo / superficie BEC | `PR.DS-02` (protección contra fuga/impersonación) | `A.8.20` (seguridad de redes y comunicaciones) |
| Cabeceras HTTP ausentes / fuga de versión de software | `PR.PS-04` (configuración segura de plataformas) | `A.8.26` (requisitos de seguridad en aplicaciones) |
| Software EOL / plugins con CVEs conocidas | `ID.RA-01` (evaluación de vulnerabilidades) | `A.8.8` (gestión de vulnerabilidades técnicas) |
| Puertos/servicios de gestión expuestos | `PR.AA-05` (protección de accesos remotos y de red) | `A.8.21` (seguridad en servicios de red) |
| Falta de política de divulgación / `security.txt` | `GV.PO-01` (gobernanza y políticas) | `A.5.1` (políticas para la seguridad de la información) |
| PII de empleados expuesta públicamente | `PR.AA-01` (gestión de identidades y credenciales) | `A.5.34` (privacidad y protección de PII) |
| Bucket/storage cloud público | `PR.DS-01` | `A.8.24` |
| RBAC/IAM sobre-privilegiado (cloud o k8s) | `PR.AA-05` | `A.8.2` (privilegios de acceso) |

## Procedimiento

1. **Identificar la categoría técnica del hallazgo** antes de escribir el
   `evidence` — la tabla de arriba es el primer punto de consulta, no una
   referencia opcional.
2. **Citar el identificador exacto del control**, no una paráfrasis
   ("PR.DS-01", nunca "protección de datos en general") — el panel de
   Cumplimiento correlaciona por ese identificador contra el catálogo
   bundled.
3. **Si la categoría no está en la tabla**, no inventar un control: dejar el
   hallazgo sin mapeo de compliance (aún se persiste como hallazgo de
   seguridad normal) y señalarlo en el resumen para que se añada una fila a
   esta tabla en la siguiente iteración de la skill.
4. **Vincular la evidencia cruda al control**: salida de `openssl s_client`,
   respuesta HTTP con el header ausente, registro DNS consultado — el panel
   de Cumplimiento muestra esa evidencia junto al estado del control, no solo
   el veredicto.

## Salida

No es una skill que genera hallazgos nuevos por sí sola — enriquece el
`evidence`/metadata de hallazgos ya identificados por otras skills con el
control formal correspondiente, antes de la llamada a
`argos_memory_save`.

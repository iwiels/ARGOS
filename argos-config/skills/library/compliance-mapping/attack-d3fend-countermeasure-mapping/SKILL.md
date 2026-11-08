---
name: "attack-d3fend-countermeasure-mapping"
description: "Para cada técnica MITRE ATT&CK identificada en un hallazgo, cita la contramedida MITRE D3FEND correspondiente en la narrativa de remediación — convierte 'qué técnica habilita esto' en 'qué debe desplegar el cliente para neutralizarlo'."
domain: cybersecurity
subdomain: compliance-mapping
tags: ["mitre-attack", "d3fend", "remediation", "countermeasure"]
mitre_attack: ["T1566.002", "T1190", "T1557", "T1046", "T1584.004", "T1078"]
source_adapted_from: "mitre-attack-d3fend-correlator (adaptación local, consolidada desde Anthropic-Cybersecurity-Skills, Apache-2.0)."
---

# Skill: De técnica ATT&CK a contramedida D3FEND

`packages/core/src/threat-intel/attack.ts` (`ATTACK_CATALOG` +
`mapFindingToAttack`) ya asigna técnicas MITRE ATT&CK a cada hallazgo de
forma automática y verificable — eso es dato real, consultado por los
paneles. **MITRE D3FEND no tiene un catálogo equivalente en código todavía**
(ver `NOTICE.md` de esta biblioteca): esta skill es la referencia textual
que el agente usa para completar la narrativa de remediación con la
contramedida correcta, no un lookup automático.

## Cuándo usar esta skill

- Al redactar la sección de remediación de un hallazgo que ya tiene técnica
  ATT&CK asignada (por `mapFindingToAttack` o por el propio agente).
- Especialmente útil para `security-report`, que debe justificar cada
  recomendación de remediación con el mecanismo de defensa que la sustenta,
  no solo con "corregir esto".

## Tabla de referencia

| Técnica ATT&CK | Nombre | Contramedida D3FEND | Acción defensiva concreta |
|---|---|---|---|
| `T1566.002` | Phishing: Spearphishing Link | `D3-MDA` (Message Delivery Authentication) | SPF `-all`, DKIM criptográfico, DMARC `p=reject` |
| `T1190` | Exploit Public-Facing Application | `D3-ARA` (Application Request Analysis) | Reglas de WAF, inspección de payload, límites de tasa |
| `T1557` | Adversary-in-the-Middle | `D3-CTA` (Certificate Authority Trust Analysis) | HSTS preload, registros DNS CAA, revocación de suites débiles |
| `T1046` | Network Service Discovery | `D3-NFA` (Network Filtering Analysis) | Bloqueo perimetral, ACLs, segmentación |
| `T1584.004` | Compromise Infrastructure: DNS Server | `D3-DNSB` (DNS Binding Verification) | DNSSEC firmado, monitoreo de resoluciones anómalas |
| `T1078` | Valid Accounts | `D3-MFA` (Multi-Factor Authentication) | MFA condicional obligatorio, rotación de credenciales |
| `T1611` | Escape to Host | `D3-PM` (Process Monitoring) / eliminar `privileged: true` | Retirar montaje del socket Docker, capacidades Linux innecesarias |

## Procedimiento

1. **Partir de la técnica ya asignada** (por el catálogo en código o por
   criterio del agente) — no inventar una técnica solo para tener algo que
   mapear a D3FEND.
2. **Citar ambos identificadores en la narrativa de remediación**: la
   técnica ofensiva justifica *por qué* importa, la contramedida D3FEND
   justifica *qué* implementar — evita recomendaciones genéricas tipo
   "mejorar la seguridad".
3. **Si la técnica no está en esta tabla**, no forzar una fila — es
   preferible omitir la referencia D3FEND que inventar una contramedida sin
   respaldo. Señalar la ausencia para ampliar la tabla en la siguiente
   iteración.

## Salida

No genera hallazgos — enriquece el campo `remediation` de hallazgos ya
identificados con la referencia D3FEND antes de `argos_memory_save`, o
se usa directamente en la redacción del reporte final.

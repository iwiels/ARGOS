---
name: "cloud-iam-overprivilege"
description: "Audita políticas IAM de AWS/Azure/GCP entregadas por el cliente en busca de permisos excesivos, wildcards peligrosos y separación de funciones rota."
domain: cybersecurity
subdomain: cloud-security
tags: ["cloud", "iam", "aws", "azure", "gcp", "overprivilege", "least-privilege", "wildcard-policy"]
mitre_attack: ["T1526", "T1078.004"]
nist_csf: ["PR.AA-05", "GV.PO-01"]
source_adapted_from: "auditing-gcp-iam-permissions / auditing-azure-active-directory-configuration (Anthropic-Cybersecurity-Skills, Apache-2.0) — consolidadas en una skill agnóstica de proveedor, orientada a revisión de exports entregados por el cliente."
---

# Skill: Sobre-privilegio en IAM cloud

A diferencia de un pentest de red, esta skill **no escanea** — audita
documentos de política que el cliente entrega (export de IAM en JSON/YAML),
porque Argos no tiene credenciales cloud del cliente ni las necesita
para este análisis. Es la skill correcta cuando el engagement incluye una
fase de revisión de configuración cloud, no solo superficie externa.

## Cuándo usar esta skill

- El cliente comparte un export de políticas IAM (AWS `aws iam
  get-account-authorization-details`, Azure role assignments, GCP
  `gcloud projects get-iam-policy`) como insumo del engagement.
- El scope declarado incluye "revisión de configuración cloud" o
  "hardening review", no solo superficie de ataque externa.

## Alcance y límites

Trabaja exclusivamente sobre el documento entregado. Si no hay export
disponible, esta skill no aplica — no se debe intentar adivinar
configuración IAM ni asumir acceso a la cuenta cloud del cliente.

## Procedimiento

1. **Localizar wildcards peligrosos.** Buscar en las políticas:
   - `"Action": "*"` combinado con `"Resource": "*"` — acceso administrativo
     total, la señal más grave.
   - `"Action": "iam:*"` o `"Action": "*Policy*"` sobre cualquier resource —
     permite auto-escalación de privilegios (el principal puede otorgarse a
     sí mismo más permisos).
   - Acciones de escritura amplias (`s3:*`, `ec2:*`) sin restricción de
     `Resource` a ARNs específicos.

2. **Revisar separación de funciones.** Un mismo principal (usuario o service
   account) con permisos de escritura de datos **y** de auditoría/logging
   (p. ej. `cloudtrail:StopLogging`, `logging.sinks.delete`) rompe la
   separación de funciones: puede actuar y luego borrar la evidencia.

3. **Identificar credenciales de larga vida sin rotación.** Access keys de
   IAM users (AWS) o service account keys (GCP) sin política de expiración
   son un vector persistente — a diferencia de roles asumibles con STS/
   Workload Identity, que expiran.

4. **Cruzar con el principio de mínimo privilegio declarado.** Si el cliente
   documentó qué debería poder hacer cada rol (matriz RACI, descripción de
   puesto), comparar la política real contra esa expectativa — la brecha
   entre "lo que necesita" y "lo que tiene" es el hallazgo, no la política en
   sí misma.

5. **Priorizar por blast radius, no por cantidad de permisos.** Un rol con 3
   permisos de administración total es más grave que uno con 40 permisos de
   solo lectura sobre un servicio acotado.

## Mapeo MITRE ATT&CK

| ID | Técnica | Táctica |
|---|---|---|
| T1526 | Cloud Service Discovery | Discovery |
| T1078.004 | Valid Accounts: Cloud Accounts | Initial Access, Persistence, Privilege Escalation, Defense Evasion |

## Salida

Persistir con `argos_memory_save`, `cwe: "CWE-269"` (Improper
Privilege Management). `evidence` debe citar el fragmento exacto de la
política (principal + statement), no una paráfrasis. `status: "observed"`
salvo que se haya confirmado con el cliente que el principal está activo y
en uso.

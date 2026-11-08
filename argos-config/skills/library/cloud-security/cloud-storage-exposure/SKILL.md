---
name: "cloud-storage-exposure"
description: "Detecta almacenamiento en la nube (S3, Azure Blob, GCS) accesible públicamente o con permisos excesivos, a partir de URLs descubiertas por recon o exports de configuración entregados por el cliente."
domain: cybersecurity
subdomain: cloud-security
tags: ["cloud", "s3", "azure-blob", "gcs", "bucket", "data-exposure", "misconfiguration"]
mitre_attack: ["T1530", "T1526"]
nist_csf: ["PR.DS-01", "PR.AA-05"]
source_adapted_from: "auditing-aws-s3-bucket-permissions (Anthropic-Cybersecurity-Skills, Apache-2.0) — reescrita como skill de detección/auditoría sin asumir CLI de AWS ni credenciales del cliente."
---

# Skill: Exposición de almacenamiento en la nube

Detecta buckets de S3, contenedores de Azure Blob Storage o buckets de Google
Cloud Storage con acceso público o permisos mal configurados. Es la causa
raíz más frecuente de exposición masiva de datos en auditorías reales — y no
requiere credenciales del cliente para su forma básica de detección.

## Cuándo usar esta skill

- El scope incluye subdominios o rutas que apuntan a `*.s3.amazonaws.com`,
  `*.blob.core.windows.net`, `*.storage.googleapis.com`, o dominios con CNAME
  hacia esos endpoints.
- `web.subdomains` / `web.crawl` descubrieron URLs que referencian objetos de
  almacenamiento (imágenes, backups, exports) alojados fuera del dominio
  principal.
- El cliente entrega un export de configuración de su cuenta cloud (política
  de bucket, ACL) como parte del alcance del engagement.

## Alcance y límites

Esta skill **no** usa `aws s3 ls`, `az storage`, `gsutil` ni ningún CLI cloud
— Argos no envuelve esas herramientas y no debe asumir que existen en el
entorno. El descubrimiento es pasivo: URLs ya recolectadas por `web.crawl` /
`web.subdomains`, y verificación con `web.probe` sobre el endpoint del bucket
(una petición HTTP simple a la URL del listado, sin autenticación, ya revela
si el listado está abierto).

## Procedimiento

1. **Identificar candidatos.** De la salida de `web.subdomains`/`web.crawl`,
   filtrar hosts que coincidan con patrones de storage cloud:
   - AWS: `*.s3.amazonaws.com`, `s3.amazonaws.com/<bucket>`, `s3-<region>.amazonaws.com/<bucket>`
   - Azure: `*.blob.core.windows.net`
   - GCP: `storage.googleapis.com/<bucket>`, `*.storage.googleapis.com`

2. **Verificar listado público** con `web.probe` sobre la raíz del bucket
   (`GET` sin parámetros). Una respuesta XML/JSON con `<Contents>` o `items:
   []` en vez de un 403/`AccessDenied` confirma listado abierto — es
   evidencia directa, no inferencia.

3. **Verificar lectura de objetos individuales.** Si el listado está cerrado
   pero se conocen rutas de objetos (por `web.crawl` o por convención de
   nombres), probar `GET` directo sobre 2-3 objetos conocidos. Un bucket
   puede tener listado cerrado y objetos individuales públicos — son hallazgos
   distintos.

4. **Clasificar severidad por contenido, no solo por acceso.** Un bucket
   público con assets estáticos de marketing es informativo; uno con
   backups, `.env`, credenciales o PII es crítico. Inspeccionar los primeros
   objetos listados antes de asignar severidad.

5. **Si el cliente entregó un export de política/ACL:** revisar
   `Principal: "*"` o `AllUsers`/`AllAuthenticatedUsers` (GCP) sin condición
   de IP/VPC — es la causa raíz detrás del listado abierto, y vale la pena
   citarla en la evidencia junto al hallazgo de acceso.

## Mapeo MITRE ATT&CK

| ID | Técnica | Táctica |
|---|---|---|
| T1530 | Data from Cloud Storage | Collection |
| T1526 | Cloud Service Discovery | Discovery |

## Salida

Persistir con `argos_memory_save`: `severity` según el contenido
expuesto (no solo el acceso), `evidence` con la URL exacta probada y el
fragmento de respuesta que confirma el listado/objeto abierto, `cwe: "CWE-284"`
(Improper Access Control) o `CWE-200` si el hallazgo es de exposición de
datos específica. Marcar `needs_followup_by: ["security-ops"]` si el
contenido expuesto involucra PII o credenciales — entra en scope de
compliance.

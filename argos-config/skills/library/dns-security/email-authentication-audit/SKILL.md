---
name: "email-authentication-audit"
description: "Evalúa SPF, DKIM, DMARC, MTA-STS y TLS-RPT con matriz de severidad explícita — profundiza sobre lo que ya detecta el skill auditoria-recon, con criterio de gravedad por política, no solo por presencia/ausencia del registro."
domain: cybersecurity
subdomain: dns-security
tags: ["email-security", "spf", "dkim", "dmarc", "mta-sts", "bec", "anti-spoofing"]
mitre_attack: ["T1586.002", "T1589.002"]
nist_csf: ["PR.DS-02", "DE.AE-02"]
iso_27001: ["A.8.20", "A.8.24"]
source_adapted_from: "email-authentication-audit (adaptación local, consolidada desde Anthropic-Cybersecurity-Skills, Apache-2.0) — complementa (no reemplaza) el chequeo SPF/DMARC de la skill operativa auditoria-recon."
---

# Skill: Auditoría de autenticación de correo (anti-BEC)

`auditoria-recon` (skill operativa con script propio) ya detecta ausencia de
SPF/DMARC vía `recon-core.mjs`, con verificación cruzada contra DNS público
para evitar falsos negativos por resolver local. Esta skill va un paso más
allá: interpreta la **política**, no solo la presencia, y añade DKIM/MTA-STS/
TLS-RPT, que el script no cubre.

## Cuándo usar esta skill

- Después de que `auditoria-recon` confirmó la presencia (o ausencia) de
  SPF/DMARC — esta skill clasifica la severidad real de lo que se encontró.

## Procedimiento

1. **SPF — evaluar la política, no solo la existencia.**
   - `-all` (hard fail): postura correcta.
   - `~all` (soft fail): el receptor puede igual entregar el correo a spam en
     vez de rechazarlo — riesgo medio, no alto.
   - `+all` o ausencia del `all` mechanism: cualquiera puede enviar en nombre
     del dominio — riesgo alto/crítico.
   - Más de 10 DNS lookups transitivos (por `include:`) invalida el registro
     SPF completo según RFC 7208 — si el cliente tiene una cadena larga de
     `include:` (proveedores de email marketing, CRM, etc.), contar los
     lookups; si excede 10, el SPF no está siendo evaluado por los
     receptores aunque parezca bien configurado.

2. **DMARC — la política es el hallazgo, no el registro en sí.**
   - `p=none`: solo monitoreo, **no previene** la suplantación — severidad
     **alta** si es la única línea de defensa (sin DKIM fuerte).
   - `p=quarantine`: correos suplantados van a spam — aceptable como paso
     intermedio.
   - `p=reject`: rechazo en origen — el estándar correcto.
   - Revisar `sp=` (subdomain policy) por separado: un dominio con
     `p=reject` pero sin `sp=reject` deja los subdominios sin protección —
     omisión frecuente.

3. **DKIM — verificar selectores, no solo la existencia del mecanismo.**
   Los selectores DKIM no aparecen en un solo registro DNS enumerable
   directamente; si el cliente los comparte o son conocidos por convención
   del proveedor (`google._domainkey`, `selector1._domainkey` de M365),
   consultarlos. Selector con clave RSA menor a 2048 bits, o que resuelve
   `NXDOMAIN`, invalida la verificación criptográfica — el correo puede
   alegar estar firmado sin que la firma sea verificable.

4. **MTA-STS y TLS-RPT (RFC 8461/8460).** Verificar `_mta-sts.<dominio>` TXT
   y el archivo de política en `https://mta-sts.<dominio>/.well-known/mta-sts.txt`.
   Su ausencia permite degradación de STARTTLS (downgrade a SMTP en claro)
   en tránsito — relevante para dominios que manejan correspondencia
   sensible, severidad baja/media para el resto.

## Matriz de severidad consolidada

| Condición | Severidad |
|---|---|
| Sin DMARC, o `p=none` sin DKIM fuerte | Alta |
| SPF `~all`, o más de 10 lookups | Media |
| DMARC `p=quarantine` sin `sp=` explícito | Media |
| Sin MTA-STS/TLS-RPT | Baja |

## Mapeo MITRE ATT&CK

| ID | Técnica | Táctica |
|---|---|---|
| T1586.002 | Compromise Accounts: Email Accounts | Resource Development |
| T1589.002 | Gather Victim Identity Information: Email Addresses | Reconnaissance |

## Salida

Persistir con `argos_memory_save`, `cwe: "CWE-290"` (Authentication
Bypass by Spoofing) para hallazgos de SPF/DMARC, `cwe: "CWE-347"` para DKIM
con clave débil/no verificable. `evidence` debe incluir el registro DNS
exacto consultado (no una paráfrasis) — mismo estándar que la skill
`dns-infrastructure-audit`.

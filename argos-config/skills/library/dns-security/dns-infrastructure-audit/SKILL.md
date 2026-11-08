---
name: "dns-infrastructure-audit"
description: "Audita DNSSEC, registros CAA, fuga de shadow IT en TXT, y subdomain takeover vía CNAME colgante — a partir de las consultas DNS que web.subdomains ya ejecuta."
domain: cybersecurity
subdomain: dns-security
tags: ["dns", "dnssec", "caa", "subdomain-takeover", "shadow-it", "dangling-cname"]
mitre_attack: ["T1584.004", "T1583.001", "T1592", "T1590"]
nist_csf: ["PR.DS-02", "ID.RA-01"]
iso_27001: ["A.8.20"]
source_adapted_from: "dns-security-audit (adaptación local, consolidada desde Anthropic-Cybersecurity-Skills, Apache-2.0) — reescrita para citar web.subdomains como fuente de datos en vez de asumir consultas DNS ad hoc."
---

# Skill: Auditoría de infraestructura DNS

Cuatro clases de hallazgo distintas comparten la misma fuente de datos: la
zona DNS pública del dominio, que `web.subdomains` ya recolecta como parte
del recon estándar.

## Cuándo usar esta skill

- Siempre que `web.subdomains` haya corrido sobre el target — esta skill
  reinterpreta esos resultados, no requiere una consulta adicional en la
  mayoría de los casos.

## Procedimiento

1. **DNSSEC.** Verificar presencia de registros `DS`/`DNSKEY`/`RRSIG` en la
   zona. Su ausencia no es un hallazgo crítico por sí sola (la mayoría de
   dominios no lo tienen), pero si el cliente maneja transacciones
   financieras o es un objetivo de alto perfil, documentarlo como mejora de
   postura — DNSSEC previene envenenamiento de caché/spoofing de
   resoluciones.

2. **Registros CAA (RFC 8659).** Ausencia total de `CAA` significa que
   *cualquier* autoridad certificadora pública puede emitir un certificado
   válido para el dominio — no es explotable directamente por un atacante
   externo (requeriría comprometer una CA), pero es una capa de defensa en
   profundidad ausente, barata de implementar. Documentar como severidad
   baja/informativa salvo que el cliente ya haya sufrido un incidente de
   emisión no autorizada.

3. **Fuga de shadow IT en registros TXT.** Los registros de verificación de
   propiedad de servicios SaaS (`google-site-verification=`, `MS=`,
   `atlassian-domain-verification=`, tokens de HubSpot/Mailgun) que ya no
   corresponden a un servicio activo revelan el inventario histórico de
   herramientas SaaS de la organización — información útil para un
   atacante en fase de reconocimiento (superficie de phishing dirigido,
   servicios a probar con credenciales reutilizadas). Contar cuántos
   registros de verificación hay: más de 10 sin explicación suele indicar
   acumulación sin limpieza (shadow IT), no necesariamente cada uno
   individual es un hallazgo.

4. **Subdomain takeover.** Para cada `CNAME` descubierto por
   `web.subdomains` que apunte a un servicio cloud (GitHub Pages, S3,
   Azure App Service, Heroku, Fastly, etc.), verificar con `web.probe` si el
   recurso de destino responde con un mensaje de "no reclamado"
   (`NoSuchBucket`, `There isn't a GitHub Pages site here`, `404 Not
   Found` con el patrón específico del proveedor). Si es así, es un
   hallazgo de **severidad crítica**: cualquiera puede registrar ese
   recurso en el proveedor cloud y servir contenido bajo el subdominio de
   la organización — incluyendo phishing con certificado TLS válido, porque
   el subdominio real apunta ahí.

## Mapeo MITRE ATT&CK

| ID | Técnica | Táctica |
|---|---|---|
| T1584.004 | Compromise Infrastructure: DNS Server | Resource Development |
| T1583.001 | Acquire Infrastructure: Domains | Resource Development |
| T1592 | Gather Victim Org Information | Reconnaissance |
| T1590 | Gather Victim Network Information | Reconnaissance |

## Salida

Persistir con `argos_memory_save`. Subdomain takeover confirmado:
`severity: "critical"`, `cwe: "CWE-284"`, `status: "validated"` solo si se
confirmó la respuesta de "no reclamado" del proveedor — `"suspected"` si el
CNAME apunta a un patrón sospechoso pero la respuesta no fue concluyente.
Registros CAA/TXT: `severity: "low"`/`"info"` según corresponda.

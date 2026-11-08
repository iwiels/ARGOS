---
name: "tls-certificate-and-hsts-audit"
description: "Detecta split-brain SSL (certificado desalineado entre apex y subdominios), expiración próxima, protocolos/suites obsoletas, y configuración de HSTS — sobre la respuesta TLS que web.probe ya puede capturar."
domain: cybersecurity
subdomain: web-hardening
tags: ["tls", "ssl", "certificate", "split-brain", "hsts", "cipher-suite"]
mitre_attack: ["T1566.002", "T1557"]
nist_csf: ["PR.DS-01", "PR.DS-02"]
iso_27001: ["A.8.24"]
source_adapted_from: "web-tls-ssl-audit (adaptación local, consolidada desde Anthropic-Cybersecurity-Skills, Apache-2.0)."
---

# Skill: Auditoría criptográfica TLS/SSL

El patrón de hallazgo más citado en auditorías reales de Argos: un
certificado renovado correctamente en el dominio raíz, pero el binding del
subdominio `www` (u otro vhost) sirviendo un certificado desalineado o
vencido — "split-brain SSL". Es fácil de confirmar y de remediar, y de alto
impacto reputacional si no se detecta.

## Cuándo usar esta skill

- Siempre que el scope incluya un endpoint HTTPS — es una de las
  verificaciones de menor costo y mayor tasa de hallazgo real.

## Procedimiento

1. **Recolectar el certificado del apex y de cada vhost por separado.**
   No asumir que el certificado del dominio raíz (`dominio.com`) es el mismo
   que sirve `www.dominio.com` — son bindings distintos en el servidor web
   (IIS, nginx, Apache) y pueden desincronizarse en la renovación. Extraer
   de cada uno: `Subject Alternative Names`, `notBefore`/`notAfter`,
   `Issuer`, `Serial Number`. Una verificación cruzada con `openssl
   s_client -connect <host>:443` contra cada vhost es la evidencia más
   sólida y reproducible para el reporte.

2. **Confirmar split-brain.** Si el apex tiene un certificado vigente
   (`notAfter` futuro) pero un vhost secundario sirve uno vencido o de
   `Issuer`/`Serial` distinto al esperado, es el hallazgo — severidad
   **alta**, porque el fix es casi siempre trivial (reinstalar el
   certificado wildcard vigente en el binding correcto) pero el estado
   actual expone a los visitantes de ese subdominio a advertencias de
   certificado inválido, entrenándolos a ignorar esas advertencias
   (relevante para el análisis de riesgo de phishing).

3. **Revisar ventana de expiración**, no solo vencimiento ya ocurrido:
   `notAfter` menor a 30 días es severidad media (proactivo), menor a 7 días
   sube a alta si no hay evidencia de renovación automática configurada.

4. **Protocolos y suites obsoletas.** TLS 1.0/1.1 aún negociables, o
   ciphers CBC sin Forward Secrecy — documentar cuáles específicamente
   acepta el servidor (no un genérico "cifrado débil"), porque la
   remediación exacta depende de qué protocolo/suite retirar en la
   configuración del servidor.

5. **HSTS.** Verificar presencia del header, `max-age >= 31536000` (1 año),
   y directiva `includeSubDomains`. Ausencia de HSTS no es crítica por sí
   sola pero elimina la protección contra downgrade a HTTP en la primera
   visita del usuario — combinarlo con el resto de headers vía la skill
   `security-headers-and-csp-bypass-patterns` de esta misma biblioteca.

## Falsos positivos a descartar

Certificados de staging/desarrollo en subdominios internos no accesibles
por usuarios finales, y certificados temporales durante ventanas de
mantenimiento ya documentadas por el cliente — confirmar con el cliente
antes de reportar si el subdominio tiene pinta de no-productivo.

## Mapeo MITRE ATT&CK

| ID | Técnica | Táctica |
|---|---|---|
| T1566.002 | Phishing: Spearphishing Link | Initial Access |
| T1557 | Adversary-in-the-Middle | Credential Access, Collection |

## Salida

Persistir con `argos_memory_save`, `cwe: "CWE-295"` (Improper
Certificate Validation) o `CWE-298` (Improper Validation of Certificate
Expiration) según aplique. `evidence` debe incluir la salida exacta de
`openssl s_client` o el fragmento de respuesta que confirma el certificado
desalineado — el mismo estándar de evidencia verificable que ya se usa en
los reportes de Argos. `severity: "high"`, `status: "validated"` si se
confirmó con verificación cruzada real.

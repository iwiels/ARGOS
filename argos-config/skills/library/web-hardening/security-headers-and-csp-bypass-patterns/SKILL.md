---
name: "security-headers-and-csp-bypass-patterns"
description: "Audita headers de seguridad (CSP, HSTS, X-Frame-Options, Permissions-Policy) sobre la respuesta ya capturada por web.probe, y evalúa si una CSP presente es efectivamente restrictiva o tiene patrones de bypass conocidos."
domain: cybersecurity
subdomain: web-hardening
tags: ["web", "security-headers", "csp", "hsts", "clickjacking", "header-bypass"]
mitre_attack: ["T1189"]
nist_csf: ["PR.PS-04"]
source_adapted_from: "Consolidada del enfoque general de hardening de headers en el repo original (Anthropic-Cybersecurity-Skills, Apache-2.0), ampliada específicamente con patrones de bypass de CSP que suelen pasarse por alto al solo verificar 'presencia' del header."
---

# Skill: Headers de seguridad y bypass de CSP

`web.probe` ya captura los headers de respuesta — el error común es
evaluarlos por **presencia** (¿existe el header CSP?) en vez de por
**efectividad** (¿la política que declara realmente restringe algo?). Una
CSP mal configurada da una falsa sensación de seguridad más peligrosa que no
tener CSP en absoluto, porque el equipo del cliente puede creer que ya está
protegido.

## Cuándo usar esta skill

- Siempre que `web.probe` haya capturado headers de respuesta de la
  aplicación en scope — es una skill de bajo costo, alto valor, aplicable a
  prácticamente cualquier auditoría web.

## Procedimiento

1. **Content-Security-Policy — evaluar por directiva, no por presencia
   binaria:**
   - `script-src` con `'unsafe-inline'` o `'unsafe-eval'` anula la mayor
     parte de la protección contra XSS que la CSP promete — es el patrón de
     bypass más común y el primero a buscar.
   - `script-src` con un dominio wildcard demasiado amplio (`*.googleapis.com`
     cuando bastaría un subdominio específico) o, peor, `https:` sin
     restricción de host — permite cargar script desde cualquier origen HTTPS.
   - Ausencia de `object-src 'none'` — sin esta directiva, `<object>`/`<embed>`
     pueden cargar Flash/plugins que evaden las restricciones de `script-src`.
   - Ausencia de `base-uri 'self'` — sin ella, un atacante que logre inyectar
     una etiqueta `<base>` puede redirigir todas las URLs relativas de la
     página, incluyendo las de scripts con rutas relativas.
   - `report-uri`/`report-to` ausente — sin reporting, violaciones de CSP
     en producción nunca llegan al equipo del cliente; es una oportunidad de
     mejora, no un hallazgo de vulnerabilidad en sí.

2. **HSTS — verificar los tres parámetros, no solo la presencia:**
   `max-age` bajo (menos de 6 meses) reduce la ventana de protección;
   ausencia de `includeSubDomains` deja subdominios sin la protección
   incluso si el dominio principal la tiene; ausencia de `preload` es menor
   pero relevante si el cliente quiere protección desde la primera visita
   del usuario (antes de que el navegador haya visto el header alguna vez).

3. **X-Frame-Options / frame-ancestors — verificar consistencia.** Si CSP
   incluye `frame-ancestors`, ese valor tiene precedencia sobre
   `X-Frame-Options` en navegadores modernos — verificar que ambos headers
   sean consistentes (si `X-Frame-Options: DENY` pero `frame-ancestors *` en
   la CSP, el sitio es igualmente vulnerable a clickjacking, porque
   `frame-ancestors` gana).

4. **Permissions-Policy (antes Feature-Policy).** Ausencia total no es
   crítico por sí solo, pero si la aplicación maneja datos sensibles y no
   restringe explícitamente `camera`, `microphone`, `geolocation`,
   `payment` — features que la aplicación probablemente no necesita — es
   una superficie de abuso adicional en caso de XSS exitoso (un XSS que de
   otro modo sería "solo" robo de sesión puede escalar a acceso a cámara/
   micrófono si el navegador lo permite por defecto).

5. **Cross-Origin headers (COOP/COEP/CORP).** Ausencia de
   `Cross-Origin-Opener-Policy: same-origin` deja la ventana abierta a
   ataques tipo Spectre que dependen de compartir el mismo proceso de
   navegador con un origen atacante en una pestaña relacionada — relevante
   si la aplicación maneja datos de alta sensibilidad (banca, salud).

6. **Escalar severidad cuando el mismo header filtra versión EOL.**
   `Server: nginx/1.18.0` o `X-Powered-By: PHP/8.0.0` no son un hallazgo por
   sí solos (fingerprinting es esperable), pero si la versión revelada está
   fuera de soporte (EOL) **y** la página que responde recolecta
   credenciales o PII (login, checkout, formularios), la combinación sube a
   severidad **alta**: el atacante no solo sabe qué explotar, sabe dónde
   apuntarlo para máximo impacto. Tratar como dos señales que se
   multiplican, no como dos hallazgos independientes de severidad baja.

## Mapeo MITRE ATT&CK

| ID | Técnica | Táctica |
|---|---|---|
| T1189 | Drive-by Compromise | Execution |

## Salida

Persistir con `argos_memory_save`, `cwe: "CWE-1021"` (Improper
Restriction of Rendered UI Layers) para clickjacking, `CWE-693` (Protection
Mechanism Failure) para CSP con bypass. `evidence` debe citar el header
exacto capturado por `web.probe`, no una descripción genérica —
`severity: "medium"` para CSP presente pero con `unsafe-inline`, `"low"`
para ausencia de Permissions-Policy sin otra condición agravante.

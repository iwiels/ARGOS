---
name: "cms-version-and-exposure-audit"
description: "Audita WordPress/Drupal/Joomla en busca de core/plugins desactualizados con CVEs conocidas, directory listing en uploads, y xmlrpc.php expuesto — sobre lo que web.tech/web.crawl ya identifican."
domain: cybersecurity
subdomain: web-hardening
tags: ["cms", "wordpress", "directory-listing", "xmlrpc", "eol-software"]
mitre_attack: ["T1190", "T1589.002"]
nist_csf: ["ID.RA-01", "DE.CM-08"]
iso_27001: ["A.8.8"]
source_adapted_from: "web-cms-exposure-audit (adaptación local, consolidada desde Anthropic-Cybersecurity-Skills, Apache-2.0)."
---

# Skill: Exposición y vulnerabilidades en CMS

WordPress sigue siendo el CMS más frecuente en el corpus de auditorías de
Argos — y sus patrones de exposición son consistentes: versión de core
filtrada en `readme.html`, plugins con CVE pública, `xmlrpc.php` expuesto a
fuerza bruta, y directory listing en `/wp-content/uploads/`.

## Cuándo usar esta skill

- `web.tech` identificó WordPress, Drupal o Joomla como stack del target.

## Procedimiento

1. **Identificar versión de core y plugins.**
   - WordPress: `readme.html` en la raíz suele filtrar la versión exacta;
     también los query strings de versión en assets CSS/JS
     (`style.css?ver=X.X.X`) y el metatag `generator`.
   - Contrastar la versión encontrada contra el estado de soporte —
     software EOL (fin de vida) público es un hallazgo aunque no tenga CVE
     activa asociada todavía: ya no recibe parches de seguridad.
   - Plugins: mismo patrón de query string de versión; si `web.crawl`
     descubrió rutas de plugins específicos (`/wp-content/plugins/<nombre>/`),
     extraer la versión del propio directorio si es legible.

2. **Directory listing en uploads.** Probar con `web.probe` si
   `/wp-content/uploads/` (o el equivalente en Drupal/Joomla) devuelve un
   índice de archivos del servidor en vez de un 403/404 — expone el
   historial completo de archivos subidos, incluyendo documentos internos
   que se compartieron vía el CMS sin intención de publicarlos.
   Severidad **media**: fuga de documentos, no acceso al sistema.

3. **XML-RPC expuesto (WordPress).** Probar si `xmlrpc.php` responde
   200/405 aceptando el método `system.multicall` — permite amplificar
   ataques de fuerza bruta contra el login (miles de intentos de
   credenciales en una sola petición HTTP) y `pingback.ping` habilita
   XML-RPC como vector de DDoS reflejado o SSRF interno. Si el sitio no usa
   activamente XML-RPC (apps móviles, Jetpack), es seguro recomendar
   bloqueo completo.

4. **Enumeración de usuarios/autores.** `/wp-json/wp/v2/users` respondiendo
   200 con usernames y slugs de autor entrega la lista exacta de cuentas
   válidas para dirigir un ataque de fuerza bruta — correlacionar con la
   skill `rate-limiting-and-throttling` de esta biblioteca si el login
   también carece de límite de intentos: la combinación (usuarios
   enumerables + sin rate limit) es lo que hace explotable en la práctica
   un login por lo demás estándar.

## Descartar falsos positivos

Endpoints deliberadamente públicos (catálogos de productos, health checks
sin autenticación) no son hallazgo salvo que filtren metadatos de
infraestructura interna además de su función declarada.

## Mapeo MITRE ATT&CK

| ID | Técnica | Táctica |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1589.002 | Gather Victim Identity Information: Email Addresses | Reconnaissance |

## Salida

Persistir con `argos_memory_save`, `cwe: "CWE-1104"` (Use of
Unmaintained Third Party Components) para software EOL, `CWE-548`
(Exposure of Information Through Directory Listing) para uploads listables,
`CWE-307` para xmlrpc sin rate limiting. `evidence` debe citar la versión
exacta detectada y su fuente (readme.html, query string, generator tag).

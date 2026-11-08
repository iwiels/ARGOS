---
name: "exposed-cloud-credentials"
description: "Detecta credenciales cloud (AWS access keys, service account JSON de GCP, connection strings de Azure) filtradas en código fuente, repositorios públicos, respuestas HTTP o archivos de configuración expuestos."
domain: cybersecurity
subdomain: cloud-security
tags: ["cloud", "credential-exposure", "aws-access-key", "service-account", "secret-scanning", "hardcoded-secret"]
mitre_attack: ["T1552"]
nist_csf: ["PR.DS-01", "PR.AA-05"]
source_adapted_from: "detecting-aws-credential-exposure-with-trufflehog (Anthropic-Cybersecurity-Skills, Apache-2.0) — reescrita sin dependencia de TruffleHog; usa patrones de detección directamente sobre evidencia de web.crawl/web.fuzz y revisión de código."
---

# Skill: Credenciales cloud expuestas

Detecta credenciales cloud filtradas en superficie que Argos ya
recolecta: respuestas HTTP, archivos estáticos descubiertos por crawling, o
código fuente en el alcance de `security-code`. No requiere TruffleHog ni
ningún scanner externo — los patrones son reconocibles directamente.

## Cuándo usar esta skill

- `web.crawl` o `web.fuzz` descubrieron archivos de configuración expuestos
  (`.env`, `config.json`, `appsettings.json`, `.git/config`, backups).
- `security-code` está revisando un repositorio en el alcance del engagement.
- Una respuesta HTTP (error verboso, stack trace, respuesta de API mal
  configurada) incluye texto que podría contener secretos.

## Alcance y límites

Detección por patrón, no fuerza bruta ni intentos de uso de la credencial
encontrada. **Nunca** validar una credencial encontrada haciendo una llamada
real contra el proveedor cloud (eso sería uso no autorizado de una
credencial ajena, fuera del alcance de una auditoría). El hallazgo se
reporta por el patrón coincidente, no por confirmación de que la credencial
sigue activa.

## Procedimiento

1. **Reconocer los patrones de credencial cloud por formato:**
   - AWS access key: `AKIA[0-9A-Z]{16}` (ya cubierto parcialmente por
     `SECRET_PATTERNS` en el pseudonymize de Argos, pero aquí el
     objetivo es el *hallazgo de seguridad*, no la tokenización).
   - AWS secret key: cadena de 40 caracteres base64-like junto a un access
     key en el mismo contexto (`aws_secret_access_key=`).
   - GCP service account JSON: objeto con `"type": "service_account"`,
     `"private_key": "-----BEGIN PRIVATE KEY-----`.
   - Azure connection string: `DefaultEndpointsProtocol=...;AccountKey=`.
   - Firebase/GCP API key en JS del lado cliente: `AIza[0-9A-Za-z_-]{35}`
     (nota: las API keys de Firebase client-side son públicas por diseño —
     no es un hallazgo por sí solo; el hallazgo es si las reglas de
     seguridad de Firestore/RTDB detrás no exigen autenticación).

2. **Buscar en las ubicaciones de mayor probabilidad primero:** archivos
   `.env`/`.env.*` expuestos, respuestas de endpoints de debug/health-check
   verbosos, comentarios en JS bundleado sin minificar, historial de git
   expuesto (`.git/` accesible → posible secreto en commits antiguos aunque
   ya no esté en el HEAD actual).

3. **Confirmar que el patrón no es un placeholder.** Descartar valores como
   `AKIAIOSFODNN7EXAMPLE` (el ejemplo oficial de AWS en su documentación) o
   cadenas obviamente truncadas/censuradas por el propio desarrollador.

4. **Determinar el blast radius sin usar la credencial.** Si el contexto
   circundante indica el propósito (nombre de variable, comentario, nombre
   del bucket/proyecto referenciado), documentarlo — ayuda a priorizar sin
   necesidad de validar la credencial.

## Mapeo MITRE ATT&CK

| ID | Técnica | Táctica |
|---|---|---|
| T1552 | Unsecured Credentials | Credential Access |

## Salida

Persistir con `argos_memory_save`, `severity: "critical"` si es una
credencial con capacidad de escritura/administración, `cwe: "CWE-798"`
(Use of Hard-coded Credentials). **La credencial en sí nunca va en texto
plano en `evidence`** — citar solo el prefijo/patrón y la ubicación
(`vector`), consistente con cómo el resto de la plataforma trata secretos
(ver el proxy de pseudonimización). Marcar `needs_followup_by:
["security-ops"]` para que el equipo recomiende rotación inmediata al
cliente.

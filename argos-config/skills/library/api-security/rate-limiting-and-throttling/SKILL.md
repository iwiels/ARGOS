---
name: "rate-limiting-and-throttling"
description: "Detecta ausencia o bypass de rate limiting en endpoints sensibles (login, reset de contraseña, OTP) mediante variación de headers y parámetros, sobre superficie ya mapeada por web.crawl."
domain: cybersecurity
subdomain: api-security
tags: ["rate-limiting", "api", "brute-force", "otp-bypass", "throttling", "abuse"]
mitre_attack: ["T1110", "T1499"]
nist_csf: ["PR.AA-03"]
source_adapted_from: "detecting-api-enumeration-attacks (Anthropic-Cybersecurity-Skills, Apache-2.0) — reescrita con foco en identificar ausencia/bypass del control, no solo detectar el patrón de abuso ya en curso."
---

# Skill: Ausencia o bypass de rate limiting

La falta de rate limiting es lo que convierte una debilidad menor (un OTP de
6 dígitos, una política de contraseña débil) en una vulnerabilidad
explotable en la práctica. Esta skill se enfoca en **confirmar la ausencia
del control**, no en ejecutar el ataque de fuerza bruta completo.

## Cuándo usar esta skill

- Endpoints identificados por `web.crawl` que corresponden a: login, reset
  de contraseña, verificación de OTP/2FA, creación de cuenta, aplicación de
  cupones/promociones, o cualquier endpoint con un valor de baja entropía
  que un atacante podría intentar adivinar.

## Alcance y límites

El objetivo es **confirmar la ausencia del control con el mínimo de
peticiones necesarias** (decenas, no miles) — no ejecutar un ataque de
fuerza bruta real contra credenciales de producción. Detenerse en cuanto se
confirma el patrón (ausencia de bloqueo tras N intentos, o bypass
confirmado), no continuar hasta comprometer una cuenta real.

## Procedimiento

1. **Establecer la línea base.** Enviar 10-15 peticiones consecutivas con
   credenciales/OTP inválidos al endpoint objetivo, midiendo tiempo de
   respuesta y código de estado. Si todas devuelven la misma respuesta sin
   incremento de latencia, captcha, ni bloqueo temporal, es indicio de
   ausencia de rate limiting.

2. **Probar bypass por variación de headers.** Si el endpoint sí limita por
   IP, probar rotación de `X-Forwarded-For`, `X-Real-IP`, `X-Client-IP` con
   valores distintos en cada petición — muchas implementaciones confían
   ciegamente en headers controlables por el cliente para identificar el
   origen, en vez de la IP real de conexión.

3. **Probar bypass por variación de sesión/cookie.** Si el límite es por
   sesión en vez de por IP, una nueva sesión (nueva cookie, sin
   autenticar) por cada intento evade el contador — confirmar si el
   servidor emite una cookie de sesión nueva sin fricción antes del login.

4. **Probar bypass por variación del payload no relevante.** Añadir un
   parámetro extra sin efecto funcional (`&debug=1`, un espacio al final del
   valor, mayúsculas/minúsculas distintas en el email) — algunas
   implementaciones de rate limiting usan el payload completo como clave de
   caché en vez de normalizar el identificador relevante (usuario/IP),
   rompiendo el conteo con variaciones triviales.

5. **Verificar si existe CAPTCHA y si es evadible.** Si aparece tras N
   intentos, confirmar que se aplica server-side (no solo oculto en el
   frontend) — probar la petición directa al endpoint sin pasar por el
   formulario que renderiza el CAPTCHA.

## Mapeo MITRE ATT&CK

| ID | Técnica | Táctica |
|---|---|---|
| T1110 | Brute Force | Credential Access |
| T1499 | Endpoint Denial of Service | Impact |

## Salida

Persistir con `argos_memory_save`, `cwe: "CWE-307"` (Improper
Restriction of Excessive Authentication Attempts) o `CWE-799` (Improper
Control of Interaction Frequency) según aplique. `evidence` debe incluir el
número de peticiones enviadas y la ausencia de degradación/bloqueo
observada — nunca reportar credenciales/OTP reales probados, solo el
patrón de comportamiento del servidor.

---
name: "jwt-implementation-weaknesses"
description: "Audita la implementación de JWT de una API (algoritmo, validación de firma, claims obligatorios) buscando alg=none, secretos débiles, y validación de expiración/audiencia ausente."
domain: cybersecurity
subdomain: api-security
tags: ["jwt", "api", "authentication", "alg-none", "weak-secret", "broken-authentication"]
mitre_attack: ["T1078", "T1552"]
nist_csf: ["PR.AA-01"]
source_adapted_from: "attacking-oauth-with-device-code-phishing / detecting-suspicious-oauth-application-consent (Anthropic-Cybersecurity-Skills, Apache-2.0) — acotada específicamente a debilidades de implementación JWT, complementaria a las skills de OAuth citadas."
---

# Skill: Debilidades de implementación JWT

El JWT en sí (el formato) rara vez es el problema — casi siempre es la
**implementación de validación** en el servidor. Esta skill enumera las
formas de romperla que aparecen con más frecuencia en auditorías de API.

## Cuándo usar esta skill

- La API en scope usa JWT como mecanismo de autenticación (identificable
  por el header `Authorization: Bearer eyJ...` o cookies con formato JWT).

## Procedimiento

1. **Decodificar el header y payload** (base64url, sin necesidad de la
   clave — el header y payload no están cifrados, solo firmados). Revisar:
   - `alg`: si es `none`, el servidor podría estar aceptando tokens sin
     firma. Confirmarlo enviando un token con `alg: none` y firma vacía —
     si el servidor lo acepta, es hallazgo crítico inmediato.
   - `alg: HS256` cuando el servidor originalmente firma con `RS256`: si el
     servidor no valida que el algoritmo recibido coincide con el esperado,
     puede ser vulnerable a confusión de algoritmo (firmar con la clave
     pública RSA como si fuera un secreto HMAC — requiere conocer/obtener
     la clave pública, que suele ser accesible en `/.well-known/jwks.json`).

2. **Probar secretos HMAC débiles/por defecto** si el algoritmo es
   `HS256`/`HS384`/`HS512`. Diccionario acotado de valores comunes
   (`secret`, `changeme`, el nombre de la app, valores de ejemplo de
   frameworks conocidos) contra la firma del token — sin fuerza bruta
   extensiva no autorizada, solo verificación de los patrones más obvios.

3. **Verificar validación de claims obligatorios en el servidor**, no en el
   token:
   - `exp` ausente o no validado: un token viejo capturado (log, proxy,
     historial) sigue siendo válido indefinidamente. Probar con un token
     expirado (esperar o modificar el `exp` si se controla la emisión en un
     entorno de prueba) contra un endpoint protegido.
   - `aud`/`iss` no validados: un token emitido para otro servicio/tenant
     del mismo proveedor de identidad podría ser aceptado — relevante en
     arquitecturas multi-tenant o con IdP compartido (Auth0, Cognito).

4. **Revisar dónde se almacena el token del lado cliente.** `localStorage`
   es vulnerable a robo vía XSS (no aislado por `httpOnly`); una cookie sin
   `httpOnly`/`Secure`/`SameSite` tiene el mismo problema. No es un fallo
   del JWT en sí, pero es parte de la superficie de la implementación
   completa y vale la pena documentarlo junto al resto.

5. **Revisar mecanismo de revocación.** Si la API no tiene lista de
   revocación (blocklist) ni tokens de vida corta con refresh, un token
   robado permanece válido hasta su `exp` natural sin forma de invalidarlo
   — documentar como hallazgo de diseño si el `exp` configurado es largo
   (días/semanas) para tokens de acceso.

## Mapeo MITRE ATT&CK

| ID | Técnica | Táctica |
|---|---|---|
| T1078 | Valid Accounts | Initial Access, Persistence, Privilege Escalation |
| T1552 | Unsecured Credentials | Credential Access |

## Salida

Persistir con `argos_memory_save`, `cwe: "CWE-347"` (Improper
Verification of Cryptographic Signature) para `alg: none`/confusión de
algoritmo/secreto débil, `CWE-613` (Insufficient Session Expiration) para
`exp` no validado. `evidence` debe incluir el token decodificado (header +
payload, nunca la firma completa de un token de sesión real ajena) y la
prueba realizada.

---
name: "broken-object-level-authorization"
description: "Detecta BOLA/IDOR en endpoints REST y GraphQL — cuando un usuario autenticado puede acceder a objetos de otro usuario cambiando un identificador — a partir de las rutas descubiertas por web.crawl/web.fuzz."
domain: cybersecurity
subdomain: api-security
tags: ["api", "bola", "idor", "broken-authorization", "rest", "graphql", "owasp-api-1"]
mitre_attack: ["T1078"]
nist_csf: ["PR.AA-05"]
source_adapted_from: "detecting-broken-object-property-level-authorization / conducting-api-security-testing (Anthropic-Cybersecurity-Skills, Apache-2.0) — enfocada en el patrón de detección más frecuente (BOLA clásico), coordinable con web.probe."
---

# Skill: Broken Object Level Authorization (BOLA / IDOR)

BOLA es la vulnerabilidad #1 en el OWASP API Security Top 10, y la más
frecuente en auditorías reales de APIs REST y GraphQL. El patrón es simple
pero fácil de pasar por alto en un crawling automático: **el endpoint
responde 200, pero con datos que no le corresponden al usuario autenticado.**

## Cuándo usar esta skill

- `web.crawl`/`web.urls` descubrieron endpoints con un identificador
  numérico o UUID en la ruta o en el body (`/api/users/123`,
  `/api/orders/{id}/invoice`, `?user_id=456`).
- El engagement incluye credenciales de al menos una cuenta de prueba
  autenticada (requisito para esta skill — sin sesión válida no se puede
  probar autorización).

## Alcance y límites

Requiere una sesión autenticada legítima entregada por el cliente para la
cuenta de prueba. No se debe intentar crear cuentas ni escalar privilegios
por fuera del alcance autorizado del engagement.

## Procedimiento

1. **Inventariar endpoints con identificador de objeto.** De la lista de
   rutas de `web.urls`/`web.crawl`, filtrar las que contienen un ID
   (numérico secuencial, UUID, o slug) que referencia un recurso
   perteneciente a un usuario: perfiles, pedidos, documentos, mensajes,
   facturas.

2. **Establecer la línea base.** Con la sesión de prueba autenticada,
   solicitar un objeto que le pertenece a esa cuenta y confirmar 200 con
   datos correctos.

3. **Sustituir el identificador.** Repetir la misma petición cambiando
   únicamente el ID por uno adyacente (`123` → `124`) o por uno conocido de
   otra cuenta (si el engagement provee dos cuentas de prueba, mejor aún:
   usar el ID real de la cuenta B mientras se está autenticado como cuenta
   A). Un 200 con datos de otro usuario es el hallazgo confirmado — no hace
   falta más prueba que esa.

4. **Distinguir de IDs no enumerables.** Si el identificador es un UUID v4
   aleatorio (no secuencial, no adivinable), el riesgo de explotación
   práctica es menor — pero si el propio endpoint filtra o lista objetos
   (`/api/orders?limit=100`), los IDs quedan expuestos de todas formas y el
   hallazgo sigue aplicando.

5. **Probar variantes de método HTTP y verbos GraphQL.** BOLA no es
   exclusivo de `GET`: un `PUT`/`DELETE`/`PATCH` sobre el objeto de otro
   usuario (modificar o borrar, no solo leer) es un hallazgo de severidad
   mayor. En GraphQL, revisar mutations que acepten un `id` sin validar
   ownership del campo resuelto.

6. **Revisar BOPLA (nivel de propiedad, no solo de objeto).** Un endpoint
   puede autorizar correctamente el objeto pero exponer campos que no
   debería (p. ej. `/api/users/me` devuelve el objeto propio, pero incluye
   `role` o `is_admin` que el cliente puede modificar en un `PATCH` sin
   validación server-side — mass assignment).

## Mapeo MITRE ATT&CK

| ID | Técnica | Táctica |
|---|---|---|
| T1078 | Valid Accounts | Initial Access, Persistence, Privilege Escalation, Defense Evasion, Lateral Movement |

## Salida

Persistir con `argos_memory_save`, `cwe: "CWE-639"` (Authorization
Bypass Through User-Controlled Key). `evidence` debe incluir la petición
exacta (método, ruta, ID sustituido) y confirmar en el `httpRequest`/
`httpResponse` que la respuesta contiene datos de un objeto ajeno.
`severity: "critical"` si permite escritura/borrado sobre el objeto ajeno,
`"high"` si es solo lectura de datos sensibles.

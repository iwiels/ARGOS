---
name: "graphql-introspection-exposure"
description: "Detecta introspección de GraphQL habilitada en producción, y prueba consultas anidadas/batching como vector de denegación de servicio, a partir de endpoints descubiertos por web.crawl."
domain: cybersecurity
subdomain: api-security
tags: ["graphql", "api", "introspection", "batching", "query-depth", "dos", "information-disclosure"]
mitre_attack: ["T1590", "T1499"]
nist_csf: ["PR.PS-04"]
source_adapted_from: "conducting-api-security-testing (Anthropic-Cybersecurity-Skills, Apache-2.0) — sección de GraphQL extraída y ampliada como skill independiente."
---

# Skill: Exposición de introspección GraphQL

GraphQL introduce dos clases de riesgo que no existen en REST tradicional:
introspección (el esquema completo, autodocumentado, disponible para
cualquiera) y consultas anidadas (el cliente decide la forma de la query, lo
que abre una superficie de DoS por complejidad).

## Cuándo usar esta skill

- `web.crawl`/`web.tech` identificó un endpoint GraphQL (típicamente
  `/graphql`, `/api/graphql`, o una respuesta que acepta `{"query": "..."}`
  con content-type `application/json`).

## Procedimiento

1. **Probar introspección con una query estándar** (`__schema { types {
   name } }` o el query de introspección completo). Si el servidor responde
   con el esquema completo, es hallazgo — en producción la introspección
   debería estar deshabilitada; expone nombres de campos, mutations y tipos
   internos que facilitan enumeración de superficie de ataque (incluyendo
   mutations administrativas que de otro modo serían difíciles de adivinar).

2. **Enumerar mutations sensibles del esquema expuesto.** Buscar
   específicamente mutations con nombres como `deleteUser`, `updateRole`,
   `impersonate`, `resetPassword`, `createApiKey` — su sola existencia en el
   esquema no es un hallazgo de autorización por sí sola, pero orienta qué
   probar después con `broken-object-level-authorization`.

3. **Probar profundidad de consulta anidada.** Sin límite de profundidad
   (`queryDepth`), una query con campos que se referencian circularmente
   (`user { posts { author { posts { author { ... } } } } }`) puede generar
   una carga de cómputo exponencial en el servidor con una sola petición
   pequeña — probar con 8-10 niveles de anidamiento y observar tiempo de
   respuesta/errores 5xx.

4. **Probar aliasing y batching abusivo.** GraphQL permite repetir el mismo
   campo con alias distintos en una sola petición (`a: expensiveField, b:
   expensiveField, c: expensiveField...`) — sin límite de complejidad, cien
   alias de un campo costoso equivalen a cien llamadas en una sola petición
   HTTP, evadiendo rate-limiting basado en conteo de requests.

5. **Revisar mensajes de error verbosos.** Errores de GraphQL que incluyen
   stack traces, nombres de resolvers internos, o detalles de la base de
   datos subyacente (mensajes de SQL/ORM) filtran información de
   implementación — más frecuente en GraphQL que en REST porque el motor de
   ejecución suele exponer el error de resolución completo por defecto en
   modo desarrollo, y a veces ese modo queda activo en producción.

## Mapeo MITRE ATT&CK

| ID | Técnica | Táctica |
|---|---|---|
| T1590 | Gather Victim Network Information | Reconnaissance |
| T1499 | Endpoint Denial of Service | Impact |

## Salida

Persistir con `argos_memory_save`. Introspección expuesta:
`cwe: "CWE-200"`, `severity: "medium"` (información, no acceso directo)
salvo que el esquema revele mutations administrativas sin protección
aparente. Query anidada/batching como DoS: `cwe: "CWE-400"` (Uncontrolled
Resource Consumption), documentar el tiempo de respuesta observado en
`evidence` como prueba.

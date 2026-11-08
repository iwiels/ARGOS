---
name: "api-surface-discovery"
description: "Identifica la superficie de API real (REST/GraphQL) a partir de rutas y documentación descubiertas por web.crawl, y aplica disciplina de falsos positivos antes de escalar a las skills de BOLA/JWT/GraphQL/rate-limiting."
domain: cybersecurity
subdomain: api-security
tags: ["api", "surface-discovery", "openapi", "swagger", "false-positive-discipline"]
mitre_attack: ["T1595"]
nist_csf: ["ID.RA-01"]
iso_27001: ["A.8.2", "A.8.24"]
source_adapted_from: "api-security-audit (adaptación local, consolidada desde Anthropic-Cybersecurity-Skills, Apache-2.0) — reducida a su parte de descubrimiento de superficie y disciplina de falsos positivos; el resto de su contenido (BOLA, JWT, rate-limiting) ya está cubierto con mayor profundidad por las otras skills de api-security/ en esta biblioteca."
---

# Skill: Descubrimiento de superficie de API

Paso previo a `broken-object-level-authorization`,
`jwt-implementation-weaknesses`, `graphql-introspection-exposure` y
`rate-limiting-and-throttling` — sin mapear la superficie real primero, esas
skills no tienen dónde aplicarse.

## Cuándo usar esta skill

- Al inicio de la fase de análisis de una API, antes de las skills de
  vulnerabilidad específica.

## Procedimiento

1. **Buscar rutas y documentos de descubrimiento estándar** en la salida de
   `web.crawl`/`web.urls`: `/api/`, `/api/v1/`, `/wp-json/`, `/graphql`,
   `/swagger.json`, `/openapi.json`, `/api-docs`, `.well-known/openapi.json`.
   Un `swagger.json`/`openapi.json` accesible es en sí mismo el mapa
   completo de la superficie — priorizar su hallazgo sobre la enumeración
   manual de rutas.

2. **Si hay documento OpenAPI/Swagger accesible**, extraer de él: todos los
   endpoints declarados, qué autenticación requiere cada uno (campo
   `security` por operación), y qué parámetros de path/query referencian
   identificadores de objeto — esa lista es el input directo para
   `broken-object-level-authorization`.

3. **Si no hay documento de descubrimiento**, inferir la superficie de las
   rutas capturadas por `web.crawl` que sigan convenciones REST (verbo +
   recurso + posible ID: `GET /api/orders/123`) o del tráfico JS bundleado
   (llamadas `fetch`/`axios` hardcodeadas a rutas de API, visibles en el
   JS no minificado si `web.crawl` lo descargó).

4. **Aplicar disciplina de falsos positivos antes de reportar cualquier
   cosa como hallazgo de exposición de superficie:** un endpoint
   deliberadamente público (catálogo de productos, health check, endpoint
   de autocompletado de búsqueda) **no es una vulnerabilidad** por estar
   accesible sin autenticación — solo lo es si además filtra metadatos de
   infraestructura interna (stack traces, versiones de dependencias,
   rutas del sistema de archivos) que exceden su función declarada. Esta
   distinción es la que evita reportes inflados con "hallazgos" que el
   cliente va a rechazar en la revisión.

5. **Clasificar cada endpoint descubierto por su necesidad de las skills
   siguientes**: ¿acepta un identificador de objeto? → candidato a BOLA.
   ¿Usa JWT? → candidato a la skill de JWT. ¿Es GraphQL? → candidato a
   introspección/batching. ¿Es de autenticación/alto volumen? → candidato
   a rate-limiting.

## Mapeo MITRE ATT&CK

| ID | Técnica | Táctica |
|---|---|---|
| T1595 | Active Scanning | Reconnaissance |

## Salida

No genera hallazgos de vulnerabilidad por sí sola (salvo exposición de
documentación con metadatos internos) — su salida es el inventario de
superficie que alimenta las skills de `api-security/` siguientes. Si el
documento OpenAPI/Swagger en sí está expuesto sin que debería estarlo
(entorno de producción sin necesidad de documentación pública), eso sí es
hallazgo: `cwe: "CWE-200"`, severidad baja/media según qué tan sensibles
sean los endpoints documentados.

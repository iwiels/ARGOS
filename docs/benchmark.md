# Argos Security Benchmark Harness

Harness de benchmark público, determinista y reproducible para evaluar la precisión y cobertura del motor de pentesting automatizado de Argos contra un ground truth controlado (`practicetarget`).

## 1. Visión General

El benchmark ejecuta una auditoría de seguridad automatizada contra una instancia efímera de `practicetarget` y contrasta los hallazgos reportados frente a un catálogo estricto de vulnerabilidades conocidas (**Ground Truth**).

Métricas evaluadas:
- **Recall**: Porcentaje de vulnerabilidades reales del ground truth descubiertas.
  $$\text{Recall} = \frac{\text{Vulnerabilidades Detectadas (TP)}}{\text{Total Vulnerabilidades en Ground Truth}} \times 100$$
- **Precision**: Porcentaje de hallazgos reportados que corresponden a vulnerabilidades reales.
  $$\text{Precision} = \frac{\text{True Positives}}{\text{True Positives} + \text{False Positives}} \times 100$$
- **False Positive Rate (FPR)**: Tasa de falsas alarmas sobre el total de hallazgos evaluados.
  $$\text{FPR} = \frac{\text{False Positives}}{\text{True Positives} + \text{False Positives}} \times 100$$
- **Duración y Throughput**: Tiempo total de ejecución en segundos para completar el ciclo de auditoría.

---

## 2. Catálogo de Ground Truth (`practicetarget`)

El entorno de pruebas `practicetarget` expone **44 vectores de prueba** con comportamiento deliberadamente vulnerable. La columna *Tool esperada* declara qué tool de Argos debería detectarlo; los marcados *(sin tool)* son vectores que **ninguna tool cubre hoy** — se declaran como `unsupported` en el código, y eso es en sí mismo un dato sobre la cobertura real del producto:

| ID | Categoría | Vector / Ruta | Descripción | Severidad | Tool esperada |
|---|---|---|---|---|---|
| GT-SQLI-01 | SQL Injection | /search?q=1 | SQLi en parámetro GET q (blind booleano y marcador de sintaxis SQL en error 500) | Critical | web.sqli |
| GT-SQLI-02 | SQL Injection | /item?id=1 | SQLi numérico en parámetro GET id con diferencial booleano | Critical | web.sqli |
| GT-XSS-01 | Cross-Site Scripting | /profile?user=admin | Reflected XSS en parámetro GET user sin sanitización | Medium | web.xss |
| GT-LEAK-ENV | Sensitive Exposure | /.env | Exposición de archivo de configuración con credenciales simuladas | High | web.fuzz |
| GT-LEAK-BACKUP | Sensitive Exposure | /backup.zip | Exposición de copia de seguridad comprimida | High | web.fuzz |
| GT-ROBOTS | Recon / Information Leak | /robots.txt | Exposición de rutas administrativas ocultas (Disallow: /admin/) | Low | *(sin tool)* |
| GT-HEADER-CSP | Security Headers | / | Ausencia de cabecera Content-Security-Policy | Low | web.scan |
| GT-HEADER-HSTS | Security Headers | / | Ausencia de cabecera Strict-Transport-Security | Low | web.scan |
| GT-HEADER-XFO | Security Headers | / | Ausencia de cabecera X-Frame-Options (clickjacking) | Low | web.scan |
| GT-IDOR-01 | IDOR / BOLA | /api/item/{id} | El registro de cualquier usuario se devuelve sin comprobar la sesión | Critical | *(sin tool)* |
| GT-CSRF-01 | CSRF | /login | El formulario de login no tiene token anti-CSRF | High | web.csrf |
| GT-CSRF-02 | CSRF | /api/transfer | Endpoint state-changing sin token ni validación de Origin | High | *(sin tool)* |
| GT-JWT-01 | JWT | /api/token | JWT firmado con lg:none (la firma nunca se verifica) | Critical | web.jwt |
| GT-JWT-02 | JWT | /api/token | JWT sin claim exp: el token nunca expira | Medium | web.jwt |
| GT-JWT-03 | JWT | /api/token | JWT sin claim ud: la audiencia no se puede validar | Medium | web.jwt |
| GT-JWT-04 | JWT | /api/token | JWT con claim de privilegio mutable: el rol lo controla el cliente | High | web.jwt |
| GT-JWT-05 | JWT | /api/token | JWT sin claim iss: el emisor no se puede validar | Low | web.jwt |
| GT-SSRF-01 | SSRF | /fetch?url= | SSRF blind: el servidor busca la URL y filtra el fallo interno | High | web.ssrf |
| GT-XXE-01 | XXE | /api/xml | El parser XML resuelve entidades externas y lee ficheros locales | High | *(sin tool)* |
| GT-SSTI-01 | SSTI | /render?tpl= | La plantilla evalúa la expresión de la petición | Critical | web.ssti |
| GT-OPENREDIR-01 | Open Redirect | /redirect?u= | Se acepta cualquier destino | Medium | *(sin tool)* |
| GT-PATHTRAV-01 | Path Traversal | /download?file= | El nombre del fichero escapa del directorio base | High | *(sin tool)* |
| GT-CMDI-01 | Command Injection | /ping?host= | El host se concatena en un comando de shell | Critical | *(sin tool)* |
| GT-DESER-01 | Deserialización | /api/deserialize | El gadget del payload llega a la shell | Critical | *(sin tool)* |
| GT-GQL-01 | GraphQL | /graphql | La introspección está habilitada: el schema completo es legible | Medium | web.graphql |
| GT-GQL-02 | GraphQL | /graphql | El schema expone campos sensibles (la contraseña del usuario) | Medium | web.graphql |
| GT-GQL-03 | GraphQL | /graphql | Las mutations state-changing no tienen regla de autorización | Medium | web.graphql |
| GT-GQL-04 | GraphQL | /graphql | Sin límite de profundidad: se acepta una query anidada | Medium | web.graphql |
| GT-GQL-05 | GraphQL | /graphql | Se procesan operaciones en batch: una petición se amplifica | Medium | web.graphql |
| GT-SMUGGLE-01 | Smuggling | / (front proxy) | HTTP request smuggling: el front acepta un framing ambiguo (CL+TE) | High | web.smuggle |
| GT-RACE-01 | Race Condition | /api/coupon | Un cupón de un solo uso se redime dos veces en concurrencia | Medium | *(sin tool)* |
| GT-USERENUM-01 | User Enumeration | /api/login | El tiempo de respuesta revela si la cuenta existe | Medium | *(sin tool)* |
| GT-RATELIMIT-01 | Auth | /api/login | Sin rate limit: el login nunca estrangula | Medium | *(sin tool)* |
| GT-GIT-01 | Exposure | /.git/ | El repositorio git está expuesto | High | web.fuzz |
| GT-GIT-02 | Exposure | /.git/config | Un token de acceso personal viaja en la URL del remote | High | web.artifact |
| GT-CORS-01 | CORS | /api/cors | CORS permisivo: cualquier origen con credenciales | High | web.csrf |
| GT-COOKIE-01 | Misconfiguration | /login | La cookie de sesión viaja sin Secure, HttpOnly ni SameSite | Medium | *(sin tool)* |
| GT-VERB-01 | Misconfiguration | /api/data | Verb tampering: el endpoint responde a los verbos state-changing | Low | *(sin tool)* |
| GT-DEBUGVARS-01 | Exposure | /debug/vars | El endpoint de debug expone la configuración y sus secretos | Medium | web.artifact |
| GT-SECTXT-01 | Recon | /security.txt | Falta security.txt: no existe canal de contacto | Info | *(sin tool)* |
| GT-SUBDOMAIN-01 | Recon | dev.payments.acme-corp.local | Subdomain takeover: el vhost responde desde un bucket borrado | High | *(sin tool)* |
| GT-CACHE-01 | Misconfiguration | /api/cache | Cache poisoning: una cache compartida sirve respuestas sin Vary | Medium | *(sin tool)* |
| GT-UNICODE-01 | Misconfiguration | /unicode/ | Unicode smuggling: la forma de ancho completo de una ruta bloqueada colada | Medium | *(sin tool)* |
| GT-SECRETJS-01 | Exposure | /static/app.js | La API key del backend viaja en el bundle JavaScript | High | web.artifact |

**Composición del ground truth (lectura correcta de las métricas)**: de los 44 vectores, **3 son "missing security header"** con severidad `Low` y se resuelven sobre la misma ruta `/`; **17 no son medibles por ninguna tool de Argos hoy** (marcados *sin tool*) y **9 requieren los escáneres de terceros** (nuclei, sqlmap, dalfox), por lo que solo el modo full los mide. Las métricas de Recall y Precision **no están ponderadas por severidad**: detectar los tres headers ausentes suma 3 al Recall con muy poco esfuerzo. Por eso el harness reporta **dos recalls**: `recall_percent` sobre los vectores que el modo ejecutado puede medir, y `overall_recall_percent` sobre el catálogo completo. El segundo es el número honesto y es deliberadamente bajo mientras existan vectores sin tool.

---

## 3. Instrucciones de Reproducción

### Requisitos Previos
- **Go 1.24+**
- Conexión a Internet si se descargan binarios de GitHub Releases en la primera ejecución (o caché local en `ARGOS_E2E_TOOLS_DIR`).

### Ejecución en Modo Rápido (Light Mode)
El modo `ARGOS_E2E_LIGHT=1` ejecuta las fases de reconocimiento, sondeo de cabeceras, crawling, fuzzing y confirmación booleana de SQLi sin requerir dependencias pesadas:

```bash
cd argos-bin
ARGOS_E2E=1 ARGOS_E2E_LIGHT=1 go test -v -run TestWebBenchmark ./e2e
```

En Windows PowerShell:
```powershell
$env:ARGOS_E2E="1"
$env:ARGOS_E2E_LIGHT="1"
cd argos-bin
go test -v -run TestWebBenchmark ./e2e
```

### Ejecución Completa (Full Mode)
Incluye validación activa de XSS con Dalfox y escaneo de plantillas Nuclei:

```powershell
$env:ARGOS_E2E="1"
$env:ARGOS_E2E_LIGHT="0"
cd argos-bin
go test -v -run TestWebBenchmark ./e2e -timeout 25m
```

---

## 4. Artefactos de Salida

Tras la ejecución, el benchmark genera automáticamente dos archivos:
1. `benchmark-report.json`: Métricas estructuradas en formato JSON aptas para pipelines de CI/CD.
2. `benchmark-report.md`: Resumen ejecutivo en Markdown con tabla de resultados por cada vector.

---

## 5. Especificaciones de Hardware de Referencia

Para comparaciones de throughput y tiempos de ejecución reproducibles:
- **CPU**: AMD Ryzen / Intel Core i7 8+ cores (3.5 GHz+)
- **RAM**: 16 GB DDR4/DDR5
- **OS**: Windows 11 / Ubuntu 22.04 LTS / macOS Sonoma (Apple Silicon)
- **Disco**: NVMe SSD (mínimo 500 MB libres para caché de herramientas)

---

---

## 7. Resultados

Ejecutado en modo light (sin descarga de binarios de terceros) contra una instancia efímera de `practicetarget`. Artefactos: `argos-bin/e2e/benchmark-report.json` y `benchmark-report.md`.

### Tres runners, un mismo ground truth

| Runner | Qué mide | Findings | TP | FP | Recall (medible) | Recall (global) | Precision |
|---|---|---|---|---|---|---|---|
| `argos_full` | Las tools de Argos con el contrato canónico y el dedup por taxonomía | **18** | 18 | 0 | **100%** | 40.9% | 100% |
| `argos_no_agents` | Las mismas tools **sin** el contrato canónico: sólo sobreviven el título y la URL | **28** | 28 | 0 | 100% | 40.9% | 100% |
| `raw_tools` | Los escáneres de terceros (nuclei, dalfox) sin Argos en el camino | — | — | — | — | — | — |

**La diferencia entre las dos primeras filas es el argumento del producto en números**: las mismas detecciones producen **28 filas** sin el contrato canónico y **18** con él. Los 10 findings sobrantes son el mismo bug reportado con títulos distintos — la deduplicación por taxonomía `(cwe, target, vector)` los colapsa. Sin ese contrato, el panel de un engagement cuenta el mismo bug tantas veces como tools lo detectaron.

`raw_tools` aparece como `measured: false` con el motivo explícito (`nuclei: not installed; dalfox: not installed`) cuando los binarios de terceros no están disponibles. **No se rellena con ceros ni se estima**: la comparación con las tools crudas es la que hay que resolver en el modo `full` con red.

### Gate de regresión

El job `benchmark` de CI corre el modo light y compara contra `argos-bin/e2e/baseline.json` (Recall 100% sobre los vectores medibles, Precision 100%, tolerancias 5% y 2%). El gate actual: `checked: true, passed: true`.

### Lo que el Recall global de 40.9% significa

De los 44 vectores del catálogo, **18** son medibles por una tool de Argos en modo light, **9** requieren los escáneres de terceros (modo full) y **17** no son detectables por ninguna tool de Argos hoy (marcados `unsupported`: IDOR, XXE, command injection, deserialización, path traversal, open redirect, race condition, user enumeration, rate limit, cookies sin flags, verb tampering, cache poisoning, unicode smuggling, subdomain takeover, `security.txt` y CSRF en endpoint state-changing).

Ese 40.9% es el número honesto del producto: **la cobertura real de las tools de Argos sobre el catálogo completo**. Los 17 vectores sin cobertura son la lista de trabajo del roadmap de detección, y están escritos en el código, no escondidos en un footnote.

## 6. Alcance del Benchmark: Qué Mide y Qué NO Mide Hoy

Esta sección existe para que nadie cite las métricas del harness como si fueran una garantía de cobertura o de calidad.

### Qué mide hoy

- **Tasa de detección sobre un ground truth fijo de 44 vectores**, contra una instancia efímera de `practicetarget` (`argos-bin/internal/practicetarget`). Cada vector declara la tool que debería detectarlo; los que ninguna tool cubre hoy están marcados como `unsupported` y eso es en sí mismo un dato sobre la cobertura real de Argos.
- **Precision y FPR** sobre los hallazgos que el harness contrasta contra el ground truth.
- **Duración y throughput** del ciclo completo de auditoría.
- **Reproducibilidad**: mismo target, mismo código y mismas versiones de herramientas → mismas métricas. Los artefactos (`benchmark-report.json`, `benchmark-report.md`) quedan en el directorio de trabajo.

### Qué NO mide hoy

- **Sí hay línea base comparativa y gate de regresión.** El harness mide **tres runners** sobre el mismo ground truth — Argos completo, las tools de terceros en crudo (nuclei/sqlmap/dalfox sueltos) y Argos sin la capa de agentes — y guarda una referencia versionada en `argos-bin/e2e/baseline.json`. El pipeline (`.github/workflows/ci.yml`, job `benchmark`) corre el modo light y **falla el merge** si el Recall o la Precision caen por debajo del baseline (tolerancias: 5% y 2%). La referencia se actualiza **solo** con una justificación explícita en el PR. La línea base actual (`mode: light`): Recall 100% sobre los 18 vectores que el modo light puede medir, 40.9% sobre el catálogo completo de 44, Precision 100%. El Recall global es bajo **a propósito y está declarado**: 9 vectores requieren los escáners de terceros y 17 no son medibles por ninguna tool de Argos hoy.
- **El gate de CI es real pero acotado.** `TestWebBenchmark` hace `t.Skip` salvo que se exporte `ARGOS_E2E=1`; el job `benchmark` de CI lo corre explícitamente en **modo light** (no descarga binarios pesados). El job falla si Recall o Precision caen bajo la tolerancia del baseline.
- **No mide el workflow multi-agente.** El harness ejercita el binario `argos-web` en modo MCP. No evalúa la derivación de compliance, la validación XBOW, el re-test, la puntuación CVSS, la reconciliación de reportes ni la síntesis multi-agente: son capas que el benchmark no toca.
- **No mide explotabilidad.** Detectar la ausencia de una cabecera no es lo mismo que demostrar que una cabecera ausente es explotable en ese target. Los vectores de baja severidad inflan el Recall respecto de la cobertura real de vulnerabilidades explotables.
- **No mide cobertura de superficie.** El target es un único servidor local con 44 vectores conocidos. No hay evaluación de crawling profundo, autenticación, SPAs, APIs, subdominios ni activos post-explotación.
- **No mide estabilidad temporal.** Las métricas dependen del entorno (descarga de binarios, red, caché local de herramientas) y de la variabilidad de los detectores de terceros; no hay repetibilidad estadística ni control de la varianza.

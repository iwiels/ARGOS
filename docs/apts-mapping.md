# Argos Self-Assessment Against OWASP APTS 2026

Mapeo de arquitectura y controles de Argos contra el estándar **OWASP Autonomous Penetration Testing Standard (APTS)** (abril 2026).

---

## 1. Introducción y Propósito

El estándar OWASP APTS establece los requisitos formales de seguridad, gobernanza, seguridad operativa y contención para agentes y plataformas de ciberseguridad autónomas y semi-autónomas.

Este documento mapea los controles de Argos contra los 8 dominios fundamentales del estándar. Es una **auto-evaluación**, no una certificación: cada dominio declara qué implementa el código hoy y qué no, y los límites se enuncian con el mismo detalle que las capacidades.

---

## 2. Los 8 Dominios de Seguridad OWASP APTS

### Dominio 1: Scope Enforcement (Delimitación Estricta de Alcance)
- **Implementación**: `argos-bin/internal/scope/scope.go` (`ScopeGuard`), invocado desde `argos-bin/cmd/web/tools/validate.go` (pre-flight de las herramientas `web.*`) y `argos-bin/cmd/lan/tools/policy.go` (herramientas `lan.*`); en el backend TypeScript, `packages/core/src/security/scope-service.ts` + `scope-eval.ts`.
- **Mecanismo implementado**:
  - Validación determinista del target **antes** de emitir la petición: FQDN exacto, comodines de dominio (`*.example.com`), bloques CIDR y lista de exclusión (`excluded_hosts`). La resolución DNS se cachea 60 s para no re-resolver en cada petición.
  - **IP pinning**: la resolución DNS se valida una vez y el diálogo se abre contra la IP ya autorizada, lo que cierra el TOCTOU y el DNS rebinding.
  - Las herramientas HTTP nativas y el pre-flight de `web.scan` usan el cliente atado al guard (`Env.Client()` → `ScopeGuard.Client()`), con pinning, rate limit y audit log encadenado. El proceso externo Nuclei no comparte ese cliente, por lo que su tráfico durante las fases no recibe esas mismas garantías; véase Dominio 2.
  - Limitador de tasa por token bucket (`max_rps`); en modo `safe_mode` corta en vez de esperar.
  - Log de auditoría encadenado por SHA-256 (`audit-<session>.jsonl`), una entrada por acción de red.
  - Denegación inmediata con error MCP normalizado (`-32602`, prefijo `SECURITY ENFORCEMENT:`) cuando el target queda fuera del alcance.
  - **Capa TypeScript**: el motor de re-test (`packages/core/src/security/retest.ts`) valida el `vector` del hallazgo contra el scope de la sesión antes de emitir su petición — si el vector está fuera de alcance el re-test se omite, el hallazgo **no cambia de estado** y queda para confirmación manual. La tool `web.browse` (`packages/core/src/tool/web-browse.ts`) valida la URL inicial y aborta **en vuelo** todo request posterior (redirects, XHR, beacons y WebSockets) cuyo host no esté autorizado, y bloquea los esquemas `file:`, `chrome:`, `about:` y `data:`.
- **Límites reales (lo que el código NO hace)**:
  - El `ScopeGuard` falla cerrado cuando no hay dominios ni CIDRs configurados. Una IP directa requiere un CIDR autorizado; una IP privada, loopback, link-local o no global resuelta por un dominio también requiere que ese IP esté autorizado explícitamente por CIDR.
  - La evaluación TypeScript también falla cerrado cuando la sesión/proyecto no declara una lista positiva de dominios o CIDRs. `web.browse` verifica hosts y bloquea direcciones IP privadas literales no autorizadas, pero no fija la IP de un dominio a nivel de socket; DNS rebinding en el navegador sigue siendo un límite conocido.
  - Nuclei recibe `-restrict-local-network-access`, `-no-interactsh` y `-disable-update-check` por defecto. Esto bloquea conexiones estándar a redes locales desde los protocolos de Nuclei y evita callbacks OAST públicos y comprobaciones de actualización automáticas; los templates OAST no se ejecutan.
  - El flag de Nuclei no aplica el scope CIDR de Argos, no fija la IP resuelta por `ScopeGuard` y no garantiza controlar toda llamada de red que pueda hacer un template. El breaker tampoco observa solicitudes mientras el proceso Nuclei está activo. Un proxy local de salida sigue siendo necesario para imponer scope y observabilidad durante toda la fase.
  - `argos-bin/cmd/web/tools/download.go` descarga binarios de terceros desde GitHub Releases con verificación de checksum según los metadatos disponibles. Ese tráfico de instalación no se dirige al target del engagement y no pasa por el `ScopeGuard`.

### Dominio 2: Safety Controls & Tripwires (Controles de Seguridad Operativa)
- **Implementación**: `argos-bin/internal/guard/` (circuit-breaker y detección de WAF reutilizable), `argos-bin/cmd/web/tools/breaker.go` (breaker por sesión de escaneo y evento de tripwire), `argos-bin/cmd/web/tools/scan.go` (fases pasiva/activa e integración del breaker), más `packages/core/src/security/gates.ts` (`phased-gates`) y `packages/core/src/security/scope-service.ts`.
- **Mecanismo implementado**:
  - **Circuit-breaker (`argos-bin/internal/guard/breaker.go`)**: un `Breaker` **por sesión de escaneo** (no global: se indexa por el `ScopeGuard` de la sesión, `tools.SessionBreaker`), que observa las respuestas del target y devuelve un `Decision{Continue, Reason, Action}` con `Action ∈ {"", "degrade", "abort"}`. Umbrales por defecto (todos ajustables por variables `ARGOS_BREAKER_*`):
    - **Regla 5xx → `abort`**: si en la ventana reciente de **20 respuestas** más del **30 %** son 5xx (y hay al menos **5** muestras), el escaneo se detiene. El motivo dice el porcentaje y el umbral: *"server error rate 40% over the last 5 responses exceeds the 30% threshold: the target is degraded and the scan was stopped to avoid denying service"*. El umbral es deliberadamente conservador: un target que ya falla un tercio de las peticiones está en problemas y seguir golpeándolo convierte un mal momento en una caída.
    - **Regla de latencia → `degrade` y luego `abort`**: si la **mediana** de la ventana supera la latencia base × **3**, el escaneo se degrada (mitad de rate limit, mitad de concurrencia, sin headless, sin clases intrusivas); si la condición persiste **3** evaluaciones seguidas, el escaneo aborta. La latencia base la fija el operador (`BaselineLatencyMs`) o la aprende el breaker de la primera ventana completa.
    - **Regla WAF → `degrade`**: si se detecta un WAF (`guard.DetectWAF`, reutilizado por la tool `web.waf` y por el breaker, de modo que ambos nunca discrepan), el escaneo se degrada: baja el rate limit y desactiva las cargas intrusivas. La detección es de firma (cabeceras y cuerpo), no activa: no envía payloads. La tool `web.waf` además alimenta el breaker de la sesión, así que un WAF detectado por recon suaviza los escaneos que vengan después.
    - **Latch**: tras un `abort` el breaker queda abierto y **no se rearma** en la misma ejecución. Un target degradado no se vuelve a tocar porque la respuesta vuelva a ser 200.
  - **Pre-flight antes de cualquier template**: `web.scan` no lanza el motor de plantillas hasta que el breaker vio suficientes respuestas sanas. Envía **5 GET** contra el target raíz por el cliente atado al `ScopeGuard` y aborta sin descargar ni ejecutar nuclei si el target ya está degradado. Es una mitigación de carga inicial, no una garantía de ausencia de impacto: el test `TestWebScan_AbortsWhenTheTargetDegrades` verifica que el caso simulado recibe **5 peticiones, no miles**.
  - **Consulta del breaker entre fases**: antes de la fase activa se vuelve a consultar el breaker; si aborta, el escaneo se detiene y se conserva lo ya encontrado; si degrada, la fase activa se suaviza.
  - **Observabilidad (obligatoria)**: el resultado de la tool declara `status`, `aborted`, `abort_reason`, `degraded`, `degraded_reason`, `waf_detected`/`waf_vendor` y el bloque `breaker` (acción, motivo y estadísticas de la ventana). Un circuit-breaker invisible es peor que no tenerlo.
  - **Fases pasiva/activa de `web.scan`**: por defecto el escaneo corre **primero la fase pasiva** (sweep de recon: clases `exposure,misconfig,tech,detect`, sólo protocolo HTTP `-pt http`, sin clases intrusivas `dos,intrusive,fuzzing,default-login`, sin headless, con presupuesto acotado a ⅓ del timeout) y **después la activa** (el conjunto pedido por el operador). Los hallazgos se reportan por separado (`passive_findings`, `active_findings`, `passive_count`, `active_count`) y la unión deduplicada va en `findings`. `passive: true` corre **sólo** la fase pasiva (la fase apta para Ola 1). Un escaneo que ya declara su conjunto de templates (`tags`) corre ese conjunto una sola vez: el sweep pasivo sería tráfico que el operador no pidió.
  - **Tripwire auditable**: cada `degrade` y cada `abort` se escribe como evento estructurado (`argos-web: circuit-breaker {...}`) y se expone el seam `tools.SetBreakerAuditor` para encadenarlo en el audit log del engagement.
  - **División estricta en compuertas por fases (backend)**: `ola1_recon` (reconocimiento no invasivo) vs `ola2_exploit` (validación activa, inyecciones y fuzzing), con bloqueo determinista de las herramientas de explotación hasta que se hayan registrado activos en la fase de reconocimiento (consulta a la base de datos, por sesión), validación de scope del target antes de autorizar la herramienta (`evaluateScopeTarget`, motivo normalizado `SCOPE ENFORCEMENT:`) y bypass de compuertas sólo con `NODE_ENV=test` o con el opt-in explícito `ARGOS_ALLOW_PHASED_GATE_BYPASS=1`.
- **Límites reales (lo que el código NO hace)**:
  - **El breaker no ve el tráfico que genera el binario externo**: las peticiones que nuclei emite durante las fases salen del binario, no del cliente atado al `ScopeGuard`, así que **no pasan por la ventana del breaker**. El control protege el pre-flight y las fronteras entre fases, no el tráfico intra-fase. Para cerrarlo habría que enrutar el tráfico de nuclei a través de un proxy local que use el cliente del guard (con la intercepción TLS que eso implica) o mover la ejecución al runtime TypeScript: es el pendiente Known Risks más relevante de esteDominio.
  - **El evento de tripwire todavía no entra en la cadena de auditoría del `ScopeGuard`**: su escritor (`logAudit`) es privado y `internal/scope/scope.go` no expone todavía un método público de auditoría. Hoy el evento queda en el log estructurado y en el resultado de la tool; el seam `tools.SetBreakerAuditor` está listo para encadenarlo en cuanto `ScopeGuard` exponga `LogAudit`.
  - **La detección de WAF es de firma**: no identifica WAFs que no dejan cabeceras reconocibles y no distingue un bloqueo real de un `403` legítimo.
  - **El breaker no conoce el SLA del cliente**: los umbrales son globales por sesión, no negociados por objetivo.
  - El gate de fases del backend (`packages/core/src/security/gates.ts`) y el breaker del runtime Go son controles **independientes**: el primero decide si una herramienta de explotación puede invocarse, el segundo decide si el target puede seguir soportando el tráfico.

### Dominio 3: Human Oversight & Permission Gate (Supervisión Humana Graduada)
- **Implementación**: Sistema de permisos interactivo en UI (`packages/app`) y runtime IPC (`packages/desktop`).
- **Mecanismo**:
  - Toda acción con impacto potencialmente destructivo requiere confirmación interactiva humana.
  - Modos de confirmación no destructivos por defecto (ej. `web.sqli` invoca sqlmap con `--batch --level=1 --risk=1` y la extracción de impacto es *off* por defecto: sólo perfil de DBMS y banner, sin dumping de datos).
  - Capacidad humana de pausar, intervenir o abortar cualquier ejecución en tiempo real: existe una **parada de emergencia** (`packages/core/src/session/kill-switch.ts` + `SessionRunCoordinator.abort`) con endpoint propio `POST /session/:id/emergency-stop`, que cancela la generación, mata el árbol de procesos de los binarios MCP (el servidor y los scanners que lanzó) y deja el evento `engagement.abort` en la cadena de auditoría. Es un endpoint **distinto** de `session.abort`, que cancela la generación y permite continuar.
  - **Presupuesto duro por engagement** (`packages/core/src/session/budget.ts`): límite de llamadas a herramientas, tokens, tiempo de reloj y hallazgos, configurable por proyecto y aplicado en los dos registries de tools (core y `packages/argos`). Al excederlo la ejecución se corta con un error tipado, no se degrada en silencio.
- **Límites reales**: existe un evaluador determinista de seguridad de PoC (`packages/core/src/security/poc.ts`, que clasifica payloads como `safe-read`/`safe-timing`/`safe-boolean`/`destructive`), pero **hoy no está conectado al camino de ejecución**: sólo lo ejercitan los tests. La protección efectiva de "no destructivo" en la ruta `web.sqli` viene de los flags del comando y de la aprobación humana, no de ese evaluador.

### Dominio 4: Auditability & Traceability (Auditabilidad Integral y Reproducibilidad)
- **Implementación**: Event sourcing en SQLite con Drizzle ORM (`packages/core`) y registro de logs MCP.
- **Mecanismo**:
  Los eventos que se envían al servicio de auditoría se guardan con marcas temporales. El encadenamiento SHA-256 permite detectar modificaciones, borrados o saltos de secuencia; no vuelve inmutable el almacenamiento.
  - Exportación estandarizada en formato **OASIS SARIF v2.1.0** para integración con pipelines DevSecOps y SIEMs.
  - Huellas digitales criptográficas (fingerprints SHA-256) por cada hallazgo para deduplicación exacta.
  - Cadena de auditoría encadenada por SHA-256 (`packages/core/src/audit/service.ts`). La cadena es *keyless*: detecta modificación, borrado y huecos de secuencia, pero no protege contra un atacante con escritura directa a la base de datos que re-apende y recomputa la cadena (para eso haría falta HMAC con secreto local).
  - **Testing out-of-band sin fuga a terceros**: la tool `web.oob` (`argos-bin/cmd/web/tools/oob.go`) no usa proveedores OAST públicos. Levanta un colector propio (`argos-bin/internal/oob/server.go`) que escucha en loopback y correlaciona cada callback por **token**, de modo que el hostname del target auditado nunca sale de la máquina del auditor. El dominio OAST con el que se ejecutó el vector queda registrado en la evidencia del hallazgo (`evidence`), junto con el `correlation`, para que el re-test sea reproducible. Un proveedor externo exige el opt-in explícito `ARGOS_OAST_EXTERNAL=1`; en ese caso la tool lo declara en su resultado (`external_oast: true` más un aviso de que el tráfico sale a un tercero) y la infraestructura propia se declara con `ARGOS_OAST_DOMAIN`. Cuando no hay colector DNS disponible, el resultado lo dice (`dns_oast: false` con su motivo), de modo que el agente no asuma que puede aplicar técnicas DNS.
- **Límites reales (lo que el código NO hace)**:
  - El colector OAST propio habla **sólo HTTP** y escucha en `127.0.0.1`: para que un target remoto alcance el callback, el operador tiene que exponer su propio dominio OAST (`ARGOS_OAST_DOMAIN` + `ARGOS_OAST_BIND`) o correr un `interactsh-server` propio. El modo DNS no está implementado dentro del proceso: depende del par `interactsh-client`/`interactsh-server` instalado en el host, y sin él la tool declara `dns_oast: false`.

### Dominio 5: Reporting & Finding Validation (Validación Determinista y Reportes)
- **Implementación**: Motor de validación tipo XBOW (`packages/core/src/security/validation.ts`), motor de re-test (`packages/core/src/security/retest.ts`) y enriquecimiento CVSS v3.1 (`packages/core/src/security/cvss.ts`).
- **Mecanismo implementado**:
  - Desacoplamiento entre detección preliminar (`suspected` / `validation_status: detected`) y confirmación empírica (`validated` / `validation_status: confirmed`), con transición a `rejected` y evidencia del error cuando el verificador falla.
  - Sincronización bidireccional con el ciclo de vida del hallazgo en la UI.
  - Scoring CVSS v3.1 cuantitativo basado en vectores observables directos, sin puntuaciones arbitrarias.
- **Límites reales (lo que el código NO hace)**:
  - El motor XBOW **no verifica por tipo de vulnerabilidad**: `validateFinding` recibe un `verifier` genérico (callback) y sólo orquesta la máquina de estados. No hay verificadores embebidos por tipo (SQLi, XSS, etc.): quién decide *cómo* se confirma un hallazgo es el llamador (agente o skill).
  - La re-verificación automática (`retest.ts`) cubre **4 cabeceras HTTP** (`strict-transport-security`, `content-security-policy`, `x-frame-options`, `x-content-type-options`) y el **handshake TLS**. Cualquier otro tipo de hallazgo queda en `in-progress` con el motivo "requiere confirmación manual" — nunca se marca `verified` sin evidencia.
  - El export estructurado cubre **9 formatos** (`packages/core/src/security/export/`): SARIF v2.1.0 (validado contra el schema oficial de OASIS), DefectDojo, JUnit XML, HTML autocontenido, CycloneDX SBOM 1.5 (validado contra su schema oficial), HAR 1.2, CSV, Markdown y **PDF nativo generado en el backend** (`packages/core/src/security/pdf.ts`, con metadatos, portada, índice y hash de contenido). El PDF se genera con un writer propio sin dependencias externas: Playwright se descartó porque no distribuye navegador y porque su salida no es determinista.

### Dominio 6: Supply Chain Trust & Provenance (Seguridad de la Cadena de Suministro)
- **Implementación**: Verificación criptográfica en `argos-bin/cmd/web/tools/download.go` y generación de SBOM.
- **Mecanismo**:
  - Verificación SHA-256 para artefactos con digest fijado y formato compatible. La disponibilidad de verificación depende de los metadatos que publique cada proveedor.
  - Generación automatizada de SBOM en formato **CycloneDX JSON** en el pipeline de CI (`.github/workflows/ci.yml`).
  - Aislamiento de paquetes Python mediante entornos virtuales dedicados (`venv`) por herramienta.
- **Límites reales**: el SBOM de CI describe **Argos como proyecto**, no el target auditado; Argos no genera un SBOM del target.

### Dominio 7: Graduated Autonomy Levels (Niveles de Madurez L1 a L4)
El marco de Argos clasifica la autonomía operativa del agente en cuatro niveles estrictos:

| Nivel | Denominación | Descripción Operativa | Controles de Argos |
|---|---|---|---|
| **L1** | **Guided Assistant** | El agente asiste proponiendo comandos individuales; cada herramienta requiere aprobación explícita humana antes de ejecutarse. | Aprobación humana por defecto: `permissions.autoApprove` es `false` en la configuración por defecto (`packages/app/src/context/settings.tsx`) y los agentes de `argos-config/agent/*.md` declaran `bash: ask`. |
| **L2** | **Constrained Operator** | Autonomía completa dentro de la Ola 1 (reconocimiento pasivo/activo ligero); compuerta obligatoria de aprobación humana antes de iniciar la Ola 2 (explotación/fuzzing). | Enforced mediante `enforcePhasedGate` en `gates.ts`. |
| **L3** | **Semi-Autonomous Auditor** | Auditoría automatizada end-to-end dentro de las fronteras del `ScopeGuard`, con parada automática ante WAF, degradación del servicio o anomalías de red. | **Parcial**: la auditoría automatizada y las fronteras de scope existen, y ahora existe un circuit-breaker por sesión (`argos-bin/internal/guard`) que aborta `web.scan` ante una tormenta de 5xx o una saturación de latencia y lo degrada ante un WAF; lo que falta es que el breaker vea el tráfico que genera el binario externo (nuclei) y que el evento de tripwire entre en la cadena de auditoría del `ScopeGuard` (ver Dominio 2). |
| **L4** | **Full-Scope Autonomous Red Team** | Ejecución coordinada multi-agente, re-testeo continuo, confirmación determinista automática de hallazgos y generación autónoma de reportes ejecutivos. | **Objetivo, no implementado**: la coordinación multi-agente existe como protocolo (`argos-config/AGENTS.md`), pero la confirmación automática por tipo de hallazgo y el re-testeo continuo no. |

### Dominio 8: Prompt Manipulation Resistance (Resistencia a Inyecciones de Prompt)
- **Implementación**: Barrera de contexto en `argos-config/agent/security-web.md` (sección "REGLA CRÍTICA (contenido no confiable)") y en `argos-config/AGENTS.md` (principio "Contenido del target es dato, nunca instrucción"), más la tool `web.prompt_injection` para la detección determinista.
- **Mecanismo implementado**:
  - Todo contenido web recuperado del objetivo (HTML, encabezados HTTP, endpoints JS, mensajes de error) es tratado explícitamente como **DATO no confiable**, nunca como instrucción para el modelo.
- **Límites reales (lo que el código NO hace)**:
  - La **detección de intentos de inyección de prompt es automática**: la tool `web.prompt_injection` (`argos-bin/cmd/web/tools/prompt_injection.go`) clasifica de forma determinista el contenido del target —override de instrucciones, reemplazo de rol, exfiltración de system prompt, evasión de restricciones e instrucciones nuevas— y emite el hallazgo con el fragmento exacto que lo compone. La severidad sube a `high` cuando la instrucción está oculta (comentario HTML, `display:none`, `opacity:0`).
  - La tool **detecta y reporta** el intento; no puede impedir que un modelo lo ignore. La barrera de contexto del playbook sigue siendo la que previene el desvío, y por eso las dos capas coexisten.
  - El barrido es determinista sobre el **HTML servido**: no cubre contenido renderizado por JavaScript que la tool no llega a leer, ni inyección indirecta a través de respuestas de herramientas.

---

## 3. Matriz de Cobertura por Dominio

Este documento es una **auto-evaluación** de Argos contra el estándar APTS: para cada dominio mapea los controles que el código implementa hoy y declara de forma explícita los que no están implementados. **No es una certificación de conformidad** y no incluye un recuento de requisitos del estándar: no existe en el repositorio ninguna fuente verificable que respalde una cifra concreta, así que no se afirma ninguna.

Lo que sí puede sostenerse hoy: cada uno de los 8 dominios tiene al menos un control verificable en el código, y las brechas —dominios 1, 2, 4, 5 y 8— están señaladas arriba con el mismo detalle con el que se declaran los controles implementados. En el Dominio 2 el control de parada automática existe desde ARG-025 (circuit-breaker por sesión en `argos-bin/internal/guard`), pero su cobertura es parcial: protege el pre-flight y las fronteras entre fases de `web.scan`, no el tráfico que genera el binario externo, y su evento todavía no está encadenado en el audit log del `ScopeGuard`.

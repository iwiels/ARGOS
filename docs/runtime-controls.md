# Argos Desktop: controles del runtime y sus límites

Este mapa describe controles presentes en el código. La disponibilidad depende del paquete, la arquitectura y el preflight del equipo; el [registro de verificación](release-verification.md) distingue las integraciones probadas de las pendientes.

## Perfil de escritorio

Windows ejecuta el servidor en la distribución privada WSL2 `ArgosRuntime`; Linux lo ejecuta de forma nativa. La auditoría web se habilita solo cuando el paquete incluye el worker fijado y el runtime verifica Docker y su imagen. El navegador requiere además un preflight de Chromium con sandbox. No hay fallback del navegador al host. LAN y Elasticsearch no forman parte de este perfil. El empaquetado macOS no incorpora actualmente el perfil de auditoría web.

Código: [configuración del servidor](../packages/desktop/src/main/server.ts), [sidecar WSL](../packages/desktop/src/main/wsl/sidecar.ts) y [disponibilidad del runtime](../packages/desktop/src/main/wsl/linux-runtime.ts). Para construir el worker, véase [Instalación](installation.md#build-from-source).

## Alcance y guardas de red

El backend evalúa destinos contra la política de la sesión mediante [scope-service.ts](../packages/core/src/security/scope-service.ts) y [scope-eval.ts](../packages/core/src/security/scope-eval.ts). El MCP web recibe del controlador el identificador de sesión, la operación y una instantánea del alcance. El runtime Go valida los destinos y las direcciones resueltas antes de conectar mediante [ScopeGuard](../argos-bin/internal/scope/scope.go); las exclusiones tienen precedencia sobre las inclusiones.

Los workers usan el [gateway de alcance](../argos-bin/internal/gateway/proxy.go) del controlador y no tienen red directa del contenedor. El gateway valida la URL de cada solicitud HTTP y conecta mediante el dialer protegido. HTTPS usa CONNECT en el puerto 443: el gateway valida el destino y su IP, pero no descifra el contenido. Si hay exclusiones de rutas, CONNECT se bloquea porque esas rutas no pueden inspeccionarse dentro del túnel. El gateway no admite cambios de protocolo, y el worker del navegador bloquea WebSockets. Estas restricciones pueden impedir flujos de aplicaciones que dependan de ellos.

La normalización de identidad para deduplicar hallazgos (`normalizeTargetIdentity`, en [ingest.ts](../packages/core/src/security/ingest.ts)) no sustituye la evaluación de alcance ni demuestra que un scanner cubrió todas las rutas autorizadas.

## Compuertas por fases

[gates.ts](../packages/core/src/security/gates.ts) clasifica las herramientas según su nombre y, cuando corresponde, su acción:

| Clase | Ejemplos |
|---|---|
| `ola1_recon` | `web.probe`, `web.crawl`, `web.tls`, `web.ports`, `web.browse:navigate`, `web.browse:login` |
| `ola2_exploit` | `web.scan`, `web.sqli`, `web.api`, `web.cms`, `web.browse:check_authz`, `web.browse:dom_xss` |
| `general` | Herramientas no incluidas en los conjuntos anteriores, como `code.sast`, `code.secrets` y `code.deps` |

Para una herramienta de Ola 2, la compuerta exige al menos un registro de hallazgo de procedencia confiable en la sesión. Ese conteo no prueba que el reconocimiento esté completo ni que el hallazgo sea una vulnerabilidad confirmada. La clasificación tampoco garantiza que una acción de Ola 1 sea pasiva: un inicio de sesión o una navegación pueden cambiar el estado de la aplicación objetivo. Las autorizaciones del operador y los permisos de herramientas siguen siendo necesarios.

Cuando recibe un destino, la compuerta también consulta la política de alcance. `NODE_ENV=test` omite estas compuertas en pruebas; `ARGOS_ALLOW_PHASED_GATE_BYPASS=1` permite omitirlas con una advertencia explícita. Ese bypass no debe confundirse con una ampliación del alcance autorizado.

## Navegador y perfiles autenticados

La herramienta de escritorio es [browser.go](../argos-bin/cmd/web/tools/browser.go), que ejecuta [browser-worker.mjs](../argos-bin/worker/browser/browser-worker.mjs) dentro del worker. La implementación TypeScript de [web-browse.ts](../packages/core/src/tool/web-browse.ts) conserva una interfaz y pruebas con un launcher inyectable; su launcher por defecto rechaza la ejecución local.

- `navigate` recoge título, enlaces y formularios de la página solicitada; puede reutilizar el estado guardado de un perfil.
- `login` usa un perfil del vault del escritorio y guarda el estado de sesión devuelto por el navegador.
- `check_authz` compara el estado HTTP y la longitud de respuesta de dos perfiles. Su indicador `potentialBOLA` es una heurística para revisión, no una prueba de BOLA/BFLA.
- `dom_xss` introduce una sonda en un parámetro y observa usos de `Element.innerHTML` y `document.write`. Detectar un sink requiere análisis posterior; no demuestra por sí solo ejecución de JavaScript ni cubre todos los sinks.

El modelo recibe identificadores opacos de perfiles. Los secretos se resuelven a través del vault y se transfieren al worker en memoria. El uso de perfiles y el puente local se describen en [Privacidad](../PRIVACY.md#browser-authentication-profiles).

## Hallazgos y triage

[FindingService](../packages/core/src/security/service.ts) consulta hallazgos de procedencia confiable de una sesión y excluye por defecto los marcados como falsos positivos mediante feedback; puede incluirlos cuando se solicita expresamente. [ingest.ts](../packages/core/src/security/ingest.ts) calcula la identidad usada por la ingesta y la deduplicación, y [finding-feedback.ts](../packages/core/src/security/finding-feedback.ts) valida el feedback contra el hallazgo y la sesión.

Los [exportadores](../packages/core/src/security/export/) conservan estados y feedback; algunos formatos incluyen hallazgos suprimidos para trazabilidad. Las métricas del modelo de exportación separan esos hallazgos de los activos. Un hallazgo importado o generado por una herramienta no equivale a una remediación verificada.

El motor de [retest](../packages/core/src/security/retest.ts) incluye matchers de PoC y comprobaciones pasivas de cabeceras/TLS, pero exige un ejecutor HTTP aislado y confiable. La API actual del escritorio no lo proporciona: devuelve `checked: false`, explica la ausencia del transporte y conserva el estado anterior del hallazgo. La conexión de retest al gateway sigue pendiente; las pruebas del evaluador con transportes de fixture no demuestran retest automático de extremo a extremo en el escritorio.

# Privacy and telemetry

Argos is a local desktop application, but not every operation stays on the device. Operators should review this page before sending assessment data to an AI provider or configuring telemetry.

## Data sent to AI providers

When an operator uses an AI model, Argos sends the configured provider the prompts and context needed for that request. Depending on the workflow, this can include target names, scanner output, findings, and other assessment evidence. The selected provider's own retention, processing, and privacy terms apply. A model hosted on the operator's machine avoids sending prompts to a remote AI provider; scanners and enabled telemetry have separate network behavior described below.

## Optional error reporting

The desktop renderer and standalone web application initialize Sentry only when `VITE_SENTRY_DSN` is supplied at build time. If enabled, uncaught application exceptions are sent to the Sentry endpoint configured by that DSN, with platform, environment, and release metadata. The repository does not configure a public Sentry DSN or a public release pipeline. Exception content is not guaranteed to be free of target names or local paths; do not enable Sentry for a distribution until its redaction and retention settings have been reviewed.

## Optional OpenTelemetry

OpenTelemetry log and trace export is inactive unless the operator configures `OTEL_EXPORTER_OTLP_ENDPOINT`. When enabled, Argos sends application logs and traces to that endpoint; credentials can be supplied through `OTEL_EXPORTER_OTLP_HEADERS`. AI SDK spans also require the `experimental.openTelemetry` setting. Those spans can include prompts, model responses, tool arguments and results, as well as the configured username and Argos session ID. The current call configuration does not disable the SDK's input or output recording. Treat the collector as another destination for assessment data; the operator chooses and controls it and its retention policy.

## Scanner traffic and local storage

Engagement records and the Argos database are stored locally by the desktop runtime. Third-party scanners are downloaded on demand from their pinned upstream releases and verified according to the checksum metadata Argos supports. Nuclei scans disable its public Interactsh service and automatic update checks by default; this also excludes OAST-based templates. In the desktop worker profile, HTTP traffic passes through Argos's scope gateway, and HTTPS uses a scoped CONNECT tunnel on port 443. The gateway does not decrypt HTTPS bodies and blocks CONNECT when path exclusions are configured because it cannot inspect those paths. Protocol upgrades are unsupported, and the browser worker disables WebSockets. Review [runtime controls](docs/runtime-controls.md), templates, and scanner behavior before use. Other integrations can contact external services according to their configuration; review [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and each tool's documentation before enabling them.

Argos does not claim that all assessment data remains local when a remote AI provider, Sentry DSN, OpenTelemetry collector, or externally configured scanner service is used.

## Browser authentication profiles

Desktop authentication profiles store the username, password, selectors, and saved browser storage state encrypted with Electron `safeStorage` under the desktop user's application data. On Linux, Argos accepts only a supported OS keyring backend; if protected storage is unavailable, profile operations fail instead of writing plaintext. Profile metadata and secrets are not exposed through the renderer's generic store API. Deleting a profile removes its encrypted record.

The LLM tool schema receives an opaque profile ID. It does not receive the stored password or browser cookies as tool input or output. For Windows/WSL2, the desktop opens a temporary HTTP bridge on loopback and the WSL virtual-network interface. A random bearer token authorizes requests from the Linux sidecar, and proxy bypass is configured for those local addresses. This bridge is local to the desktop/WSL environment but is not TLS-encrypted; secrets exist in process memory while the MCP server transfers them to the isolated browser worker. The browser state returned by the worker is written back to the desktop vault, and the bridge closes when the sidecar stops.

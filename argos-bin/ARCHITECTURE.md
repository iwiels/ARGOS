# Go MCP servers

`argos-bin` is a separate Go module that builds Argos's MCP servers. The desktop starts these executables as child processes over MCP stdio; they are not imported into the TypeScript server.

## Runtime profile

| Binary | Responsibility | Linux-first desktop profile |
|---|---|---|
| `orquestador` | Audit coordination, engagement memory, and structured finding storage | Enabled |
| `argos-web` | Web application and API assessment tools | Conditional on the versioned worker package and Docker preflight |
| `argos-lan` | Network discovery and port/service assessment | Deferred from the first desktop milestone |
| `argos-es` | Read-only Elasticsearch integration | Not enabled in this profile |

On Windows, the Linux-first desktop keeps Electron on Windows and runs the Linux server binaries in WSL 2. On Linux, the supported profile runs natively. macOS keeps its existing desktop runtime. See [desktop installation requirements](../docs/installation.md) for the current support boundaries; this document does not promise a published installer or stable release.

## Scanner dependencies and network behavior

The Go servers are not standalone, offline scanners. Several tools are downloaded on demand from pinned upstream releases into the user's tool cache. Argos verifies published checksums where the provider's checksum metadata can be used; consult [`cmd/web/tools/spec.go`](cmd/web/tools/spec.go) and [`cmd/web/tools/download.go`](cmd/web/tools/download.go) for the current versions and verification behavior. Downloaded tools retain their own licenses and may have additional dependencies; see the repository's [third-party notices](../THIRD_PARTY_NOTICES.md).

External scanner processes run in the digest-pinned Argos worker image with Docker `--network=none`, a non-root user, a read-only workspace, and resource limits. When a controller supplies a session, operation, and scope snapshot, the worker relay exposes only a Unix socket to the scope gateway. The relay supplies the gateway proxy settings to the scanner; direct socket traffic from the worker has no network route. Scanner downloads are performed by the Argos MCP process and are separate from requests to assessment targets. Nuclei's public Interactsh integration and automatic update checks are disabled by default. Scanner and template behavior still varies, so the runtime reports unsupported or unavailable capabilities rather than promising that every tool can run through this gateway.

## Scope enforcement

Network actions require an explicit positive allowlist of authorized domains or CIDRs. Empty scope blocks scans. A hostname entry does not authorize a private, loopback, link-local, or metadata-service IP; authorize internal addresses with an explicit IP or CIDR. The scope gateway validates each proxied target and pins the validated DNS answer for the socket connection. Its initial proxy contract supports HTTP to port 80 and HTTPS `CONNECT` to port 443; HTTPS `CONNECT` is disabled when path exclusions are configured, and protocol upgrades/WebSockets are blocked. Tools that need raw UDP, arbitrary TCP, unsupported ports, or other bypass protocols remain unavailable through this profile. The browser uses the proxy explicitly and has no host-browser fallback; its MCP tool is exposed only after the packaged Chromium worker passes preflight.

The container boundary currently applies to external scanner processes, the browser worker, and HTTP checks from `web.scan`, `web.waf`, `web.csrf`, `web.graphql`, `web.jwt`, `web.oauth`, `web.prompt_injection`, and `web.ssti`. The scan preflight runs five bounded health probes and a passive WAF fingerprint in `/usr/local/bin/argos-worker-preflight`; `web.waf` uses the same helper with one health probe. The six native HTTP probes execute through `/usr/local/bin/argos-worker-probe`, which accepts only controller-bound tool calls and discards partial results if any request fails or the gateway blocks it. The controller accepts only complete, versioned worker responses. Native probe responses also carry a SHA-256 digest that must match the exact session, operation, scope snapshot, and parameters sent to the worker, and their result tool and target must match the request. The scan preflight separately verifies its exact target and feeds scan health and WAF results into the session circuit breaker. Direct sockets, gateway denials, upstream gateway errors, malformed or mismatched output, missing workers, and timeouts block the operation. Nuclei is not launched unless the scan preflight succeeds. `web.sqli`, `web.smuggle`, and `web.ssrf` remain explicitly unavailable in Linux-first: SQLi's Nuclei/sqlmap and native probes are not yet composed inside the isolated execution; smuggling requires unsupported raw-socket handling; and blind SSRF needs a callback service reachable by the assessed target, which this profile does not provision. The full web audit path remains incomplete until these capabilities move behind the worker boundary and report their execution status explicitly.

With `ARGOS_TRAFFIC_CAPTURE=1`, the scope gateway records proxied HTTP exchanges in the session traffic store. Request/response bodies are capped at 4 MiB per exchange; URL and credential-header values plus recognized request-body secrets are redacted. HTTPS records only the successful `CONNECT` tunnel's host and duration because TLS contents are not decrypted. Capture is off by default; a persistence error is logged while the scope decision remains in the hash-chained audit log.

Use Argos only against systems for which the operator has authorization. Scope controls reduce accidental out-of-scope activity; they do not replace authorization or guarantee network isolation.

## Building and testing

Use the Go version declared in [`go.mod`](go.mod). From this directory:

```bash
go test ./...
go build -o bin/orquestador ./cmd/orquestador
go build -o bin/argos-web ./cmd/web
go build -o bin/argos-lan ./cmd/lan
go build -o bin/argos-es ./cmd/es
```

The output executable format follows the host platform. To cross-compile, set `GOOS` and `GOARCH` explicitly and confirm that every bundled or downloaded third-party tool supports the target architecture. In particular, availability on `arm64` depends on upstream release artifacts; Argos reports tools without a compatible artifact as unavailable.

The desktop build and WSL runtime packaging are maintained separately under `packages/desktop`. Build commands and runtime prerequisites are documented in [Installation](../docs/installation.md).

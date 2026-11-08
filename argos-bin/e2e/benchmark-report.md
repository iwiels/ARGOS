# Argos Security Benchmark Report

- **Fecha:** 2026-10-22T14:20:11Z
- **Modo:** light
- **Duración:** 35.64s
- **Ground truth:** 44 vectores (18 medibles en modo light, 17 sin tool que los detecte)

## Runners

| Runner | Recall | Recall (light) | Precision | FPR | Hallazgos | TP | FP |
|---|---|---|---|---|---|---|---|
| `argos_full` | 40.9% | 100.0% | 100.0% | 0.0% | 18 | 18 | 0 |
| `argos_no_agents` | 40.9% | 100.0% | 100.0% | 0.0% | 28 | 28 | 0 |
| `raw_tools` | n/d | n/d | n/d | n/d | 0 | 0 | 0 |

- `argos_full`: the Argos tools with the canonical contract and the taxonomy dedup
- `argos_no_agents`: the same tools without the canonical contract: only the title and the URL survive
- `raw_tools`: the third party scanners (nuclei, dalfox) without Argos in the path (the third party binaries are not available: nuclei: not installed; dalfox: not installed)

## Ground truth

| ID | Categoría | Ruta | Descripción | Severidad | Tool | Modo | Detectado |
|---|---|---|---|---|---|---|---|
| GT-SQLI-01 | sqli | /search?q=1 | SQLi in query parameter q (blind / syntax error) | critical | web.sqli | full | ❌ No |
| GT-SQLI-02 | sqli | /item?id=1 | SQLi in query parameter id (numeric boolean differential) | critical | web.sqli | full | ❌ No |
| GT-XSS-01 | xss | /profile?user=admin | Reflected XSS in parameter user | medium | web.xss | full | ❌ No |
| GT-LEAK-ENV | exposure | /.env | Exposed environment configuration file | high | web.fuzz | full | ❌ No |
| GT-LEAK-BACKUP | exposure | /backup.zip | Exposed backup archive | high | web.fuzz | full | ❌ No |
| GT-ROBOTS | recon | /robots.txt | Exposed robots.txt disclosing sensitive routes | low | unsupported | none | ❌ No |
| GT-HEADER-CSP | misconfig | / | Missing Content-Security-Policy header | low | web.scan | full | ❌ No |
| GT-HEADER-HSTS | misconfig | / | Missing Strict-Transport-Security header | low | web.scan | full | ❌ No |
| GT-HEADER-XFO | misconfig | / | Missing X-Frame-Options header (clickjacking) | low | web.scan | full | ❌ No |
| GT-IDOR-01 | idor | /api/item/{id} | IDOR/BOLA: the record of any user is returned without checking the session | critical | unsupported | none | ❌ No |
| GT-CSRF-01 | csrf | /login | CSRF: the login form has no anti-CSRF token | high | web.csrf | light | ✅ Sí (web.csrf) |
| GT-CSRF-02 | csrf | /api/transfer | CSRF: a state changing endpoint with no token and no Origin validation | high | unsupported | none | ❌ No |
| GT-JWT-01 | jwt | /api/token | JWT signed with alg:none (the signature is never verified) | critical | web.jwt | light | ✅ Sí (web.jwt) |
| GT-JWT-02 | jwt | /api/token | JWT without exp claim: the token never expires | medium | web.jwt | light | ✅ Sí (web.jwt) |
| GT-JWT-03 | jwt | /api/token | JWT without aud claim: the audience cannot be validated | medium | web.jwt | light | ✅ Sí (web.jwt) |
| GT-JWT-04 | jwt | /api/token | JWT carries a mutable privilege claim: the role of the token is client controlled | high | web.jwt | light | ✅ Sí (web.jwt) |
| GT-JWT-05 | jwt | /api/token | JWT without iss claim: the issuer cannot be validated | low | web.jwt | light | ✅ Sí (web.jwt) |
| GT-SSRF-01 | ssrf | /fetch?url= | Blind SSRF: the server fetches the URL it receives and leaks the internal failure | high | web.ssrf | light | ✅ Sí (web.ssrf) |
| GT-XXE-01 | xxe | /api/xml | XXE: the XML parser resolves external entities and reads local files | high | unsupported | none | ❌ No |
| GT-SSTI-01 | ssti | /render?tpl= | SSTI: the template evaluates the expression of the request | critical | web.ssti | light | ✅ Sí (web.ssti) |
| GT-OPENREDIR-01 | redirect | /redirect?u= | Open redirect: any destination is accepted | medium | unsupported | none | ❌ No |
| GT-PATHTRAV-01 | traversal | /download?file= | Path traversal: the file name escapes the base directory | high | unsupported | none | ❌ No |
| GT-CMDI-01 | cmd-injection | /ping?host= | Command injection: the host is concatenated into a shell command | critical | unsupported | none | ❌ No |
| GT-DESER-01 | deserialization | /api/deserialize | Unsafe deserialization: the gadget of the payload reaches the shell | critical | unsupported | none | ❌ No |
| GT-GQL-01 | graphql | /graphql | GraphQL introspection is enabled: the whole schema is readable | medium | web.graphql | light | ✅ Sí (web.graphql) |
| GT-GQL-02 | graphql | /graphql | The GraphQL schema exposes sensitive fields (the password of the user) | medium | web.graphql | light | ✅ Sí (web.graphql) |
| GT-GQL-03 | graphql | /graphql | GraphQL exposes state changing mutations without an authorization rule | medium | web.graphql | light | ✅ Sí (web.graphql) |
| GT-GQL-04 | graphql | /graphql | GraphQL has no depth limit: a deeply nested query is accepted | medium | web.graphql | light | ✅ Sí (web.graphql) |
| GT-GQL-05 | graphql | /graphql | GraphQL processes batched operations: a single request is amplified | medium | web.graphql | light | ✅ Sí (web.graphql) |
| GT-SMUGGLE-01 | smuggling | / (front proxy) | HTTP request smuggling: the front-end accepts an ambiguous framing (CL+TE) | high | web.smuggle | light | ✅ Sí (web.smuggle) |
| GT-RACE-01 | race | /api/coupon | Race condition: a single use coupon is redeemed twice concurrently | medium | unsupported | none | ❌ No |
| GT-USERENUM-01 | auth | /api/login | User enumeration: the response time tells whether the account exists | medium | unsupported | none | ❌ No |
| GT-RATELIMIT-01 | auth | /api/login | Missing rate limit: the login endpoint never throttles | medium | unsupported | none | ❌ No |
| GT-GIT-01 | exposure | /.git/ | The git repository is exposed | high | web.fuzz | full | ❌ No |
| GT-GIT-02 | exposure | /.git/config | A personal access token travels in the URL of the git remote | high | web.artifact | light | ✅ Sí (web.artifact) |
| GT-CORS-01 | cors | /api/cors | Permissive CORS: any origin is accepted together with the credentials | high | web.csrf | light | ✅ Sí (web.csrf) |
| GT-COOKIE-01 | misconfig | /login | The session cookie travels without Secure, HttpOnly nor SameSite | medium | unsupported | none | ❌ No |
| GT-VERB-01 | misconfig | /api/data | Verb tampering: the endpoint answers the state changing verbs too | low | unsupported | none | ❌ No |
| GT-DEBUGVARS-01 | exposure | /debug/vars | Information disclosure: the debug endpoint exposes the configuration and its secrets | medium | web.artifact | light | ✅ Sí (web.artifact) |
| GT-SECTXT-01 | recon | /security.txt | security.txt is missing: the contact channel of the project does not exist | info | unsupported | none | ❌ No |
| GT-SUBDOMAIN-01 | recon | dev.payments.acme-corp.local | Subdomain takeover: the vhost still answers from a deleted bucket | high | unsupported | none | ❌ No |
| GT-CACHE-01 | misconfig | /api/cache | Cache poisoning: a shared cache serves a response that depends on the headers without Vary | medium | unsupported | none | ❌ No |
| GT-UNICODE-01 | misconfig | /unicode/ | Unicode smuggling: the fullwidth spelling of a blocked path slips through the edge | medium | unsupported | none | ❌ No |
| GT-SECRETJS-01 | exposure | /static/app.js | The API key of the backend travels in the JavaScript bundle | high | web.artifact | light | ✅ Sí (web.artifact) |

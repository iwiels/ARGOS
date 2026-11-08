# Import scanner findings

Argos can attach an external scanner report to an existing audit session. In the session's **Findings** tab, choose **Import report**, select the format, choose a report file, and preview it. The preview validates the whole file and displays a bounded list of findings and parser warnings. Select **Save import** only after reviewing the preview.

Supported formats:

- SARIF 2.1.0
- Nuclei JSONL
- Semgrep JSON
- Gitleaks JSON
- Trivy JSON
- OWASP ZAP JSON
- Burp XML export
- DefectDojo Generic JSON

The file limit is 8 MiB and each report is limited to 50,000 findings. JSON parsers also enforce depth and node-count limits. Burp exports use an internal DTD; Argos accepts only structural `ELEMENT` and `ATTLIST` declarations, then discards the DTD without resolving it. External DTDs, entity declarations, and parameter entities are rejected. A malformed report is rejected as a whole; Argos does not persist the valid prefix of a failed import. See PortSwigger's [XML issue export documentation](https://portswigger.net/burp/documentation/dast/user-guide/work-with-scan-results/generate-reports).

Imported findings enter the session with status `observed` and confidence `possible`. An external scanner status such as `verified`, `closed`, or `active: false` is retained only as source metadata where supported; it does not close the Argos finding or verify remediation. Empty reports can be previewed but cannot be saved because Argos does not yet persist scanner-run records independently of findings.

Argos stores normalized finding fields and selected provenance rather than copying scanner documents wholesale. The current parsers omit common raw request/response bodies, matched source snippets, and captured secret fields; SARIF partial fingerprints are hashed before storage. Keep the original report if you need its full scanner-native detail.

Repeating an import with the same format and content is idempotent within a session. API clients can provide a new `importID` to record an otherwise identical report as a separate batch. Reimports do not automatically mark a finding fixed when a later report omits it.

## Finding cases

New findings with the same project-scoped identity are linked to one case while each session keeps its own finding row and evidence. Existing findings are migrated one-to-one into separate cases; Argos does not infer historical cross-session matches. The Findings tab lists cases linked to the current session, including recurrence counts, and allows their remediation status and reason to be updated. Accepting risk requires a future expiry. Status transitions are retained in case history and the audit log. Deleting a session removes its finding rows; a shared case remains while another session still backs it.

The case API is scoped through an existing session. `GET /api/session/{sessionID}/finding-cases` lists related cases with bounded pagination; `GET /api/session/{sessionID}/finding-cases/{caseID}/history` reads at most 100 status transitions; `GET /api/session/{sessionID}/finding-cases/{caseID}/operations` reads at most 100 merge/split operations. `POST /api/session/{sessionID}/finding-cases/{caseID}/status` updates a case only if it has a finding in the session. `accepted-risk` updates require `acceptedRiskUntil` as a future Unix timestamp in milliseconds.

Cases can be merged with `POST /api/session/{sessionID}/finding-cases/{sourceCaseID}/merge` and a `targetCaseID` plus reason, or split with `POST /api/session/{sessionID}/finding-cases/{caseID}/split` and 1–500 finding IDs from that session plus a reason. `POST /api/session/{sessionID}/finding-cases/{caseID}/operations/{operationID}/reverse` reverses an operation with a required reason. Every operation stores its finding-ID snapshot and history; later dependent operations must be reversed first. A merge source is hidden from the session case list while merged, and the target case exposes the operation history for reversal. These controls change case grouping only; they do not change scanner evidence or mark findings remediated.

## HTTP API

Both endpoints are scoped to an existing session and accept a JSON body with `format`, `content`, and an optional `importID`:

- `POST /api/session/{sessionID}/findings/import/preview` parses without writing findings or observations.
- `POST /api/session/{sessionID}/findings/import` validates and imports the report.

The response includes the parser version, SHA-256 of the uploaded content, normalized findings, and warnings. Import errors include a stable error code; Nuclei JSONL errors may also identify the source line.

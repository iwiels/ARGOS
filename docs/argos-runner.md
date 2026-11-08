# Argos Runner

`argos-runner` is an early-access Linux CLI for driving an Argos session without the desktop renderer. It is built into the versioned Linux runtime and is intended for local automation experiments. If the binary is not on `PATH`, invoke the copy in `$HOME/.local/share/argos/runtime/<Argos-version>/argos-runner` under WSL, or the Linux binary in `argos-bin/bin/linux-<arch>/` when working from the repository.

The CLI connects to an already running Argos server. It does not start the server, create sessions, select targets, or approve scope. Create a session and verify its approved scope in Argos first; the CLI checks the session ID format but does not independently validate authorization. The latest execution must not be interrupted; recovery remains an explicit operator action in the desktop.

```sh
argos-runner run --session ses_<id> --prompt "Audit the approved web target"
argos-runner status --session ses_<id>
argos-runner cancel --session ses_<id>
argos-runner export --session ses_<id> --format sarif --output ./report.sarif
```

Pass `--prompt -` to read the instruction from standard input. `--fail-on` accepts `critical`, `high`, `medium`, `low`, or `info` and defaults to `high`. `--timeout` and `--poll-interval` accept Go duration values such as `45m` and `2s`. `argos-runner --version` reports the Argos package version embedded by the build.

The server URL defaults to `http://127.0.0.1:4096`; set `ARGOS_SERVER_URL` or pass `--server` to change it. If server authentication is enabled, set `ARGOS_SERVER_PASSWORD` and, when needed, `ARGOS_SERVER_USERNAME` (default username: `opencode`). The CLI sends credentials only to localhost over HTTP; use HTTPS for any other host. Do not put passwords in command-line arguments.

## Exit codes for `run`

|  Code | Meaning                                                                                                                                 |
| ----: | --------------------------------------------------------------------------------------------------------------------------------------- |
|   `0` | The execution and its required coverage record are complete, and no unsuppressed finding met the configured severity threshold.         |
|   `1` | CLI, server, authentication, or export error.                                                                                           |
|   `2` | The execution completed and at least one unsuppressed finding met the threshold.                                                        |
|   `3` | The execution failed, was interrupted, timed out, did not reach a durable completion cursor, or has no verified complete coverage plan. |
| `130` | The operator cancelled the command with Ctrl-C.                                                                                         |

Argos stores append-only coverage observations at `GET` and `POST /api/session/{sessionID}/runs/{runID}/coverage`. An observation records the surface (`web`, `api`, or `repository`), role, test key, state (`executed`, `no-finding`, `blocked`, `skipped`, or `inconclusive`), evidence hash/reference, and its attestation. Runtime observations require both a SHA-256 evidence hash and an evidence reference. Repeating a POST with the same run and idempotency key returns the original record; changing its content returns a conflict. API-submitted observations are always marked `api-reported`; the caller cannot set the attestation or runtime tool. Only internal runtime code can mark a record `runtime-observed`.

The immutable controller-owned plan is read at `GET /api/session/{sessionID}/runs/{runID}/coverage-plan`; it returns `null` until a plan exists. A requirement binds a surface, role, test key, and expected runtime tool. The runner fetches this plan and the observations for the exact completed run. `coverageStatus` reports `not-recorded`, `reported-unverified`, `runtime-incomplete`, `runtime-unplanned`, `plan-incomplete`, `plan-complete`, or `unavailable`. `plan-complete` requires a matching runtime observation for every requirement, with the expected tool, a complete status, and valid evidence hash/reference. These non-complete states return exit code `3`; a threshold finding still returns `2`.

The persistence and read contract for controller plans now exists, but the run controller does not generate plans yet and the isolated runtime does not yet submit runtime attestations. Therefore a clean run still cannot reach exit code `0` in the current product. The runner-managed isolated runtime is not yet available. Web scanners remain disabled unless the desktop runtime reports a ready, scope-enforcing container gateway. Do not use this early-access runner as a release gate for production until plan generation, runtime attestations, container preflight, and CI integration are complete.

An interrupted latest execution is not resumed automatically. `status` shows the execution journal; use the desktop's explicit recovery flow before starting another run. If timeout or Ctrl-C cannot be confirmed by the server's abort endpoint, the run result includes `stopError`. `export` accepts the report formats listed above, verifies the server-provided SHA-256 before writing, and uses restrictive file permissions on Linux.

For `status`, `cancel`, and `export`, code `0` means that command succeeded and code `1` means it failed; those commands do not evaluate the audit gate.

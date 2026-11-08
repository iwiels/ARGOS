---
description: Run the security audit orchestrator
agent: security-orchestrator
---

Launch the orchestrator only for authorized targets. Start a structured run, persist phase artifacts, and use the linked MCP runtime tools to gate any risky tooling before correlation/reporting.

**REGLA CRÍTICA (run_id):** `audit.run.start` devuelve el `run_id` canónico (timestamp + target, p.ej. `20260807-193103-https---aulavirtualsiste`). Usá SIEMPRE ese valor en `audit.run.phase`, `audit.run.inspect` y `audit.run.correlate`. NUNCA uses el campaign/session ID (p.ej. `aulavirtualsistemas-2026-08-07`) como `run_id` — no es el mismo identificador y la tool responde error MCP -32602 "Run not found". Pasá el `run_id` a los especialistas al lanzarlos para que lo usen en sus llamadas a `audit.run.phase`.

**Parallel execution (fan-out, no sequential waits):**
- Use `audit.dispatch` to launch specialist agents (scout/web/code/ops) in parallel fan-out: max 3 concurrent per wave.
- Do NOT wait for `phase-complete` between dispatches: poll `audit.run.inspect` for phase artifacts and advance to the next wave once minimum coverage exists.
- Persist each agent's findings with `memory.save` as they arrive (streaming), then run `audit.run.correlate` once coverage is sufficient.
- The MCP servers honor `ARGOS_MCP_CONCURRENCY` (default 4) and `ARGOS_MCP_TIMEOUT_MS` (default 120000). Tune these env vars per host instead of serializing agent runs; if the MCP returns saturation errors, retry once with backoff before treating the call as failed.

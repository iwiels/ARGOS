/**
 * E2E de ARG-013: tool Go → store de memoria → reconciliador → fila en la DB.
 *
 * El ciclo completo atraviesa los dos lenguajes, así que ningún test de un
 * solo lado puede demostrarlo:
 *
 *   1. El binario Go (cmd/web/tools) escribe el hallazgo en el store con el
 *      contrato canónico — el mismo código que corre en producción.
 *   2. El backend (packages/core) reconcilia ese store y lo deja en la tabla
 *      `security_finding` con el CWE de la tool.
 *
 * Uso:  bun scripts/argos-013-e2e.ts
 */
import { mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { $ } from "bun"

const repoRoot = join(import.meta.dir, "..")
const binDir = join(repoRoot, "argos-bin")

const store = await mkdtemp(join(tmpdir(), "argos-013-e2e-"))
const sessionID = "ses_agent_go_store"

console.log(`[argos-013] store: ${store}`)
console.log(`[argos-013] session: ${sessionID}`)

const env = { ...process.env, ARGOS_E2E_STORE_DIR: store, ARGOS_E2E_SESSION_ID: sessionID }

try {
  console.log("[argos-013] 1/2 — el binario Go escribe el store")
  const go = await $`go test ./cmd/web/tools/ -run TestE2EWriteStoreForTheBackend -count=1`.cwd(binDir).env(env).quiet()
  console.log(go.stdout.toString().trim())
  console.log(go.stderr.toString().trim())
  if (go.exitCode !== 0) throw new Error(`the Go side failed with exit code ${go.exitCode}`)

  console.log("[argos-013] 2/2 — el backend reconcilia el store")
  const ts = await $`bun test packages/core/test/agent-findings-reconcile.test.ts`.cwd(repoRoot).env(env).quiet()
  console.log(ts.stdout.toString().trim())
  console.log(ts.stderr.toString().trim())
  if (ts.exitCode !== 0) throw new Error(`the TypeScript side failed with exit code ${ts.exitCode}`)

  console.log("[argos-013] OK — tool Go → store → reconciliador → fila en DB")
} finally {
  await rm(store, { recursive: true, force: true })
}

import { build } from "esbuild"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"

const __dirname = dirname(fileURLToPath(import.meta.url))
const configDir = join(__dirname, "..", "..", "..", "argos-config")

const entries = [
  {
    src: join(configDir, "skills", "auditoria-web", "scripts", "web-core.ts"),
    out: join(configDir, "skills", "auditoria-web", "scripts", "web-core.mjs"),
  },
  {
    src: join(configDir, "skills", "auditoria-recon", "scripts", "recon-core.ts"),
    out: join(configDir, "skills", "auditoria-recon", "scripts", "recon-core.mjs"),
  },
  {
    src: join(configDir, "skills", "auditoria-red", "scripts", "lan-core.ts"),
    out: join(configDir, "skills", "auditoria-red", "scripts", "lan-core.mjs"),
  },
]

for (const { src, out } of entries) {
  await build({
    entryPoints: [src],
    outfile: out,
    bundle: false,
    platform: "node",
    format: "esm",
    target: "node20",
    logLevel: "warning",
  })
  console.log(`[core-scripts] ${out}`)
}

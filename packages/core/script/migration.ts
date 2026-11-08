#!/usr/bin/env bun

import { $ } from "bun"
import fs from "fs/promises"
import os from "os"
import path from "path"
import { pathToFileURL } from "url"
import { parseArgs } from "util"

const root = path.resolve(import.meta.dirname, "../../..")
const sqlDir = path.join(root, "packages/core/migration")
const tsDir = path.join(root, "packages/core/src/database/migration")
const registry = path.join(root, "packages/core/src/database/migration.gen.ts")
const args = parseArgs({
  args: process.argv.slice(2),
  options: {
    check: { type: "boolean" },
    name: { type: "string" },
  },
})

if (args.values.check) {
  await check()
  process.exit(0)
}

await $`bun drizzle-kit generate ${args.values.name ? ["--name", args.values.name] : []}`.cwd(
  path.join(root, "packages/core"),
)

const sqlMigrations = (await Array.fromAsync(new Bun.Glob("*/migration.sql").scan({ cwd: sqlDir })))
  .map((file) => path.dirname(file).replaceAll("\\", "/"))
  .filter((name) => name !== undefined && name !== ".")
  .sort()

for (const name of sqlMigrations) {
  if (await Bun.file(path.join(tsDir, `${name}.ts`)).exists()) continue
  await Bun.write(
    path.join(tsDir, `${name}.ts`),
    renderMigration(name, await Bun.file(path.join(sqlDir, name, "migration.sql")).text()),
  )
}

const allTsMigrations = (await Array.fromAsync(new Bun.Glob("*.ts").scan({ cwd: tsDir })))
  .map((file) => path.basename(file, ".ts"))
  .filter((name) => name !== undefined && name !== ".")
  .sort()

await Bun.write(registry, renderRegistry(allTsMigrations))

async function check() {
  const temporary = await fs.mkdtemp(path.join(os.tmpdir(), "opencode-core-migration-check-"))
  const output = path.join(temporary, "migration")
  try {
    await fs.cp(sqlDir, output, { recursive: true })
    const config = path.join(temporary, "drizzle.config.ts")
    await Bun.write(
      config,
      `import config from ${JSON.stringify(pathToFileURL(path.join(root, "packages/core/drizzle.config.ts")).href)}

export default { ...config, out: ${JSON.stringify(output)} }
`,
    )
    const before = await snapshot(output)
    await $`bun drizzle-kit generate --config ${config}`.cwd(path.join(root, "packages/core"))
    const after = await snapshot(output)
    if (before === after) return
    console.error("drizzle-kit generate produced changes that are not checked into version control")
    process.exit(1)
  } finally {
    await fs.rm(temporary, { recursive: true, force: true })
  }
}

function renderMigration(id: string, sql: string) {
  const statements = sql
    .split("--> statement-breakpoint")
    .map((s) => s.trim())
    .filter(Boolean)
  return `import { Effect } from "effect"
import type { DatabaseMigration } from "../migration"

export default {
  id: ${JSON.stringify(id)},
  up(tx) {
    return Effect.gen(function* () {
${statements.map((s) => `      yield* tx.run(\`${s.replaceAll("`", "\\`")}\`)`).join("\n")}
    })
  },
} satisfies DatabaseMigration.Migration
`
}

function renderRegistry(migrations: string[]) {
  return `import type { DatabaseMigration } from "./migration"

export const migrations = (
  await Promise.all([
${migrations.map((m) => `    import("./migration/${m}"),`).join("\n")}
  ])
).map((module) => module.default) satisfies DatabaseMigration.Migration[]
`
}

async function snapshot(dir: string) {
  const files = (await Array.fromAsync(new Bun.Glob("**/*").scan({ cwd: dir }))).sort()
  const entries: string[] = []
  for (const file of files) {
    const full = path.join(dir, file)
    const stat = await fs.stat(full)
    if (!stat.isFile()) continue
    entries.push(`${file}:${await Bun.file(full).text()}`)
  }
  return entries.join("\n")
}

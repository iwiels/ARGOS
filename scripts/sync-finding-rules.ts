#!/usr/bin/env bun
/**
 * Validates the canonical finding taxonomy registry and mirrors it into the
 * Go tools.
 *
 * The registry itself lives in packages/core/src/security/rules/registry.json:
 * the TypeScript side owns it and the Go tools consume it. A Go module cannot
 * embed a file that lives outside its own tree, so this script generates the
 * mirror at argos-bin/cmd/web/tools/rules/registry.json and fails when the
 * two diverge.
 *
 *   bun scripts/sync-finding-rules.ts            # validate + write the mirror
 *   bun scripts/sync-finding-rules.ts --check    # validate + fail on drift (CI)
 */
import { readFileSync, writeFileSync } from "node:fs"
import { join } from "node:path"

const repoRoot = join(import.meta.dir, "..")
const sourcePath = join(repoRoot, "packages/core/src/security/rules/registry.json")
const mirrorPath = join(repoRoot, "argos-bin/cmd/web/tools/rules/registry.json")
const derivePath = join(repoRoot, "packages/core/src/compliance/derive.ts")
const attackPath = join(repoRoot, "packages/core/src/threat-intel/attack.ts")

const SEVERITIES = new Set(["critical", "high", "medium", "low", "info"])
const GENERATED_NOTE =
  "GENERATED FILE - do not edit by hand. Source: packages/core/src/security/rules/registry.json. Run: bun scripts/sync-finding-rules.ts"

export type RegistryRule = {
  id: string
  cwe: string[]
  owasp: string[]
  severity_floor: string
  tags: string[]
  references: string[]
  matcher?: string
}

export type Registry = {
  version: string
  vocabulary: string[]
  cwe_by_tag: Record<string, string>
  rules: RegistryRule[]
}

/**
 * Extracts the canonical tag vocabulary from the engines that consume it:
 * the semantic rules of the compliance deriver and the MITRE ATT&CK catalog.
 * The registry may not invent tags outside this vocabulary.
 */
export function canonicalVocabulary(): string[] {
  const tags = new Set<string>()
  for (const path of [derivePath, attackPath]) {
    const source = readFileSync(path, "utf8")
    for (const match of source.matchAll(/tags:\s*\[([^\]]*)\]/g)) {
      for (const raw of match[1]!.split(",")) {
        const tag = raw.trim().replace(/^["']|["']$/g, "").trim()
        if (tag) tags.add(tag)
      }
    }
  }
  return [...tags].sort()
}

/** Parses and validates the registry source. Throws on the first problem. */
export function parseRegistry(raw: string): Registry {
  const registry = JSON.parse(raw) as Registry

  if (typeof registry.version !== "string" || !registry.version.trim()) {
    throw new Error("registry.version is missing")
  }
  if (!Array.isArray(registry.rules) || registry.rules.length === 0) {
    throw new Error("registry.rules is missing or empty")
  }
  if (!Array.isArray(registry.vocabulary) || registry.vocabulary.length === 0) {
    throw new Error("registry.vocabulary is missing or empty")
  }
  if (!registry.cwe_by_tag || typeof registry.cwe_by_tag !== "object") {
    throw new Error("registry.cwe_by_tag is missing")
  }

  const vocabulary = new Set(registry.vocabulary)
  const expected = canonicalVocabulary()
  const missing = expected.filter((tag) => !vocabulary.has(tag))
  if (missing.length > 0) {
    throw new Error(
      `registry.vocabulary does not cover the tags the engines match on: ${missing.join(", ")}`,
    )
  }
  const extra = registry.vocabulary.filter((tag) => !expected.includes(tag))
  if (extra.length > 0) {
    throw new Error(`registry.vocabulary has tags the engines do not know: ${extra.join(", ")}`)
  }

  for (const [tag, cwe] of Object.entries(registry.cwe_by_tag)) {
    if (!vocabulary.has(tag)) throw new Error(`cwe_by_tag key "${tag}" is not in the vocabulary`)
    if (!/^CWE-\d{1,5}$/.test(cwe)) throw new Error(`cwe_by_tag["${tag}"] is not a CWE id: ${cwe}`)
  }

  const seen = new Set<string>()
  for (const rule of registry.rules) {
    if (typeof rule.id !== "string" || !rule.id.trim()) throw new Error("a rule has no id")
    if (seen.has(rule.id)) throw new Error(`duplicated rule id: ${rule.id}`)
    seen.add(rule.id)
    if (!rule.id.startsWith("nuclei:") && !rule.id.startsWith("semgrep:")) {
      throw new Error(`rule id "${rule.id}" must be prefixed with "nuclei:" or "semgrep:"`)
    }
    if (!SEVERITIES.has(rule.severity_floor)) {
      throw new Error(`rule "${rule.id}" has an invalid severity_floor: ${rule.severity_floor}`)
    }
    for (const cwe of rule.cwe ?? []) {
      if (!/^CWE-\d{1,5}$/.test(cwe)) throw new Error(`rule "${rule.id}" has an invalid cwe: ${cwe}`)
    }
    for (const owasp of rule.owasp ?? []) {
      if (!/^A\d{2}:2021$/.test(owasp)) {
        throw new Error(`rule "${rule.id}" has an invalid owasp id: ${owasp}`)
      }
    }
    for (const tag of rule.tags ?? []) {
      if (!vocabulary.has(tag)) {
        throw new Error(`rule "${rule.id}" has a tag outside the vocabulary: ${tag}`)
      }
    }
    for (const reference of rule.references ?? []) {
      if (!/^https?:\/\//.test(reference)) {
        throw new Error(`rule "${rule.id}" has a non-http reference: ${reference}`)
      }
    }
    if (rule.matcher !== undefined && !["content", "status"].includes(rule.matcher)) {
      throw new Error(`rule "${rule.id}" has an invalid matcher: ${rule.matcher}`)
    }
  }

  return registry
}

/** Renders the deterministic Go mirror of the registry. */
export function renderMirror(registry: Registry): string {
  const mirror = {
    _generated: GENERATED_NOTE,
    version: registry.version,
    vocabulary: registry.vocabulary,
    cwe_by_tag: registry.cwe_by_tag,
    rules: registry.rules,
  }
  return JSON.stringify(mirror, null, 2) + "\n"
}

function main() {
  const check = process.argv.includes("--check")

  let registry: Registry
  try {
    registry = parseRegistry(readFileSync(sourcePath, "utf8"))
  } catch (error) {
    console.error(`Finding rules: ${(error as Error).message}`)
    process.exit(1)
  }

  const rendered = renderMirror(registry)
  const current = (() => {
    try {
      return readFileSync(mirrorPath, "utf8")
    } catch {
      return ""
    }
  })()

  if (check) {
    if (current !== rendered) {
      console.error("Finding rules: argos-bin/cmd/web/tools/rules/registry.json is out of date.")
      console.error("Run: bun scripts/sync-finding-rules.ts")
      process.exit(1)
    }
    console.log(`Finding rules: OK (${registry.rules.length} rules, vocabulary ${registry.vocabulary.length})`)
    return
  }

  if (current !== rendered) {
    writeFileSync(mirrorPath, rendered)
    console.log(`Finding rules: wrote ${registry.rules.length} rules to the Go mirror`)
    return
  }
  console.log(`Finding rules: OK (${registry.rules.length} rules, vocabulary ${registry.vocabulary.length})`)
}

if (import.meta.main) main()

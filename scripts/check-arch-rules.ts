/**
 * Enforces .arch-rules.json forbidden dependency rules as a blocking gate.
 *
 * Usage: bun scripts/check-arch-rules.ts   (exit 1 on violation)
 */
import { readdirSync, readFileSync, statSync } from "node:fs"
import { extname, join } from "node:path"

type Rule = { name: string; from: string[]; to: string[]; allow?: Array<{ file: string; specifier: string }> }

const repoRoot = join(import.meta.dir, "..")
const configPath = join(repoRoot, ".arch-rules.json")
const SKIP_DIRS = new Set(["node_modules", "dist", "out", "build", ".git"])
const CODE_EXTS = new Set([".ts", ".tsx", ".mts", ".cts"])
const IMPORT_RE = /(?:\bfrom\s*|\bimport\s*\(\s*|\brequire\s*\(\s*)["']([^"']+)["']/g

type PackageInfo = { name: string; dir: string }

function listPackages(dir: string, depth = 0): PackageInfo[] {
  if (depth > 3 || !statSync(dir, { throwIfNoEntry: false })?.isDirectory()) return []
  if (SKIP_DIRS.has(dir.split(/[\\/]/).pop() ?? "")) return []
  const found: PackageInfo[] = []
  try {
    const manifest = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"))
    if (typeof manifest?.name === "string") {
      found.push({ name: manifest.name, dir: dir.slice(repoRoot.length + 1).replaceAll("\\", "/") })
    }
  } catch {
    // directory without package.json - keep walking
  }
  for (const entry of readdirSync(dir)) {
    found.push(...listPackages(join(dir, entry), depth + 1))
  }
  return found
}

function walkFiles(rootRel: string, extensions: Set<string> = CODE_EXTS): string[] {
  const abs = join(repoRoot, rootRel)
  if (!statSync(abs, { throwIfNoEntry: false })?.isDirectory()) return []
  const out: string[] = []
  const walk = (current: string) => {
    for (const entry of readdirSync(current)) {
      if (SKIP_DIRS.has(entry)) continue
      const file = join(current, entry)
      if (statSync(file).isDirectory()) {
        walk(file)
        continue
      }
      if (!extensions.has(extname(file))) continue
      if (file.endsWith(".d.ts")) continue
      out.push(file.slice(repoRoot.length + 1).replaceAll("\\", "/"))
    }
  }
  walk(abs)
  return out
}

function globToRegExp(glob: string): RegExp {
  const pattern = glob.replaceAll("\\", "/")
  let re = ""
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i]
    if (ch === undefined) break
    if (ch === "*") {
      if (pattern[i + 1] === "*") {
        let j = i + 2
        if (pattern[j] === "/") j++
        re += "(?:.*/)?"
        i = j - 1
        continue
      }
      re += "[^/]*"
      continue
    }
    if (ch === "{") {
      const end = pattern.indexOf("}", i)
      re += `(?:${pattern.slice(i + 1, end).split(",").join("|")})`
      i = end
      continue
    }
    re += ch.replace(/[.+?()[\]^$|\\]/g, "\\$&")
  }
  return new RegExp(`^${re}`)
}

/** Longest literal directory prefix of a glob (no wildcards). */
function globBaseDir(glob: string): string | null {
  const cut = glob.search(/[*{]/)
  if (cut === -1) return glob.replaceAll("\\", "/")
  const base = glob.slice(0, cut).replaceAll("\\", "/")
  return base.replace(/[^/]+$/, "") || null
}

function resolveSpecifier(specifier: string, importerRel: string, packages: PackageInfo[]): string | null {
  if (specifier.startsWith(".")) {
    const baseDir = posixDirname(importerRel)
    return posixNormalize(`${baseDir}/${specifier}`)
  }
  if (specifier.startsWith("@/")) {
    // The "@" alias is per-package: it resolves to the src/ of the package
    // that owns the importing file (each package maps "@/*" in its tsconfig).
    const owner = packages.find((candidate) => importerRel.startsWith(`${candidate.dir}/`))
    const base = owner ? `${owner.dir}/src` : "packages/app/src"
    return posixNormalize(`${base}/${specifier.slice(2)}`)
  }
  const pkg = packages.find(
    (candidate) => specifier === candidate.name || specifier.startsWith(`${candidate.name}/`),
  )
  if (!pkg) return null
  const rest = specifier.slice(pkg.name.length).replace(/^\//, "")
  return posixNormalize(`${pkg.dir}/${rest}`) + (rest ? "" : "/package.json")
}

function posixDirname(value: string) {
  const idx = value.lastIndexOf("/")
  return idx === -1 ? "." : value.slice(0, idx)
}

function posixNormalize(value: string) {
  const parts: string[] = []
  for (const segment of value.split("/")) {
    if (segment === "." || segment === "") continue
    if (segment === "..") parts.pop()
    else parts.push(segment)
  }
  return parts.join("/")
}

const config: { forbidden: Rule[] } = JSON.parse(readFileSync(configPath, "utf8"))
const packages = listPackages(join(repoRoot, "packages")).concat(listPackages(join(repoRoot, "argos-bin")))

const violations: Array<{ rule: string; file: string; specifier: string }> = []

for (const rule of config.forbidden) {
  const fromRes = rule.from.map(globToRegExp)
  const toRes = rule.to.map(globToRegExp)
  const roots = [...new Set(rule.from.map(globBaseDir).filter((v): v is string => !!v))]
  const seenFiles = new Set<string>()
  for (const root of roots) {
    for (const file of walkFiles(root)) {
      if (!fromRes.some((re) => re.test(file)) || seenFiles.has(file)) continue
      seenFiles.add(file)
      const content = readFileSync(join(repoRoot, file), "utf8")
      for (const match of content.matchAll(IMPORT_RE)) {
        const specifier = match[1]
        if (!specifier) continue
        const target = resolveSpecifier(specifier, file, packages)
        if (target && toRes.some((re) => re.test(target))) {
          const allowed = rule.allow?.some(
            (entry) => globToRegExp(entry.file).test(file) && globToRegExp(entry.specifier).test(specifier),
          )
          if (!allowed) violations.push({ rule: rule.name, file, specifier })
        }
      }
    }
  }
}

if (violations.length > 0) {
  console.error(`Arch rules: ${violations.length} violation(s)`)
  for (const v of violations) console.error(`  [${v.rule}] ${v.file} -> ${v.specifier}`)
  process.exit(1)
}

/**
 * Reglas de contenido: constructs prohibidos dentro de un archivo.
 *
 * No son reglas de import — acotan qué puede escribir un archivo concreto.
 * La familia de abajo es la del cliente HTTP de las tools web: todo request
 * contra un target tiene que salir del cliente atado al ScopeGuard
 * (IP-pinning, rate limit y audit log encadenado), así que un http.Client
 * propio es un bypass silencioso del control de alcance.
 */
const CONTENT_RULES: Array<{
  name: string
  files: string
  extensions: string[]
  forbid: RegExp[]
  allow?: string[]
  reason: string
}> = [
  {
    name: "web-tools-scope-client",
    files: "argos-bin/cmd/web/tools/**/*.go",
    extensions: [".go"],
    forbid: [/&http\.Client\s*\{/, /\bhttp\.Get\s*\(/, /\bhttp\.Post\s*\(/, /\bhttp\.DefaultClient\b/],
    // download.go baja los binarios de los terceros desde GitHub Releases: no
    // escanea el target del engagement, no es tráfico de la auditoría.
    allow: ["argos-bin/cmd/web/tools/download.go"],
    reason:
      "Las tools web deben emitir sus peticiones con env.Client() (el cliente atado al ScopeGuard). Un http.Client propio se salta el IP-pinning, el rate limit y el audit log encadenado.",
  },
]

const contentViolations: Array<{ rule: string; file: string; match: string; reason: string }> = []

for (const rule of CONTENT_RULES) {
  const fileRe = globToRegExp(rule.files)
  const base = globBaseDir(rule.files)
  if (!base) continue
  for (const file of walkFiles(base, new Set(rule.extensions))) {
    if (!fileRe.test(file)) continue
    if (rule.allow?.some((allowed) => globToRegExp(allowed).test(file))) continue
    const content = readFileSync(join(repoRoot, file), "utf8")
    for (const pattern of rule.forbid) {
      const match = pattern.exec(content)
      if (!match) continue
      contentViolations.push({ rule: rule.name, file, match: match[0].trim(), reason: rule.reason })
    }
  }
}

if (contentViolations.length > 0) {
  console.error(`Content rules: ${contentViolations.length} violation(s)`)
  for (const v of contentViolations) {
    console.error(`  [${v.rule}] ${v.file}: ${v.match}`)
    console.error(`      ${v.reason}`)
  }
  process.exit(1)
}

console.log("Arch rules: OK")

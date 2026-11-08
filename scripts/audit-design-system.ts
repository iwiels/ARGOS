import fs from "node:fs"
import path from "node:path"

interface Violation {
  file: string
  line: number
  rule: string
  message: string
  snippet: string
}

const rootDir = process.cwd()
const appDir = path.join(rootDir, "packages/app/src")
const uiDir = path.join(rootDir, "packages/ui/src")

const violations: Violation[] = []

function walk(dir: string, extensionRegex: RegExp, cb: (filePath: string) => void) {
  if (!fs.existsSync(dir)) return
  const entries = fs.readdirSync(dir, { withFileTypes: true })
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      walk(fullPath, extensionRegex, cb)
    } else if (entry.isFile() && extensionRegex.test(entry.name)) {
      cb(fullPath)
    }
  }
}

// ── Rule 1: JSX Design System Audit (TSX/JSX) ──
walk(appDir, /\.(tsx|jsx)$/, (filePath) => {
  const relPath = path.relative(rootDir, filePath)
  const content = fs.readFileSync(filePath, "utf8")
  const lines = content.split("\n")

  lines.forEach((line, idx) => {
    const lineNum = idx + 1
    const trimmed = line.trim()

    // 1.1 Prohibit direct <svg> in JSX (enforce <Icon>)
    if (
      /<svg[\s>]/.test(trimmed) &&
      !filePath.includes("components/icon") &&
      !filePath.includes("pierre") &&
      !filePath.includes("topology-canvas") &&
      !filePath.includes("titlebar")
    ) {
      violations.push({
        file: relPath,
        line: lineNum,
        rule: "no-raw-svg-in-jsx",
        message: "No uses <svg> directo; utiliza el componente <Icon> para mantener la consistencia del Design System.",
        snippet: trimmed.slice(0, 100),
      })
    }

    // 1.2 Prohibit hardcoded hex colors in Tailwind classes (e.g., bg-[#000000], text-[#121212])
    const hexMatch = trimmed.match(/class(?:Name)?=["'][^"']*(?:bg|text|border|ring)-\[#(?:[0-9a-fA-F]{3,8})\][^"']*["']/)
    if (hexMatch) {
      violations.push({
        file: relPath,
        line: lineNum,
        rule: "color-no-hardcoded-hex",
        message: "Prohibido usar colores hexadecimales hardcodeados en Tailwind. Utiliza tokens semánticos (var(--*)).",
        snippet: trimmed.slice(0, 100),
      })
    }

    // 1.3 Detect inconsistent Icon badges (e.g. rounded-full on empty state icons vs rounded-xl)
    if (
      trimmed.includes("rounded-full") &&
      (trimmed.includes("Icon") || trimmed.includes("bg-bg-")) &&
      (trimmed.includes("empty") || trimmed.includes("fallback") || trimmed.includes("h-12"))
    ) {
      violations.push({
        file: relPath,
        line: lineNum,
        rule: "consistent-icon-wrapper",
        message: "Inconsistencia en contenedor de íconos. Usa el badge estándar (rounded-xl bg-bg-surface border border-border-default).",
        snippet: trimmed.slice(0, 100),
      })
    }

    // 1.4 Prohibit hardcoded Tailwind color literals (e.g., text-orange-500, text-emerald-400)
    const colorLiteralMatch = trimmed.match(/\b(text|bg|border)-(?:orange|emerald|purple|indigo|violet|cyan|amber)-(?:400|500|600)\b/)
    if (colorLiteralMatch && !filePath.includes("test")) {
      violations.push({
        file: relPath,
        line: lineNum,
        rule: "no-tailwind-color-literals",
        message: `Literal de color Tailwind detectado (${colorLiteralMatch[0]}). Utiliza tokens semánticos (text-accent, severity-*, etc.).`,
        snippet: trimmed.slice(0, 100),
      })
    }

    // 1.5 Prohibit font-mono in major headings (h1, h2, h3)
    if (/<h[1-3][\s>]/.test(trimmed) && trimmed.includes("font-mono")) {
      violations.push({
        file: relPath,
        line: lineNum,
        rule: "no-heading-font-mono",
        message: "Encabezados principales (h1-h3) no deben usar font-mono. Reserva mono para telemetría, código y CVEs.",
        snippet: trimmed.slice(0, 100),
      })
    }

    // 1.6 Prohibit gratuitous backdrop-blur on content cards
    if (trimmed.includes("backdrop-blur-") && !filePath.includes("dialog") && !filePath.includes("popover") && !filePath.includes("overlay") && !filePath.includes("titlebar") && !filePath.includes("sidebar-shell")) {
      violations.push({
        file: relPath,
        line: lineNum,
        rule: "no-card-backdrop-blur",
        message: "Prohibido backdrop-blur decorativo en tarjetas de contenido (anti-slop). Usa superficies sólidas u opacas tokenizadas.",
        snippet: trimmed.slice(0, 100),
      })
    }

    // 1.7 Prohibit off-scale radii in TSX (V5: freeze 4px canonical scale)
    const radiusOffMatch = trimmed.match(/rounded-\[(1px|3px)\]/)
    if (radiusOffMatch) {
      violations.push({
        file: relPath,
        line: lineNum,
        rule: "radius-no-offscale",
        message: `Radio fuera de escala (${radiusOffMatch[0]}). Usa rounded-sm/md/lg del sistema (4px canónico).`,
        snippet: trimmed.slice(0, 100),
      })
    } else if (/\brounded(?![\w\-\[])/.test(trimmed)) {
      violations.push({
        file: relPath,
        line: lineNum,
        rule: "radius-no-offscale",
        message: "Radio `rounded` plano fuera de escala. Usa rounded-sm/md/lg del sistema (4px canónico).",
        snippet: trimmed.slice(0, 100),
      })
    }

    // 1.8 Prohibit arbitrary pixel font sizes in TSX (V5: tokenized .text-* scale)
    const textPxMatch = trimmed.match(/text-\[(9|10|11|12|13)px\]/)
    if (textPxMatch) {
      violations.push({
        file: relPath,
        line: lineNum,
        rule: "type-no-arbitrary-px",
        message: `Tamaño arbitrario (${textPxMatch[0]}). Usa clases .text-* tokenizadas (text-10-regular/mono, text-11-*, text-12-*, text-13-*).`,
        snippet: trimmed.slice(0, 100),
      })
    }

    // 1.9 Artisanal <button> pills in pages/** must use <Button> or justify inline (V5).
    // El script no distingue severidades: se reporta como error con allowlist inline
    // ({/* audit-allow: <motivo> */} en el bloque del botón).
    const isPagesFile = filePath.includes(`${path.sep}pages${path.sep}`)
    if (isPagesFile && /<button(?![\w-])/.test(trimmed) && !/audit-allow/.test(trimmed)) {
      const prevLine = idx > 0 ? lines[idx - 1] : ""
      const windowText = lines.slice(idx, idx + 11).join("\n")
      if (!/audit-allow/.test(prevLine) && !/audit-allow/.test(windowText) && windowText.includes("rounded-full") && windowText.includes("border")) {
        violations.push({
          file: relPath,
          line: lineNum,
          rule: "button-prefer-design-system",
          message: "<button> artesanal con pill (rounded-full+border) en pages/**. Usa <Button>/<IconButton> o justifica con {/* audit-allow: <motivo> */} en el bloque.",
          snippet: trimmed.slice(0, 100),
        })
      }
    }
  })
})

// ── Rule 2: CSS Token Audit (theme.css) ──
const themeCssPath = path.join(uiDir, "styles/theme.css")
if (fs.existsSync(themeCssPath)) {
  const relPath = path.relative(rootDir, themeCssPath)
  const cssContent = fs.readFileSync(themeCssPath, "utf8")
  const cssLines = cssContent.split("\n")

  cssLines.forEach((line, idx) => {
    const lineNum = idx + 1
    const trimmed = line.trim()

    // 2.1 Enforce strict token assignment in CSS
    if (
      (trimmed.startsWith("color:") || trimmed.startsWith("background-color:") || trimmed.startsWith("border-color:")) &&
      !trimmed.includes("var(") &&
      !trimmed.includes("transparent") &&
      !trimmed.includes("currentColor") &&
      !trimmed.includes("inherit")
    ) {
      violations.push({
        file: relPath,
        line: lineNum,
        rule: "css-declaration-strict-value",
        message: "En CSS se exige el uso de tokens semánticos var(--*). No uses valores directos.",
        snippet: trimmed,
      })
    }
  })
}

// ── Rule 3: CSS Cascade Layer Audit ──
// Enfuerza el contrato de @layer para evitar que CSS custom compita con las
// utilidades de Tailwind (ver: conflicto .text-* vs font-*/leading-*/tracking-*).
const uiStylesDir = path.join(uiDir, "styles")
const tailwindIndexPath = path.join(uiStylesDir, "tailwind/index.css")
const stylesIndexPath = path.join(uiStylesDir, "index.css")

// Archivos que pueden importarse SIN layer() (Tailwind los procesa o se auto-capas).
const UNLAYERED_OK = new Set([
  "styles/index.css", // se auto-capas internamente (@layer dentro del archivo)
  "styles/tailwind/utilities.css", // contiene SOLO @utility (lo procesa Tailwind)
  "styles/tailwind/colors.css", // contiene SOLO @theme (generado)
])

function parseImports(content: string): Array<{ target: string; layered: boolean; offset: number }> {
  const imports: Array<{ target: string; layered: boolean; offset: number }> = []
  const re = /@import\s+(?:"([^"]+)"|'([^']+)')([^;]*);/g
  let m: RegExpExecArray | null
  while ((m = re.exec(content))) {
    const target = m[1] ?? m[2]
    if (!target || target.startsWith("tailwindcss/") || !target.endsWith(".css")) continue
    imports.push({ target, layered: /layer\(/.test(m[3] ?? ""), offset: m.index })
  }
  return imports
}

function lineOf(content: string, offset: number): number {
  return content.slice(0, offset).split("\n").length
}

function resolveImport(fromFile: string, target: string): string {
  return path.normalize(path.join(path.dirname(fromFile), target)).replace(/\\/g, "/")
}

function relToUi(resolved: string): string {
  // Relativo a packages/ui/src para que las rutas coincidan con UNLAYERED_OK
  // ("styles/index.css", "styles/tailwind/utilities.css", …)
  return path.relative(uiDir, resolved).replace(/\\/g, "/")
}

const layerAuditFiles: Array<{ file: string; content: string }> = []
if (fs.existsSync(tailwindIndexPath)) {
  layerAuditFiles.push({ file: tailwindIndexPath, content: fs.readFileSync(tailwindIndexPath, "utf8") })
}
if (fs.existsSync(stylesIndexPath)) {
  layerAuditFiles.push({ file: stylesIndexPath, content: fs.readFileSync(stylesIndexPath, "utf8") })
}

if (layerAuditFiles.length > 0) {
  // 3.1 Contrato de orden: la tipografía tokenizada (.text-*) debe importarse
  // ANTES de las utilidades core para que font-*/leading-*/tracking-* ganen.
  const tailwindIndex = layerAuditFiles.find((f) => f.file === tailwindIndexPath)
  if (tailwindIndex) {
    const stylesIdx = tailwindIndex.content.indexOf('@import "../index.css"')
    const coreIdx = tailwindIndex.content.indexOf('@import "tailwindcss/utilities.css"')
    if (stylesIdx === -1 || coreIdx === -1) {
      violations.push({
        file: "packages/ui/src/styles/tailwind/index.css",
        line: 1,
        rule: "cascade-layer-order",
        message:
          'Falta "@import \"../index.css\"" o "@import \"tailwindcss/utilities.css\"" — no se puede validar el orden de capas.',
        snippet: "tailwind/index.css",
      })
    } else if (stylesIdx > coreIdx) {
      const coreLine = lineOf(tailwindIndex.content, coreIdx)
      const coreLines = tailwindIndex.content.split("\n").slice(coreLine - 1, coreLine + 1)
      violations.push({
        file: "packages/ui/src/styles/tailwind/index.css",
        line: coreLine,
        rule: "cascade-layer-order",
        message:
          '"@import \"../index.css\"" (tipografía tokenizada .text-*) debe ir ANTES de "@import \"tailwindcss/utilities.css\"", de lo contrario .text-* anula font-*/leading-*/tracking-* por orden de capa.',
        snippet: coreLines.join(" | "),
      })
    }
  }

  // Resolver la cadena de imports para 3.2 / 3.3 / 3.4
  // Nota: las entradas NO se siembran en `seen` — se registran al ser importadas
  // por la cadena (así un import duplicado de un entry también se detecta).
  const seen = new Map<string, { file: string; layered: boolean }>()
  const processed = new Set<string>()
  // Entradas con layered:true (no se audita su propio import): el import real
  // sin layer() de un entry queda cubierto por la whitelist UNLAYERED_OK.
  const queue = layerAuditFiles.map((f) => ({ resolved: f.file, content: f.content, layered: true }))
  while (queue.length > 0) {
    const current = queue.shift()!
    const rel = relToUi(current.resolved)
    if (processed.has(rel)) continue // imports en diamante: procesar cada archivo una sola vez
    processed.add(rel)

    // 3.2 Import sin layer() de un archivo con reglas planas (no whitelisted)
    if (!current.layered && !UNLAYERED_OK.has(rel)) {
      violations.push({
        file: `packages/ui/src/${rel}`,
        line: 1,
        rule: "cascade-layer-unlayered",
        message:
          "Import sin layer() de un archivo con CSS plano — competirá contra las utilidades de Tailwind y ganará por precedencia de capa. Envuélvelo en layer(...) o muévelo a @utility/@theme.",
        snippet: rel,
      })
    }

    for (const imp of parseImports(current.content)) {
      const resolved = resolveImport(current.resolved, imp.target)
      const relTarget = relToUi(resolved)
      if (!relTarget.startsWith("styles/")) continue

      // 3.4 El archivo de @utility (tailwind/utilities.css) debe importarse SIN layer()
      if (relTarget === "styles/tailwind/utilities.css" && imp.layered) {
        violations.push({
          file: `packages/ui/src/${rel}`,
          line: lineOf(current.content, imp.offset),
          rule: "cascade-layer-utility-layered",
          message: "styles/tailwind/utilities.css contiene directivas @utility que NO pueden anidarse en layer(): impórtalo sin layer().",
          snippet: imp.target,
        })
      }

      // 3.3 Duplicados: el mismo archivo importado dos veces (excepto theme-only).
      // Heurística: un archivo con @theme en sus primeros 200 chars se considera
      // re-importable sin riesgo (Tailwind fusiona bloques @theme — p.ej. colors.css).
      if (seen.has(relTarget)) {
        const isThemeOnly =
          !fs.existsSync(resolved) || /@theme\b/.test(fs.readFileSync(resolved, "utf8").slice(0, 200))
        if (!isThemeOnly) {
          violations.push({
            file: `packages/ui/src/${rel}`,
            line: lineOf(current.content, imp.offset),
            rule: "cascade-layer-duplicate-import",
            message: `Import duplicado de "${relTarget}" — el mismo CSS se incluye dos veces y el segundo orden gana sobre el primero.`,
            snippet: imp.target,
          })
        }
      } else {
        seen.set(relTarget, { file: resolved, layered: imp.layered })
        if (fs.existsSync(resolved)) {
          queue.push({ resolved, content: fs.readFileSync(resolved, "utf8"), layered: imp.layered })
        }
      }
    }
  }
}

// ── Rule 1b: TSX Design System Audit for @argos/ui (V5) ──
// Replica radius-no-offscale y type-no-arbitrary-px en los tsx de la librería
// (el walk principal solo cubre packages/app/src).
walk(uiDir, /\.(tsx|jsx)$/, (filePath) => {
  const relPath = path.relative(rootDir, filePath)
  const content = fs.readFileSync(filePath, "utf8")
  const lines = content.split("\n")

  lines.forEach((line, idx) => {
    const lineNum = idx + 1
    const trimmed = line.trim()

    const radiusOffMatch = trimmed.match(/rounded-\[(1px|3px)\]/)
    if (radiusOffMatch) {
      violations.push({
        file: relPath,
        line: lineNum,
        rule: "radius-no-offscale",
        message: `Radio fuera de escala (${radiusOffMatch[0]}). Usa rounded-sm/md/lg del sistema (4px canónico).`,
        snippet: trimmed.slice(0, 100),
      })
    } else if (/\brounded(?![\w\-\[])/.test(trimmed)) {
      violations.push({
        file: relPath,
        line: lineNum,
        rule: "radius-no-offscale",
        message: "Radio `rounded` plano fuera de escala. Usa rounded-sm/md/lg del sistema (4px canónico).",
        snippet: trimmed.slice(0, 100),
      })
    }

    const textPxMatch = trimmed.match(/text-\[(9|10|11|12|13)px\]/)
    if (textPxMatch) {
      violations.push({
        file: relPath,
        line: lineNum,
        rule: "type-no-arbitrary-px",
        message: `Tamaño arbitrario (${textPxMatch[0]}). Usa clases .text-* tokenizadas (text-10-regular/mono, text-11-*, text-12-*, text-13-*).`,
        snippet: trimmed.slice(0, 100),
      })
    }
  })
})

// ── Rule 4: CSS Literal Type Audit (V5: tokenize weights/sizes) ──
// font-weight 440|530|540|640 y font-size 13px literales fuera de
// theme/utilities deben tokenizarse (var(--font-weight-*), .text-*).
const CSS_TYPE_EXEMPT = new Set([
  "packages/ui/src/styles/theme.css",
  "packages/ui/src/styles/utilities.css",
  "packages/ui/src/styles/tailwind/utilities.css",
  "packages/ui/src/styles/tailwind/colors.css",
  "packages/ui/src/styles/tailwind/index.css",
  "packages/ui/src/styles/index.css",
])

for (const cssDir of [uiDir, appDir]) {
  walk(cssDir, /\.css$/, (filePath) => {
    const relPath = path.relative(rootDir, filePath).replace(/\\/g, "/")
    if (CSS_TYPE_EXEMPT.has(relPath)) return
    const content = fs.readFileSync(filePath, "utf8")
    const lines = content.split("\n")

    lines.forEach((line, idx) => {
      const lineNum = idx + 1
      const trimmed = line.trim()

      const weightMatch = trimmed.match(/font-weight\s*:\s*(440|530|540|640)\b/)
      if (weightMatch) {
        violations.push({
          file: relPath,
          line: lineNum,
          rule: "css-no-literal-type",
          message: `font-weight literal (${weightMatch[1]}). Tokeniza con var(--font-weight-*) (regular/medium/semibold).`,
          snippet: trimmed.slice(0, 100),
        })
      }

      if (/font-size\s*:\s*13px\b/.test(trimmed)) {
        violations.push({
          file: relPath,
          line: lineNum,
          rule: "css-no-literal-type",
          message: "font-size literal (13px). Tokeniza con var(--font-size-*) o clases .text-13-regular/.text-13-medium.",
          snippet: trimmed.slice(0, 100),
        })
      }
    })
  })
}

// ── Rule 5: Pixel SVG crispEdges Audit (V5: single pixel gate, warning) ──
// Todo tsx de ui que renderice pixel-art (viewBox 0 0 32 32) debe usar
// shape-rendering: crispEdges como la rama pixel de <Icon>.
walk(path.join(uiDir, "components"), /\.tsx$/, (filePath) => {
  const relPath = path.relative(rootDir, filePath)
  const content = fs.readFileSync(filePath, "utf8")
  if (content.includes("0 0 32 32") && !content.includes("crispEdges")) {
    const lines = content.split("\n")
    const idx = lines.findIndex((l) => l.includes("0 0 32 32"))
    violations.push({
      file: relPath,
      line: idx + 1,
      rule: "pixel-missing-crisp-edges",
      message: "Advertencia (warning): SVG pixel-art (viewBox 0 0 32 32) sin shape-rendering: crispEdges — el mismo glifo se rasteriza distinto que en <Icon>. Añade crispEdges para puerta pixel única.",
      snippet: lines[idx].trim().slice(0, 100),
    })
  }
})

// ── Output Summary ──
// Reglas de deuda (warnings): no rompen CI; documentan trabajo pendiente.
// Todo lo demás es error bloqueante.
const WARNING_RULES = new Set(["radius-no-offscale", "type-no-arbitrary-px", "css-no-literal-type"])
console.log("\n=======================================================")
console.log(" 🎨 ARGOS DESIGN SYSTEM & TOKEN AUDITOR")
console.log("=======================================================\n")

const printViolations = (title: string, items: Violation[]) => {
  if (items.length === 0) return
  console.log(`${title} (${items.length} hallazgos)\n`)
  const grouped = new Map<string, Violation[]>()
  for (const v of items) {
    const list = grouped.get(v.rule) ?? []
    list.push(v)
    grouped.set(v.rule, list)
  }

  for (const [rule, list] of grouped.entries()) {
    console.log(`📌 Regla: [${rule}] (${list.length} hallazgos)`)
    for (const item of list) {
      console.log(`   └─ ${item.file}:${item.line}`)
      console.log(`      Mensaje: ${item.message}`)
      console.log(`      Snippet: ${item.snippet}\n`)
    }
  }
}

if (violations.length === 0) {
  console.log("✨ ¡FELICIDADES! 0 violaciones detectadas.")
  console.log("Todos los componentes, íconos y tokens CSS están 100% estandarizados.\n")
  process.exit(0)
} else {
  const warnings = violations.filter((v) => WARNING_RULES.has(v.rule))
  const errors = violations.filter((v) => !WARNING_RULES.has(v.rule))
  printViolations("⚠️ Warnings (deuda, no bloquean)", warnings)
  printViolations("❌ Errores bloqueantes", errors)
  process.exit(errors.length > 0 ? 1 : 0)
}

// Test para la regla argos/icon-without-wrapper.
// Ejecuta oxlint contra el fixture y verifica:
//  - los casos INVÁLIDOS se reportan (5 warnings)
//  - los casos VÁLIDOS no se reportan
import { spawnSync } from "node:child_process"
import { fileURLToPath } from "node:url"
import path from "node:path"

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const fixture = path.join(root, "scripts/fixtures/icon-wrapper.tsx")

function runOxlint() {
  const res = spawnSync("npx", ["oxlint", fixture], {
    cwd: root,
    encoding: "utf8",
    timeout: 120_000,
  })
  const stdout = res.stdout ?? ""
  const stderr = res.stderr ?? ""
  return { stdout, stderr, status: res.status }
}

describe("argos/icon-without-wrapper", () => {
  it("reporta los iconos sueltos sin wrapper ni tamaño (5 casos inválidos)", () => {
    const { stdout, stderr } = runOxlint()
    const combined = stdout + stderr
    const reported = combined.split("\n").filter((l) => l.includes("icon-without-wrapper"))
    expect(reported).toHaveLength(5)
    // Cada caso inválido debe mencionar el nombre del icono reportado.
    expect(combined).toContain(`name="console"`)
    expect(combined).toContain(`name="edit"`)
    expect(combined).toContain(`name="branch"`)
    expect(combined).toContain(`name="server"`) // IconV2 suelto
    expect(combined).toContain(`name="warning"`) // slot propio de app
  })

  it("no reporta iconos con size, clase de tamaño, wrapper o template literal", () => {
    const { stdout, stderr } = runOxlint()
    const combined = stdout + stderr
    const warnLines = combined.split("\n").filter((l) => l.includes("icon-without-wrapper"))
    const warnText = warnLines.join("\n")

    // Estos iconos (casos válidos) NO deben estar en ninguna línea de warning.
    const validNames = ["search", "menu", "shield", "magnifying-glass", "help", "chevron-right", "outline-dots", "plus"]
    for (const name of validNames) {
      expect(warnText, `no debería reportar <Icon name="${name}">`).not.toContain(`name="${name}"`)
    }
  })

  it("el lint del repo sigue cargando el plugin sin errores", () => {
    const { stdout, stderr, status } = runOxlint()
    const combined = stdout + stderr
    // Los warnings no deberían romper el proceso; si oxlint sale con código no
    // cero es por los warnings del fixture (que es lo esperado).
    expect(combined).toContain("Found 5 warnings")
    // Sin errores catastróficos del plugin (como fallos de carga o crash).
    expect(stderr).not.toMatch(/SyntaxError|TypeError|Cannot find|Error loading plugin/i)
  })
})

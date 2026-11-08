import { describe, expect, test } from "bun:test"
import { stripFrontMatter } from "./report-preview"

describe("stripFrontMatter", () => {
  test("quita el bloque YAML que el renderer pintaba como texto suelto", () => {
    const md = [
      "---",
      'classification: "CONFIDENCIAL — TLP:AMBER"',
      'generated_at: "2026-08-28T15:30:56.229Z"',
      "cvss_average: 4.7",
      "---",
      "",
      "# Informe Ejecutivo",
    ].join("\n")

    const out = stripFrontMatter(md)
    expect(out.startsWith("# Informe Ejecutivo")).toBe(true)
    expect(out).not.toContain("classification:")
    expect(out).not.toContain("cvss_average")
  })

  test("deja intacto un markdown sin front matter", () => {
    const md = "# Informe\n\nTexto del cuerpo."
    expect(stripFrontMatter(md)).toBe(md)
  })

  test("no recorta cuando el bloque nunca cierra", () => {
    // Sin cierre no hay front matter válido: recortar comería el documento.
    const md = '---\nclassification: "X"\n\n# Informe'
    expect(stripFrontMatter(md)).toBe(md)
  })

  test("conserva las reglas horizontales del cuerpo", () => {
    const md = ["---", 'a: "1"', "---", "", "# Título", "", "---", "", "## Sección"].join("\n")
    const out = stripFrontMatter(md)
    expect(out).toContain("---")
    expect(out).toContain("## Sección")
    expect(out).not.toContain('a: "1"')
  })
})

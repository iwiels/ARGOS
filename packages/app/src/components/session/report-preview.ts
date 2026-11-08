/**
 * El Markdown exportado abre con un bloque YAML (`---\nclassification: …\n---`)
 * pensado para herramientas que consumen el archivo. En la vista previa no lo
 * lee nadie: el renderer lo pinta como texto suelto arriba del título, que es
 * justo lo que ensuciaba la primera línea del documento. Se quita sólo para
 * mostrar; el archivo que se descarga lo conserva.
 */
export function stripFrontMatter(markdown: string): string {
  if (!markdown.startsWith("---")) return markdown
  const lines = markdown.split("\n")
  if (lines[0]?.trim() !== "---") return markdown
  const closing = lines.findIndex((line, index) => index > 0 && line.trim() === "---")
  if (closing < 0) return markdown
  return lines
    .slice(closing + 1)
    .join("\n")
    .replace(/^\n+/, "")
}

export type IocType = "ip" | "domain" | "url" | "hash" | "email"

export interface Ioc {
  type: IocType
  value: string
}

const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g
const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi
const URL_RE = /\bhttps?:\/\/[^\s"'<>]+/gi
const HASH_RE = /\b[a-f0-9]{32}(?:[a-f0-9]{8}(?:[a-f0-9]{24})?)?\b/g
const EMAIL_RE = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi

const FILE_EXTENSIONS = new Set([
  "asp", "aspx", "exe", "xml", "json", "php", "js", "ts", "jsx", "tsx", "css", "html", "htm",
  "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "woff", "woff2", "ttf", "eot",
  "pdf", "doc", "docx", "xls", "xlsx", "zip", "tar", "gz", "7z", "rar", "bak", "old", "sql",
  "txt", "md", "log", "yaml", "yml", "toml", "ini", "conf", "sh", "bat", "py", "rb", "go",
  "dll", "bin", "so", "class", "jar", "war", "ear", "jsp", "jspx", "cgi", "pl", "env",
])

function isRealDomain(domain: string): boolean {
  const parts = domain.split(".")
  if (parts.length < 2) return false
  const tld = parts.at(-1)!
  if (FILE_EXTENSIONS.has(tld)) return false
  if (/^\d+$/.test(tld) || tld.length < 2) return false
  return true
}

/** Extrae el hostname de una URL para reputación de dominio. */
export function domainFromUrl(url: string) {
  try {
    const parsed = new URL(url)
    return parsed.hostname.replace(/^www\./i, "")
  } catch {
    return undefined
  }
}

/**
 * Extrae IoCs (IPs, dominios, URLs, hashes, emails) de un texto (evidence,
 * vector, target, tags concatenados). Deduplica por tipo+valor normalizado.
 *
 * `exclude` saca de la extracción valores que son metadatos propios del motor,
 * no indicadores del target. Importa para `source_tool`: sus valores
 * (`code.review`, `ops.analysis`, `recon.osint`, `web.scan`…) tienen forma de
 * dominio y `.review`/`.osint` pasan el filtro de TLD, así que sin esto cada
 * hallazgo mostraba su propia herramienta de origen como si fuera un dominio
 * observado en el objetivo auditado.
 */
export function extractIocs(text: string, options?: { exclude?: readonly (string | null | undefined)[] }): Ioc[] {
  const found = new Map<string, Ioc>()
  const excluded = new Set(
    (options?.exclude ?? [])
      .filter((value): value is string => typeof value === "string" && value.trim().length > 0)
      .map((value) => value.trim().toLowerCase()),
  )

  const add = (type: IocType, value: string) => {
    if (!value) return
    const normalized = value.trim().toLowerCase()
    if (!normalized) return
    if (excluded.has(normalized)) return
    const key = `${type}:${normalized}`
    if (!found.has(key)) found.set(key, { type, value: normalized })
  }

  for (const match of text.matchAll(URL_RE)) add("url", match[0])
  for (const match of text.matchAll(IPV4_RE)) add("ip", match[0])
  for (const match of text.matchAll(HASH_RE)) {
    const hash = match[0].toLowerCase()
    if (hash.length === 32 || hash.length === 40 || hash.length === 64) add("hash", hash)
  }
  for (const match of text.matchAll(EMAIL_RE)) add("email", match[0])
  // Hosts de todas las URLs: no deben repetirse como dominios aparte (el host
  // ya tiene reputación vía el tipo url/domain de la URL).
  const urlHosts = new Set(
    Array.from(found.values())
      .filter((ioc) => ioc.type === "url")
      .map((ioc) => domainFromUrl(ioc.value))
      .filter((host): host is string => !!host),
  )
  for (const match of text.matchAll(DOMAIN_RE)) {
    const domain = match[0].toLowerCase()
    if (urlHosts.has(domain)) continue
    if (!isRealDomain(domain)) continue
    add("domain", domain)
  }

  return [...found.values()]
}

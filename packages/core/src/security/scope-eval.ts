/**
 * Evaluación de scope determinista y sin I/O.
 *
 * Vive aparte de `gates.ts` porque lo consumen módulos que abren sockets
 * (`security/retest.ts`, `tool/web-browse.ts`): la validación tiene que
 * ejecutarse ANTES de emitir la petición, no después.
 */

export interface ScopePolicy {
  domains?: string[]
  cidrs?: string[]
  excluded?: string[]
  maxRPS?: number
  safeMode?: boolean
}

/**
 * Normaliza un target de red o URL extrayendo el host o dirección IP y subruta.
 */
export function extractTargetHost(target: string): { host: string; path: string } {
  let cleaned = target.trim()
  if (!cleaned.includes("://") && !cleaned.startsWith("/")) {
    cleaned = `http://${cleaned}`
  }
  try {
    const parsed = new URL(cleaned)
    return { host: parsed.hostname.toLowerCase(), path: parsed.pathname }
  } catch {
    const parts = target.split("/")[0].split(":")[0].toLowerCase()
    return { host: parts, path: target.substring(parts.length) }
  }
}

/**
 * Comprueba si un host coincide con un patrón de dominio (soporta *.wildcards).
 */
export function matchesDomainPattern(host: string, pattern: string): boolean {
  const normHost = host.toLowerCase().trim()
  let normPattern = pattern.toLowerCase().trim()
  if (normPattern.includes("://") || (normPattern.includes(":") && !normPattern.includes("/"))) {
    normPattern = extractTargetHost(normPattern).host
  }
  if (normPattern.startsWith("*.")) {
    const base = normPattern.slice(2)
    return normHost === base || normHost.endsWith(`.${base}`)
  }
  return normHost === normPattern
}

function parseIpv4(ip: string): number | null {
  const parts = ip.split(".")
  if (parts.length !== 4) return null
  let num = 0
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return null
    const n = parseInt(part, 10)
    if (n < 0 || n > 255) return null
    num = (num << 8) | n
  }
  return num >>> 0
}

export function matchCidr(ipStr: string, cidrStr: string): boolean {
  const trimmed = cidrStr.trim().toLowerCase()
  const ip = ipStr.trim().toLowerCase()
  const [baseIp, maskStr, extra] = trimmed.split("/")
  if (extra !== undefined) return false

  if (!maskStr) {
    const ipV4 = parseIpv4(ip)
    const baseV4 = parseIpv4(baseIp)
    if (ipV4 !== null || baseV4 !== null) return ipV4 !== null && ipV4 === baseV4

    const ipV6 = parseIpv6(ip)
    const baseV6 = parseIpv6(baseIp)
    return ipV6 !== null && baseV6 !== null && ipV6.every((group, index) => group === baseV6[index])
  }
  if (!/^\d+$/.test(maskStr)) return false
  const maskBits = Number(maskStr)

  if (ip.includes(":") || baseIp.includes(":")) {
    if (maskBits > 128) return false
    const ipGroups = parseIpv6(ip)
    const baseGroups = parseIpv6(baseIp)
    if (!ipGroups || !baseGroups) return false

    const fullGroups = Math.floor(maskBits / 16)
    for (let i = 0; i < fullGroups; i++) {
      if (ipGroups[i] !== baseGroups[i]) return false
    }
    const remainingBits = maskBits % 16
    if (remainingBits === 0) return true
    const mask = (0xffff << (16 - remainingBits)) & 0xffff
    return (ipGroups[fullGroups] & mask) === (baseGroups[fullGroups] & mask)
  }

  if (maskBits > 32) return false
  const ipNum = parseIpv4(ip)
  const baseNum = parseIpv4(baseIp)
  if (ipNum === null || baseNum === null) return false
  if (maskBits === 0) return true
  const mask = (0xffffffff << (32 - maskBits)) >>> 0
  return (ipNum & mask) === (baseNum & mask)
}

export function scopeAllowsPrivateHost(scope: ScopePolicy, host: string): boolean {
  return (scope.cidrs ?? []).some((cidr) => matchCidr(host, cidr))
}

/**
 * Valida determinísticamente si un target está permitido dentro del scope autorizado.
 */
export function evaluateScopeTarget(
  target: string,
  scope?: { domains?: string[]; cidrs?: string[]; excluded?: string[] },
): { allowed: boolean; reason?: string } {
  if (!scope) {
    return { allowed: false, reason: "SCOPE ENFORCEMENT: No authorized scope is configured for this session" }
  }

  const hasDomains = scope.domains && scope.domains.length > 0
  const hasCidrs = scope.cidrs && scope.cidrs.length > 0
  const hasExcluded = scope.excluded && scope.excluded.length > 0

  const { host, path } = extractTargetHost(target)

  // 1. Verificar exclusiones (Out-of-Scope)
  if (hasExcluded) {
    for (const rawExcluded of scope.excluded!) {
      const ex = rawExcluded.trim().toLowerCase()
      if (!ex) continue
      // Si la exclusión es una ruta (ej. /logout, /api/v1/billing/*)
      if (ex.startsWith("/")) {
        const pattern = ex.replace(/\*/g, ".*")
        if (new RegExp(`^${pattern}`).test(path)) {
          return {
            allowed: false,
            reason: `SCOPE ENFORCEMENT: Target path '${path}' is explicitly excluded (${rawExcluded})`,
          }
        }
      } else {
        // Exclusión de host / dominio / IP / bloque CIDR
        if (matchesDomainPattern(host, ex) || host === ex || matchCidr(host, ex)) {
          return {
            allowed: false,
            reason: `SCOPE ENFORCEMENT: Target '${host}' is explicitly excluded from scope (${rawExcluded})`,
          }
        }
      }
    }
  }

  // 2. Sin una lista positiva de dominios o CIDRs no hay alcance autorizado.
  if (!hasDomains && !hasCidrs) {
    return { allowed: false, reason: "SCOPE ENFORCEMENT: No authorized scope is configured for this session" }
  }

  // 3. Comprobar dominios autorizados
  if (hasDomains) {
    for (const domain of scope.domains!) {
      if (matchesDomainPattern(host, domain)) {
        return { allowed: true }
      }
    }
  }

  // 4. Comprobar CIDRs autorizados (soporta máscaras /0 hasta /32 e IPs directas)
  if (hasCidrs) {
    for (const cidr of scope.cidrs!) {
      if (matchCidr(host, cidr)) {
        return { allowed: true }
      }
    }
  }

  return {
    allowed: false,
    reason: `SCOPE ENFORCEMENT: Target '${target}' (${host}) is out of authorized scope`,
  }
}

const HEX_GROUP = /^[0-9a-f]{1,4}$/

/**
 * Convierte una dirección IPv6 a sus 8 grupos de 16 bits. Acepta notación
 * comprimida (`::`), IPv4 embebido (`::ffff:127.0.0.1`), corchetes (`[::1]`) y
 * zone id (`fe80::1%eth0`).
 */
function parseIpv6(input: string): number[] | null {
  let value = input.trim().toLowerCase()
  if (value.startsWith("[") && value.endsWith("]")) value = value.slice(1, -1)
  const zone = value.indexOf("%")
  if (zone !== -1) value = value.slice(0, zone)
  if (!value.includes(":")) return null

  let embedded: number[] | undefined
  const lastColon = value.lastIndexOf(":")
  const tail = value.slice(lastColon + 1)
  if (tail.includes(".")) {
    const v4 = parseIpv4(tail)
    if (v4 === null) return null
    embedded = [(v4 >>> 16) & 0xffff, v4 & 0xffff]
    value = `${value.slice(0, lastColon + 1)}0:0`
  }

  const doubleColon = value.indexOf("::")
  let head: string[]
  let rest: string[]
  if (doubleColon === -1) {
    head = value.split(":")
    rest = []
  } else {
    if (value.indexOf("::", doubleColon + 1) !== -1) return null
    const left = value.slice(0, doubleColon)
    const right = value.slice(doubleColon + 2)
    head = left ? left.split(":") : []
    rest = right ? right.split(":") : []
  }

  const provided = head.length + rest.length
  if (doubleColon === -1 ? provided !== 8 : provided > 7) return null

  const groups: number[] = []
  for (const group of head) {
    if (!HEX_GROUP.test(group)) return null
    groups.push(parseInt(group, 16))
  }
  if (doubleColon !== -1) {
    for (let i = 0; i < 8 - provided; i++) groups.push(0)
  }
  for (const group of rest) {
    if (!HEX_GROUP.test(group)) return null
    groups.push(parseInt(group, 16))
  }
  if (groups.length !== 8) return null
  if (embedded) {
    groups[6] = embedded[0]
    groups[7] = embedded[1]
  }
  return groups
}

/** Rangos IPv4 que nunca deben alcanzarse desde un target de pentest. */
const IPV4_PRIVATE_RANGES: Array<[number, number]> = [
  [0x00000000, 0x00ffffff], // 0.0.0.0/8 — unspecified + "this network"
  [0x0a000000, 0x0affffff], // 10.0.0.0/8 — RFC1918
  [0x7f000000, 0x7fffffff], // 127.0.0.0/8 — loopback
  [0xa9fe0000, 0xa9feffff], // 169.254.0.0/16 — link-local (incluye metadata 169.254.169.254)
  [0xac100000, 0xac1fffff], // 172.16.0.0/12 — RFC1918
  [0xc0a80000, 0xc0a8ffff], // 192.168.0.0/16 — RFC1918
  [0xe0000000, 0xefffffff], // 224.0.0.0/4 — multicast
  [0xf0000000, 0xffffffff], // 240.0.0.0/4 — reservado + broadcast
]

function isPrivateIpv4(num: number): boolean {
  return IPV4_PRIVATE_RANGES.some(([start, end]) => num >= start && num <= end)
}

function isPrivateIpv6(groups: number[]): boolean {
  if (groups.every((group) => group === 0)) return true // :: — unspecified
  if (groups.slice(0, 7).every((group) => group === 0) && groups[7] === 1) return true // ::1 — loopback
  // IPv4-mapped (::ffff:0:0/96) y IPv4-compatible (::/96) se juzgan con las reglas IPv4.
  if (groups.slice(0, 5).every((group) => group === 0) && groups[5] === 0xffff) {
    return isPrivateIpv4(((groups[6] << 16) >>> 0) + groups[7])
  }
  if (groups.slice(0, 6).every((group) => group === 0)) {
    return isPrivateIpv4(((groups[6] << 16) >>> 0) + groups[7])
  }
  if ((groups[0] & 0xfe00) === 0xfc00) return true // fc00::/7 — ULA
  if ((groups[0] & 0xffc0) === 0xfe80) return true // fe80::/10 — link-local
  if ((groups[0] & 0xff00) === 0xff00) return true // ff00::/8 — multicast
  return false
}

/**
 * Indica si un host es una dirección de red privada / local / metadata.
 *
 * Invariante de seguridad: es la puerta que impide que un target de pentest
 * resuelva contra la red interna del operador o contra el endpoint de
 * metadata de la nube (SSRF). Un host que no parsea como IP devuelve `false`:
 * un dominio no es una IP privada (su resolución es un problema aparte).
 */
export function isPrivateAddress(host: string): boolean {
  const value = host.trim().toLowerCase()
  if (!value) return false
  const v4 = parseIpv4(value)
  if (v4 !== null) return isPrivateIpv4(v4)
  const v6 = parseIpv6(value)
  if (v6) return isPrivateIpv6(v6)
  return false
}

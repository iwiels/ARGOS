import { describe, expect, it } from "bun:test"

// Test sanitization and validation helpers used in DialogEditProject
function sanitizeDomain(d: string): string {
  let s = d.trim()
  if (s.includes("://")) {
    try {
      s = new URL(s).hostname
    } catch {
      s = s.replace(/^[a-z]+:\/\//i, "").split("/")[0]
    }
  }
  if (s.endsWith("/")) s = s.slice(0, -1)
  return s
}

function isValidCidrOrIp(entry: string): boolean {
  const trimmed = entry.trim()
  if (!trimmed) return true
  const [ip, mask] = trimmed.split("/")
  const ipv4Parts = ip.split(".")
  if (ipv4Parts.length === 4) {
    const allOctetsValid = ipv4Parts.every((p) => {
      if (!/^\d+$/.test(p)) return false
      const n = Number(p)
      return n >= 0 && n <= 255
    })
    if (!allOctetsValid) return false
    if (mask !== undefined) {
      if (!/^\d+$/.test(mask)) return false
      const m = Number(mask)
      if (m < 0 || m > 32) return false
    }
    return true
  }
  if (ip.includes(":")) {
    if (mask !== undefined) {
      if (!/^\d+$/.test(mask)) return false
      const m = Number(mask)
      if (m < 0 || m > 128) return false
    }
    return true
  }
  return false
}

function parseList(text: string): string[] {
  return Array.from(
    new Set(
      text
        .split(/[\n,]/)
        .map((s) => s.trim())
        .filter((s) => s.length > 0),
    ),
  )
}

describe("DialogEditProject validation & sanitization", () => {
  it("sanitizes full URLs and URLs with paths to hostnames", () => {
    expect(sanitizeDomain("https://sum.unmsm.edu.pe/alumnoWebSum/login")).toBe("sum.unmsm.edu.pe")
    expect(sanitizeDomain("http://api.target.com:8080/")).toBe("api.target.com")
    expect(sanitizeDomain("sub.domain.org/")).toBe("sub.domain.org")
    expect(sanitizeDomain("*.wildcard.com")).toBe("*.wildcard.com")
  })

  it("validates IPv4 addresses and CIDR notations", () => {
    expect(isValidCidrOrIp("192.168.1.1")).toBe(true)
    expect(isValidCidrOrIp("10.0.0.0/8")).toBe(true)
    expect(isValidCidrOrIp("172.16.0.0/16")).toBe(true)
    expect(isValidCidrOrIp("256.1.1.1")).toBe(false)
    expect(isValidCidrOrIp("192.168.1.0/33")).toBe(false)
    expect(isValidCidrOrIp("invalid-ip")).toBe(false)
  })

  it("validates IPv6 addresses and CIDR notations", () => {
    expect(isValidCidrOrIp("::1")).toBe(true)
    expect(isValidCidrOrIp("2001:db8::/32")).toBe(true)
    expect(isValidCidrOrIp("2001:db8::/129")).toBe(false)
  })

  it("parses multiline or comma separated lists without duplicates", () => {
    const raw = "sum.unmsm.edu.pe\napp.target.com, api.target.com\nsum.unmsm.edu.pe"
    const parsed = parseList(raw).map(sanitizeDomain)
    expect(parsed).toEqual(["sum.unmsm.edu.pe", "app.target.com", "api.target.com"])
  })
})

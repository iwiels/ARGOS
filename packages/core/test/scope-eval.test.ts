import { describe, expect, it } from "bun:test"
import { evaluateScopeTarget, matchCidr, scopeAllowsPrivateHost } from "../src/security/scope-eval"

describe("evaluateScopeTarget", () => {
  it("fails closed when no positive scope is configured", () => {
    expect(evaluateScopeTarget("https://example.invalid").allowed).toBe(false)
    expect(evaluateScopeTarget("https://example.invalid", {}).allowed).toBe(false)
  })
})

describe("scopeAllowsPrivateHost", () => {
  it("requires a matching explicit CIDR or IP, not a domain entry", () => {
    expect(scopeAllowsPrivateHost({ domains: ["127.0.0.1"] }, "127.0.0.1")).toBe(false)
    expect(scopeAllowsPrivateHost({ cidrs: ["127.0.0.1"] }, "127.0.0.1")).toBe(true)
    expect(scopeAllowsPrivateHost({ cidrs: ["127.0.0.0/8"] }, "127.0.0.1")).toBe(true)
  })
})

describe("matchCidr IPv6", () => {
  it("matches IPv6 prefixes, equivalent forms, and private network scopes", () => {
    expect(matchCidr("2001:db8::1", "2001:db8::/32")).toBe(true)
    expect(matchCidr("2001:db9::1", "2001:db8::/32")).toBe(false)
    expect(matchCidr("2001:db8::1", "2001:0db8:0:0:0:0:0:1")).toBe(true)
    expect(scopeAllowsPrivateHost({ cidrs: ["fd12:3456::/32"] }, "fd12:3456::5")).toBe(true)
    expect(matchCidr("fd12:3456::5", "fd12:3456::/129")).toBe(false)
    expect(evaluateScopeTarget("http://[fd12:3456::5]/", { cidrs: ["fd12:3456::/32"] }).allowed).toBe(true)
  })
})

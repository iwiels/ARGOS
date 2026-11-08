import { describe, expect, test } from "bun:test"
import { readFileSync } from "node:fs"
import { join } from "node:path"
import {
  canonicalVocabulary,
  cweForTag,
  isCanonicalTag,
  lookupRule,
  severityFloor,
  tagsForRule,
} from "@argos/core/security/contract"

const repoRoot = join(import.meta.dir, "..", "..", "..")
const sourcePath = join(repoRoot, "packages/core/src/security/rules/registry.json")
const mirrorPath = join(repoRoot, "argos-bin/cmd/web/tools/rules/registry.json")

type RegistryRule = {
  id: string
  cwe: string[]
  owasp: string[]
  severity_floor: string
  tags: string[]
  references: string[]
  matcher?: string
}

type Registry = {
  version: string
  vocabulary: string[]
  cwe_by_tag: Record<string, string>
  rules: RegistryRule[]
}

const source = JSON.parse(readFileSync(sourcePath, "utf8")) as Registry

describe("lookupRule", () => {
  test("returns the taxonomy of a known rule", () => {
    const rule = lookupRule("nuclei:generic-env")
    expect(rule).toBeDefined()
    expect(rule!.id).toBe("nuclei:generic-env")
    expect(rule!.cwe).toContain("CWE-522")
    expect(rule!.owasp.length).toBeGreaterThan(0)
    expect(rule!.severityFloor).toBe("high")
    expect(rule!.tags).toContain(".env")
    expect(rule!.references.length).toBeGreaterThan(0)
  })

  test("returns undefined for a rule the registry does not know", () => {
    expect(lookupRule("nuclei:does-not-exist")).toBeUndefined()
    expect(lookupRule("")).toBeUndefined()
    expect(lookupRule("not-a-scanner:rule")).toBeUndefined()
  })

  test("a caller cannot mutate the registry through the returned rule", () => {
    const rule = lookupRule("nuclei:generic-env")!
    rule.tags.push("not-a-real-tag")
    expect(tagsForRule("nuclei:generic-env")).not.toContain("not-a-real-tag")
  })

  test("every rule of the registry resolves", () => {
    for (const rule of source.rules) {
      const found = lookupRule(rule.id)
      expect(found).toBeDefined()
      expect(found!.cwe).toEqual(rule.cwe)
      expect(found!.owasp).toEqual(rule.owasp)
      expect(found!.tags).toEqual(rule.tags)
      expect(found!.references).toEqual(rule.references)
      expect(found!.severityFloor).toBe(rule.severity_floor)
    }
  })
})

describe("severityFloor", () => {
  test("returns the floor of a known rule", () => {
    expect(severityFloor("nuclei:generic-env")).toBe("high")
    expect(severityFloor("nuclei:expired-ssl")).toBe("low")
  })

  test("returns undefined for an unknown rule", () => {
    expect(severityFloor("nuclei:does-not-exist")).toBeUndefined()
  })

  test("every floor is a canonical severity", () => {
    for (const rule of source.rules) {
      expect(["critical", "high", "medium", "low", "info"]).toContain(rule.severity_floor)
    }
  })
})

describe("tagsForRule", () => {
  test("returns the tags of a known rule", () => {
    expect(tagsForRule("nuclei:git-config")).toEqual(["git-exposure", "information-disclosure"])
  })

  test("returns an empty list for an unknown rule", () => {
    expect(tagsForRule("nuclei:does-not-exist")).toEqual([])
  })

  test("every tag belongs to the canonical vocabulary", () => {
    const vocabulary = new Set(canonicalVocabulary())
    for (const rule of source.rules) {
      for (const tag of rule.tags) {
        expect(vocabulary.has(tag)).toBe(true)
      }
    }
  })
})

describe("canonical vocabulary", () => {
  test("is the vocabulary the compliance and ATT&CK engines match on", () => {
    const vocabulary = canonicalVocabulary()
    for (const tag of ["sqli", "xss", "tls", "information-disclosure", "default-credentials", "rce"]) {
      expect(vocabulary).toContain(tag)
      expect(isCanonicalTag(tag)).toBe(true)
    }
    expect(isCanonicalTag("not-a-real-tag")).toBe(false)
  })

  test("matches the vocabulary declared in the registry", () => {
    expect([...canonicalVocabulary()].sort()).toEqual([...source.vocabulary].sort())
  })
})

describe("cweForTag", () => {
  test("maps the canonical tags onto their CWE", () => {
    expect(cweForTag("sqli")).toBe("CWE-89")
    expect(cweForTag("xss")).toBe("CWE-79")
    expect(cweForTag("path-traversal")).toBe("CWE-22")
    expect(cweForTag("ssrf")).toBe("CWE-918")
    expect(cweForTag("command-injection")).toBe("CWE-78")
    expect(cweForTag("information-disclosure")).toBe("CWE-200")
  })

  test("returns undefined for a tag without a CWE", () => {
    expect(cweForTag("not-a-real-tag")).toBeUndefined()
  })
})

// The Go tools read the same registry through a generated mirror. The two must
// resolve the same taxonomy, otherwise a finding would be scored differently
// depending on which side produced it.
describe("Go / TS parity", () => {
  const mirror = JSON.parse(readFileSync(mirrorPath, "utf8")) as Registry

  test("the mirror holds the same rules as the source", () => {
    expect(mirror.rules.length).toBe(source.rules.length)
    expect(mirror.version).toBe(source.version)
  })

  test("every rule resolves identically on both sides", () => {
    for (const rule of source.rules) {
      const mirrored = mirror.rules.find((candidate) => candidate.id === rule.id)
      expect(mirrored).toBeDefined()
      expect(mirrored!.cwe).toEqual(rule.cwe)
      expect(mirrored!.owasp).toEqual(rule.owasp)
      expect(mirrored!.severity_floor).toBe(rule.severity_floor)
      expect(mirrored!.tags).toEqual(rule.tags)
      expect(mirrored!.references).toEqual(rule.references)
    }
  })

  test("the mirror declares the same tag to CWE mapping", () => {
    for (const [tag, cwe] of Object.entries(source.cwe_by_tag)) {
      expect(cweForTag(tag)).toBe(cwe)
    }
  })
})

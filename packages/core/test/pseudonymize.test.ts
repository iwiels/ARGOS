import { describe, expect, it } from "bun:test"
import { Effect } from "effect"
import { Database } from "../src/database/database"
import {
  maskSecrets,
  Pseudonymize,
  SlidingWindowDetokenizer,
} from "../src/security/pseudonymize"

describe("Pseudonymize Engine", () => {
  it("masks sensitive secrets irreversibly", () => {
    const raw = "AWS: AKIAIOSFODNN7EXAMPLE and JWT eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozS6w_token and password: 'SuperSecretPassword123!'"
    const masked = maskSecrets(raw)

    expect(masked).not.toContain("AKIAIOSFODNN7EXAMPLE")
    expect(masked).not.toContain("eyJhbGci")
    expect(masked).not.toContain("SuperSecretPassword123!")
    expect(masked).toContain("[SECRET-REDACTED]")
  })

  it("allocates and tokenizes IPs, emails, CIDRs, and target domains", async () => {
    const program = Effect.gen(function* () {
      const engagementId = "eng_test_1"
      yield* Pseudonymize.seedTargetScope(engagementId, "https://example.org")

      const input = "Target host 192.0.2.137 and subnet 192.0.2.0/24 with admin@example.org on www.example.org"
      const tokenized = yield* Pseudonymize.tokenizeText(engagementId, input)

      expect(tokenized).not.toContain("192.0.2.137")
      expect(tokenized).not.toContain("192.0.2.0/24")
      expect(tokenized).not.toContain("admin@example.org")
      expect(tokenized).not.toContain("example.org")

      expect(tokenized).toContain("ZXIP")
      expect(tokenized).toContain("ZXCIDR")
      expect(tokenized).toContain("ZXMAIL")
      expect(tokenized).toContain("ZXDOM")

      const detokenized = yield* Pseudonymize.detokenizeText(engagementId, tokenized)
      expect(detokenized).toContain("192.0.2.137")
      expect(detokenized).toContain("192.0.2.0/24")
      expect(detokenized).toContain("admin@example.org")
      expect(detokenized).toContain("example.org")
    })

    await Effect.runPromise(program.pipe(Effect.provide(Database.defaultLayer)))
  })

  it("handles SlidingWindowDetokenizer across fragmented stream chunks", () => {
    const mappings: Record<string, string> = {
      ZXDOM001: "example.org",
      ZXIP001: "198.51.100.158",
    }
    const detokenizer = new SlidingWindowDetokenizer((token) => mappings[token])

    // Simulate streaming chunks where tokens are split right in the middle
    const chunk1 = "Connecting to ZXDO"
    const chunk2 = "M001 on port 443 with IP ZXI"
    const chunk3 = "P001 confirmed."

    let output = ""
    output += detokenizer.processChunk(chunk1)
    output += detokenizer.processChunk(chunk2)
    output += detokenizer.processChunk(chunk3)
    output += detokenizer.flush()

    expect(output).toBe("Connecting to example.org on port 443 with IP 198.51.100.158 confirmed.")
  })
})

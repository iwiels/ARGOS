import { describe, expect, it } from "bun:test"
import { evaluatePocSafety, generateCurlCommand } from "@argos/core/security/poc"

describe("PoC Verification & Safe Exploitation Engine", () => {
  describe("evaluatePocSafety", () => {
    it("flags destructive SQL injection payloads as unsafe", () => {
      const dropTest = evaluatePocSafety({
        target: "https://api.example.com/items",
        payload: "1'; DROP TABLE users; --",
        method: "POST",
      })
      expect(dropTest.safe).toBe(false)
      expect(dropTest.category).toBe("destructive")
      expect(dropTest.reason).toContain("Destructive payload pattern detected")

      const deleteTest = evaluatePocSafety({
        target: "https://api.example.com/items?id=1; DELETE FROM audit_log",
      })
      expect(deleteTest.safe).toBe(false)
      expect(deleteTest.category).toBe("destructive")
    })

    it("flags remote code execution / destructive commands as unsafe", () => {
      const cmdTest = evaluatePocSafety({
        target: "https://api.example.com/run",
        payload: "file.txt; rm -rf /var/www",
        method: "POST",
      })
      expect(cmdTest.safe).toBe(false)
      expect(cmdTest.category).toBe("destructive")
    })

    it("classifies non-destructive timing payloads as safe-timing", () => {
      const sleepTest = evaluatePocSafety({
        target: "https://api.example.com/user",
        payload: "1' AND (SELECT 1 FROM (SELECT(SLEEP(2)))a)--",
      })
      expect(sleepTest.safe).toBe(true)
      expect(sleepTest.category).toBe("safe-timing")
    })

    it("classifies boolean payloads as safe-boolean", () => {
      const boolTest = evaluatePocSafety({
        target: "https://api.example.com/login",
        payload: "admin' OR '1'='1",
      })
      expect(boolTest.safe).toBe(true)
      expect(boolTest.category).toBe("safe-boolean")
    })

    it("classifies benign XSS alerts and SSTI expressions as safe-echo", () => {
      const xssTest = evaluatePocSafety({
        target: "https://api.example.com/search?q=<script>alert(1)</script>",
      })
      expect(xssTest.safe).toBe(true)
      expect(xssTest.category).toBe("safe-echo")

      const sstiTest = evaluatePocSafety({
        target: "https://api.example.com/template",
        payload: "{{7*7}}",
        method: "POST",
      })
      expect(sstiTest.safe).toBe(true)
      expect(sstiTest.category).toBe("safe-echo")
    })
  })

  describe("generateCurlCommand", () => {
    it("builds reproducible cURL commands with headers and payload", () => {
      const curl = generateCurlCommand({
        target: "https://api.example.com/v1/auth",
        method: "POST",
        payload: '{"username":"admin\' OR 1=1--"}',
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer test_token",
        },
      })

      expect(curl).toContain('curl -i -s -k -X POST "https://api.example.com/v1/auth"')
      expect(curl).toContain('-H "Content-Type: application/json"')
      expect(curl).toContain('-H "Authorization: Bearer test_token"')
      expect(curl).toContain("--data-raw '{\"username\":\"admin\\' OR 1=1--\"}'")
    })
  })
})

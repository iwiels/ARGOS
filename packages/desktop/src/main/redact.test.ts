import { describe, expect, test } from "bun:test"
import { isRedactableFile, redactSecrets } from "./redact"

describe("redactSecrets", () => {
  test("redacta auth_token en query strings (PTY/terminal)", () => {
    const line = `[pty] connect ws://127.0.0.1:4096/pty/abc/connect-token?auth_token=eyJhbGciOiJIUzI1NiJ9.x.y&cols=80`
    expect(redactSecrets(line)).toBe(
      `[pty] connect ws://127.0.0.1:4096/pty/abc/connect-token?auth_token=[REDACTED]&cols=80`,
    )
  })

  test("redacta Authorization Bearer y x-api-key", () => {
    expect(redactSecrets(`"Authorization": "Bearer sk-abcdef1234567890"`)).toBe(
      `"Authorization": "Bearer [REDACTED]"`.replace("sk-", ""),
    )
    expect(redactSecrets("x-api-key: AIzaSyD-1234567890")).toBe("x-api-key: [REDACTED]")
  })

  test("redacta campos JSON de credenciales", () => {
    const json = `{"http":{"url":"http://10.0.0.5:4096","password":"s3cr3t-pass"},"user":"ana"}`
    expect(redactSecrets(json)).toBe(`{"http":{"url":"http://10.0.0.5:4096","password":"[REDACTED]"},"user":"ana"}`)
  })

  test("redacta basic-auth embebido en URL", () => {
    expect(redactSecrets(`GET https://user:p4ss@host.local/api HTTP/1.1`)).toBe(
      `GET https://user:[REDACTED]@host.local/api HTTP/1.1`,
    )
  })

  test("no toca contenido benigno", () => {
    const line = `[main] session ses_abc123 started in C:\\proj`
    expect(redactSecrets(line)).toBe(line)
  })
})

describe("isRedactableFile", () => {
  test("archivos de texto sí", () => {
    expect(isRedactableFile("desktop/main.log")).toBe(true)
    expect(isRedactableFile("server-1/settings.json")).toBe(true)
    expect(isRedactableFile("trace.ndjson")).toBe(true)
  })

  test("binarios no", () => {
    expect(isRedactableFile("crashpad/report.dmp")).toBe(false)
    expect(isRedactableFile("network.netlog")).toBe(false)
  })
})

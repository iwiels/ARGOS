import { describe, expect, test } from "bun:test"
import {
  canUseSecurePasswordStorage,
  protectServerPasswords,
  revealServerPasswords,
  SERVER_PASSWORD_MARK,
  type PasswordCrypt,
} from "./secure-fields"

const b64: PasswordCrypt = {
  encrypt: (plain) => SERVER_PASSWORD_MARK + Buffer.from(plain, "utf8").toString("base64"),
  decrypt: (stored) => {
    if (!stored.startsWith(SERVER_PASSWORD_MARK)) return stored
    try {
      return Buffer.from(stored.slice(SERVER_PASSWORD_MARK.length), "base64").toString("utf8")
    } catch {
      return null
    }
  },
}

const blob = {
  list: [
    { type: "sidecar", http: { url: "http://127.0.0.1:4096", username: "local", password: "s3cret" } },
    { url: "https://siem.cliente.local:9200", username: "auditor", password: "p@ss2" },
    { url: "https://sin-password.local" },
  ],
  projects: {},
}

describe("protectServerPasswords", () => {
  test("cifra solo los password de objetos con url, en cualquier profundidad", () => {
    const out = protectServerPasswords(blob, b64)
    const sidecar = (out.list as any[])[0].http.password as string
    const remote = (out.list as any[])[1].password as string

    expect(sidecar.startsWith(SERVER_PASSWORD_MARK)).toBe(true)
    expect(sidecar).not.toContain("s3cret")
    expect(remote.startsWith(SERVER_PASSWORD_MARK)).toBe(true)
    expect(remote).not.toContain("p@ss2")
    expect((out.list as any[])[2].password).toBeUndefined()
    expect((out.list as any[])[0].http.url).toBe("http://127.0.0.1:4096")
  })

  test("permite guardar solo con almacenamiento del sistema protegido", () => {
    expect(canUseSecurePasswordStorage({ platform: "win32", available: true })).toBe(true)
    expect(canUseSecurePasswordStorage({ platform: "darwin", available: true })).toBe(true)
    expect(
      canUseSecurePasswordStorage({ platform: "linux", available: true, backend: "gnome_libsecret" }),
    ).toBe(true)
    expect(canUseSecurePasswordStorage({ platform: "linux", available: true, backend: "basic_text" })).toBe(false)
    expect(canUseSecurePasswordStorage({ platform: "linux", available: true, backend: "unknown" })).toBe(false)
    expect(canUseSecurePasswordStorage({ platform: "linux", available: false, backend: "kwallet6" })).toBe(false)
  })

  test("deja intacto lo que no es servidor", () => {
    const value = { settings: { password: "no-tocar" }, list: [] }
    const out = protectServerPasswords(value, b64)
    expect((out.settings as any).password).toBe("no-tocar")
  })

  test("no re-cifra un valor ya marcado", () => {
    const once = protectServerPasswords({ list: [{ url: "x", password: "a" }] }, b64)
    const twice = protectServerPasswords(once, b64)
    expect(twice).toEqual(once)
  })

  test("crypt que falla (null) rechaza el guardado en vez de conservar plaintext", () => {
    const failing: PasswordCrypt = { encrypt: () => null, decrypt: () => null }
    expect(() => protectServerPasswords(blob, failing)).toThrow("Secure storage is unavailable")
  })
})

describe("revealServerPasswords", () => {
  test("invierte lo cifrado y pasa through valores legacy sin marca", () => {
    const protected_ = protectServerPasswords(blob, b64)
    const revealed = revealServerPasswords(protected_, b64)
    expect(revealed).toEqual(blob)
  })

  test("decrypt roto devuelve null sin lanzar", () => {
    const broken: PasswordCrypt = { encrypt: (plain) => b64.encrypt(plain), decrypt: () => null }
    const protected_ = protectServerPasswords(blob, b64)
    const revealed = revealServerPasswords(protected_, broken)
    expect((revealed.list as any[])[1].password).toBeNull()
  })
})

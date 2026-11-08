/**
 * At-rest protection for server credentials inside the persisted server list
 * (`opencode.global.dat` -> key `server`).
 *
 * Pure JSON walk: encryption itself is injected so this module stays free of
 * electron imports and can be unit-tested directly (same pattern as
 * cors-headers.ts).
 *
 * Shape-aware: only objects that look like a server connection (have a
 * string `url`) get their `password` field rewritten. Everything else is
 * traversed untouched, so unrelated settings in the same blob are never
 * transformed.
 */

export const SERVER_PASSWORD_MARK = "enc:v1:"
export const SECURE_STORAGE_UNAVAILABLE = "Secure storage is unavailable. Passwords were not saved."

const linuxSecureBackends = new Set(["gnome_libsecret", "kwallet", "kwallet5", "kwallet6"])

export function canUseSecurePasswordStorage(input: {
  platform: string
  available: boolean
  backend?: string
}): boolean {
  if (!input.available) return false
  if (input.platform !== "linux") return true
  return input.backend !== undefined && linuxSecureBackends.has(input.backend)
}

export type PasswordCrypt = {
  /** Returns marked ciphertext, or null when encryption is unavailable. */
  encrypt(plain: string): string | null
  /** Returns plaintext from a marked value; null on failure. */
  decrypt(stored: string): string | null
}

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value)

const isServerNode = (value: Record<string, unknown>) => typeof value.url === "string"

function rewrite(
  value: unknown,
  transformPassword: (node: Record<string, unknown>, password: string) => void,
): unknown {
  if (Array.isArray(value)) return value.map((entry) => rewrite(entry, transformPassword))
  if (!isPlainObject(value)) return value

  const next: Record<string, unknown> = { ...value }
  if (isServerNode(next)) {
    const password = next.password
    if (typeof password === "string" && password.length > 0) transformPassword(next, password)
  }
  for (const key of Object.keys(next)) {
    const child = next[key]
    if (isPlainObject(child) || Array.isArray(child)) next[key] = rewrite(child, transformPassword)
  }
  return next
}

/** Encrypts every server password found in the parsed JSON value. */
export function protectServerPasswords<T>(value: T, crypt: PasswordCrypt): T {
  return rewrite(value, (node, password) => {
    if (password.startsWith(SERVER_PASSWORD_MARK)) return
    const encrypted = crypt.encrypt(password)
    if (!encrypted) throw new Error(SECURE_STORAGE_UNAVAILABLE)
    node.password = encrypted
  }) as T
}

/** Restores plaintext passwords (marked values only) from a parsed JSON value. */
export function revealServerPasswords<T>(value: T, crypt: PasswordCrypt): T {
  return rewrite(value, (node, stored) => {
    if (!stored.startsWith(SERVER_PASSWORD_MARK)) return
    node.password = crypt.decrypt(stored)
  }) as T
}

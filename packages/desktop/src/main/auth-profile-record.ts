const PROFILE_ID = /^auth_[A-Fa-f0-9]{32}$/
const SESSION_ID = /^[A-Za-z0-9_-]{1,128}$/
const MAX_RECORD_BYTES = 512 * 1024

export type AuthProfileInput = {
  id?: string
  sessionID: string
  name: string
  username: string
  password: string
  userSelector?: string
  passwordSelector?: string
  submitSelector?: string
  successSelector?: string
}

export type AuthProfileRecord = AuthProfileInput & { id: string; version: 1; storageState?: object }
export type AuthProfileMetadata = { id: string; name: string; username: string; hasBrowserSession: boolean }

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

function optionalString(value: unknown, maximum: number) {
  return value === undefined || (typeof value === "string" && value.length <= maximum)
}

export function validAuthProfileID(value: string): boolean {
  return PROFILE_ID.test(value)
}

export function validateAuthProfileInput(value: unknown): asserts value is AuthProfileInput {
  if (!isObject(value)) throw new Error("Invalid authentication profile")
  if (
    typeof value.sessionID !== "string" ||
    !SESSION_ID.test(value.sessionID) ||
    typeof value.name !== "string" ||
    !value.name.trim() ||
    value.name.length > 120 ||
    typeof value.username !== "string" ||
    !value.username ||
    value.username.length > 4096 ||
    typeof value.password !== "string" ||
    !value.password ||
    value.password.length > 4096 ||
    (value.id !== undefined && (typeof value.id !== "string" || !validAuthProfileID(value.id))) ||
    !optionalString(value.userSelector, 512) ||
    !optionalString(value.passwordSelector, 512) ||
    !optionalString(value.submitSelector, 512) ||
    !optionalString(value.successSelector, 512)
  ) {
    throw new Error("Invalid authentication profile")
  }
}

export function createAuthProfileRecord(input: AuthProfileInput, id: string): AuthProfileRecord {
  validateAuthProfileInput(input)
  if (!validAuthProfileID(id)) throw new Error("Invalid authentication profile ID")
  return {
    id,
    version: 1,
    sessionID: input.sessionID,
    name: input.name,
    username: input.username,
    password: input.password,
    userSelector: input.userSelector,
    passwordSelector: input.passwordSelector,
    submitSelector: input.submitSelector,
    successSelector: input.successSelector,
  }
}

export function parseAuthProfileRecord(raw: string, id: string): AuthProfileRecord | null {
  if (!validAuthProfileID(id) || new TextEncoder().encode(raw).byteLength > MAX_RECORD_BYTES) return null
  try {
    const value: unknown = JSON.parse(raw)
    if (!isObject(value) || value.id !== id || value.version !== 1) return null
    validateAuthProfileInput(value)
    const fields = value as unknown as Record<string, unknown>
    if (
      fields.storageState !== undefined &&
      (!isObject(fields.storageState) || new TextEncoder().encode(JSON.stringify(fields.storageState)).byteLength > MAX_RECORD_BYTES)
    ) {
      return null
    }
    const profile = createAuthProfileRecord(value, id)
    if (fields.storageState !== undefined) profile.storageState = fields.storageState as object
    return profile
  } catch {
    return null
  }
}

export function authProfileMetadata(profile: AuthProfileRecord): AuthProfileMetadata {
  return {
    id: profile.id,
    name: profile.name,
    username: profile.username,
    hasBrowserSession: !!profile.storageState,
  }
}

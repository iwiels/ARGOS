import { randomUUID } from "node:crypto"
import { networkInterfaces } from "node:os"
import { safeStorage } from "electron"
import { canUseSecurePasswordStorage, SECURE_STORAGE_UNAVAILABLE } from "./secure-fields"
import { getStore } from "./store"
import { createAuthVaultBridge, wslHostAddresses } from "./auth-vault-http"
import {
  authProfileMetadata,
  createAuthProfileRecord,
  parseAuthProfileRecord,
  validAuthProfileID,
  validateAuthProfileInput,
  type AuthProfileInput,
  type AuthProfileMetadata,
  type AuthProfileRecord,
} from "./auth-profile-record"

const AUTH_SECRET_MARK = "argos-auth:v1:"
const AUTH_VAULT_STORE = "argos.auth.vault"

function authVaultBackend() {
  const store = getStore(AUTH_VAULT_STORE)
  const isAvailable = () => {
    try {
      return canUseSecurePasswordStorage({
        platform: process.platform,
        available: safeStorage.isEncryptionAvailable(),
        backend: process.platform === "linux" ? safeStorage.getSelectedStorageBackend() : undefined,
      })
    } catch {
      return false
    }
  }
  return {
    store,
    isAvailable,
    get: (id: string) => {
      const stored = store.get(`secret.${id}`)
      if (typeof stored !== "string" || !stored.startsWith(AUTH_SECRET_MARK)) return null
      try {
        return safeStorage.decryptString(Buffer.from(stored.slice(AUTH_SECRET_MARK.length), "base64"))
      } catch {
        throw new Error(SECURE_STORAGE_UNAVAILABLE)
      }
    },
    set: (id: string, value: string) => {
      if (!isAvailable()) throw new Error(SECURE_STORAGE_UNAVAILABLE)
      try {
        const encrypted = safeStorage.encryptString(value).toString("base64")
        store.set(`secret.${id}`, `${AUTH_SECRET_MARK}${encrypted}`)
      } catch {
        throw new Error(SECURE_STORAGE_UNAVAILABLE)
      }
    },
    delete: (id: string) => store.delete(`secret.${id}`),
  }
}

function profileRecord(backend: ReturnType<typeof authVaultBackend>, id: string) {
  const raw = backend.get(id)
  if (!raw) return null
  return parseAuthProfileRecord(raw, id)
}

export function listAuthProfiles(sessionID: string): AuthProfileMetadata[] {
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(sessionID)) throw new Error("Invalid session ID")
  const backend = authVaultBackend()
  if (!backend.isAvailable()) throw new Error(SECURE_STORAGE_UNAVAILABLE)
  return Object.keys(backend.store.store)
    .filter((key) => key.startsWith("secret."))
    .map((key) => key.slice("secret.".length))
    .flatMap((id) => {
      const profile = validAuthProfileID(id) ? profileRecord(backend, id) : null
      return !profile || profile.sessionID !== sessionID
        ? []
        : [authProfileMetadata(profile)]
    })
    .sort((a, b) => a.name.localeCompare(b.name))
}

export function saveAuthProfile(input: AuthProfileInput): AuthProfileMetadata {
  validateAuthProfileInput(input)
  const backend = authVaultBackend()
  if (!backend.isAvailable()) throw new Error(SECURE_STORAGE_UNAVAILABLE)
  const id = input.id ?? `auth_${randomUUID().replaceAll("-", "")}`
  if (!validAuthProfileID(id)) throw new Error("Invalid authentication profile ID")
  if (input.id) {
    const existing = profileRecord(backend, id)
    if (!existing || existing.sessionID !== input.sessionID) throw new Error("Authentication profile is unavailable")
  }
  const record: AuthProfileRecord = createAuthProfileRecord(input, id)
  backend.set(id, JSON.stringify(record))
  return authProfileMetadata(record)
}

export function deleteAuthProfile(sessionID: string, id: string) {
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(sessionID) || !validAuthProfileID(id)) throw new Error("Invalid authentication profile")
  const backend = authVaultBackend()
  if (!backend.isAvailable()) throw new Error(SECURE_STORAGE_UNAVAILABLE)
  const profile = profileRecord(backend, id)
  if (!profile || profile.sessionID !== sessionID) throw new Error("Authentication profile is unavailable")
  backend.delete(id)
}

export async function startAuthVaultBridge(input: { wslHost?: boolean } = {}) {
  const backend = authVaultBackend()
  const hosts = input.wslHost && process.platform === "win32" ? wslHostAddresses(networkInterfaces()) : []
  return createAuthVaultBridge({ backend, hosts })
}

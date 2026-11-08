import { isIP } from "node:net"
import { Context, Effect, Layer } from "effect"
import { isPrivateAddress } from "./scope-eval"

const UNAVAILABLE = "secure vault is unavailable"
const SECRET_ID = /^auth_[a-fA-F0-9]{32}$/
const REQUEST_TIMEOUT_MS = 5_000

export interface AuthSecretVaultClient {
  get(id: string): Promise<string | null>
  put(id: string, value: string): Promise<void>
  delete(id: string): Promise<void>
}

export interface AuthSecretVaultService {
  get(id: string): Effect.Effect<string | null, Error>
  put(id: string, value: string): Effect.Effect<void, Error>
  delete(id: string): Effect.Effect<void, Error>
}

export class Service extends Context.Service<Service, AuthSecretVaultService>()("@argos/security/AuthSecretVault") {}

type Fetcher = (input: URL, init?: RequestInit) => Promise<Response>

function validEndpoint(raw: string): URL | undefined {
  try {
    const url = new URL(raw)
    const host = url.hostname.replace(/^\[|\]$/g, "")
    if (
      url.protocol !== "http:" ||
      url.username ||
      url.password ||
      url.pathname !== "/" ||
      url.search ||
      url.hash ||
      isIP(host) === 0 ||
      !isPrivateAddress(host)
    ) {
      return undefined
    }
    return url
  } catch {
    return undefined
  }
}

function unavailable(): Error {
  return new Error(UNAVAILABLE)
}

function validateID(id: string) {
  if (!SECRET_ID.test(id)) throw unavailable()
}

export function makeClient(input: { urls: string[]; token: string; fetcher?: Fetcher }): AuthSecretVaultClient {
  const endpoints = input.urls.map(validEndpoint).filter((url): url is URL => url !== undefined)
  const token = input.token
  const fetcher = input.fetcher ?? fetch

  async function request(id: string, method: "GET" | "PUT" | "DELETE", value?: string) {
    validateID(id)
    if (!token || endpoints.length === 0) throw unavailable()

    for (const endpoint of endpoints) {
      const url = new URL(`/v1/secrets/${encodeURIComponent(id)}`, endpoint)
      const controller = new AbortController()
      const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS)
      let response: Response
      try {
        response = await fetcher(url, {
          method,
          headers: {
            authorization: `Bearer ${token}`,
            ...(value === undefined ? {} : { "content-type": "application/json" }),
          },
          ...(value === undefined ? {} : { body: JSON.stringify({ value }) }),
          cache: "no-store",
          redirect: "error",
          signal: controller.signal,
        })
      } catch {
        continue
      } finally {
        clearTimeout(timeout)
      }

      if (method === "GET" && response.status === 404) return null
      if (method === "GET" && response.status === 200) {
        try {
          const body: unknown = await response.json()
          if (body && typeof body === "object" && typeof (body as { value?: unknown }).value === "string") {
            return (body as { value: string }).value
          }
        } catch {
          throw unavailable()
        }
        throw unavailable()
      }
      if ((method === "PUT" || method === "DELETE") && (response.status === 204 || response.status === 200)) {
        return null
      }
      throw unavailable()
    }

    throw unavailable()
  }

  return {
    get: async (id) => await request(id, "GET"),
    put: async (id, value) => {
      await request(id, "PUT", value)
    },
    delete: async (id) => {
      await request(id, "DELETE")
    },
  }
}

export function clientFromEnvironment(env: Record<string, string | undefined> = process.env): AuthSecretVaultClient {
  let urls: string[] = []
  try {
    const parsed: unknown = JSON.parse(env.ARGOS_AUTH_VAULT_URLS ?? "[]")
    if (Array.isArray(parsed) && parsed.every((entry) => typeof entry === "string")) urls = parsed
  } catch {}
  return makeClient({ urls, token: env.ARGOS_AUTH_VAULT_TOKEN ?? "" })
}

function effectService(client: AuthSecretVaultClient): AuthSecretVaultService {
  return {
    get: (id) => Effect.tryPromise({ try: () => client.get(id), catch: () => unavailable() }),
    put: (id, value) => Effect.tryPromise({ try: () => client.put(id, value), catch: () => unavailable() }),
    delete: (id) => Effect.tryPromise({ try: () => client.delete(id), catch: () => unavailable() }),
  }
}

export const layer = Layer.succeed(Service, effectService(clientFromEnvironment()))

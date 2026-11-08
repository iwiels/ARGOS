import { randomBytes, timingSafeEqual } from "node:crypto"
import { isIP } from "node:net"
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http"

const MAX_SECRET_BYTES = 512 * 1024
const ID_PATTERN = /^auth_[A-Fa-f0-9]{32}$/

export type AuthVaultBackend = {
  isAvailable: () => boolean
  get: (id: string) => string | null
  set: (id: string, value: string) => void
  delete: (id: string) => void
}

export type AuthVaultBridge = {
  urls: string[]
  token: string
  close: () => Promise<void>
}

export function authVaultEnvironment(bridge: Pick<AuthVaultBridge, "urls" | "token">) {
  return {
    ARGOS_AUTH_VAULT_URLS: JSON.stringify(bridge.urls),
    ARGOS_AUTH_VAULT_TOKEN: bridge.token,
  }
}

export function authVaultNoProxy(bridge: Pick<AuthVaultBridge, "urls">) {
  return [...new Set(bridge.urls.flatMap((raw) => {
    try {
      const host = new URL(raw).hostname.replace(/^\[|\]$/g, "")
      return host ? [host] : []
    } catch {
      return []
    }
  }))].join(",")
}

function isPrivateIPv4(address: string) {
  const octets = address.split(".").map(Number)
  if (octets.length !== 4 || octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) return false
  const [first, second] = octets
  return (
    first === 10 ||
    first === 127 ||
    (first === 169 && second === 254) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168)
  )
}

export function wslHostAddresses(
  interfaces: Record<string, Array<{ address: string; family: number | string; internal: boolean }> | undefined>,
) {
  return [
    ...new Set(
      Object.entries(interfaces)
        .filter(([name]) => /wsl/i.test(name))
        .flatMap(([, entries]) =>
          (entries ?? [])
            .filter(
              (entry) =>
                (entry.family === 4 || entry.family === "IPv4") &&
                !entry.internal &&
                isIP(entry.address) === 4 &&
                isPrivateIPv4(entry.address),
            )
            .map((entry) => entry.address),
        ),
    ),
  ]
}

function json(response: ServerResponse, status: number, value: unknown) {
  response.writeHead(status, {
    "cache-control": "no-store",
    "content-type": "application/json; charset=utf-8",
  })
  response.end(JSON.stringify(value))
}

function noContent(response: ServerResponse) {
  response.writeHead(204, { "cache-control": "no-store" })
  response.end()
}

function authenticated(request: IncomingMessage, token: string) {
  const authorization = request.headers.authorization
  if (typeof authorization !== "string" || !authorization.startsWith("Bearer ")) return false
  const expected = Buffer.from(token)
  const actual = Buffer.from(authorization.slice(7))
  return expected.length === actual.length && timingSafeEqual(expected, actual)
}

function readJson(request: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let length = 0
    let oversized = false
    request.on("data", (chunk: Buffer | string) => {
      if (oversized) return
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
      length += buffer.byteLength
      if (length > MAX_SECRET_BYTES) {
        oversized = true
        chunks.length = 0
        return
      }
      chunks.push(buffer)
    })
    request.on("end", () => {
      if (oversized) {
        reject(new RangeError("Secret payload is too large"))
        return
      }
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")))
      } catch {
        reject(new SyntaxError("Invalid JSON payload"))
      }
    })
    request.on("error", reject)
  })
}

function handleRequest(request: IncomingMessage, response: ServerResponse, input: { token: string; backend: AuthVaultBackend }) {
  if (!authenticated(request, input.token)) {
    json(response, 401, { error: "Unauthorized" })
    return
  }

  let url: URL
  try {
    url = new URL(request.url ?? "/", "http://localhost")
  } catch {
    json(response, 400, { error: "Invalid request" })
    return
  }

  const match = /^\/v1\/secrets\/([^/]+)$/.exec(url.pathname)
  if (!match) {
    json(response, 404, { error: "Not found" })
    return
  }

  let id: string
  try {
    id = decodeURIComponent(match[1])
  } catch {
    json(response, 400, { error: "Invalid secret ID" })
    return
  }
  if (!ID_PATTERN.test(id)) {
    json(response, 400, { error: "Invalid secret ID" })
    return
  }

  if (!input.backend.isAvailable()) {
    json(response, 503, { error: "Secure storage is unavailable" })
    return
  }

  if (request.method === "GET") {
    try {
      const value = input.backend.get(id)
      if (value === null) {
        json(response, 404, { error: "Secret not found" })
        return
      }
      json(response, 200, { value })
    } catch {
      json(response, 503, { error: "Secure storage is unavailable" })
    }
    return
  }

  if (request.method === "DELETE") {
    try {
      input.backend.delete(id)
      noContent(response)
    } catch {
      json(response, 503, { error: "Secure storage is unavailable" })
    }
    return
  }

  if (request.method !== "PUT") {
    response.setHeader("allow", "GET, PUT, DELETE")
    json(response, 405, { error: "Method not allowed" })
    return
  }

  const contentType = request.headers["content-type"]
  if (typeof contentType !== "string" || !contentType.toLowerCase().startsWith("application/json")) {
    json(response, 415, { error: "Content type must be application/json" })
    return
  }

  const contentLength = Number(request.headers["content-length"] ?? 0)
  if (Number.isFinite(contentLength) && contentLength > MAX_SECRET_BYTES) {
    json(response, 413, { error: "Secret payload is too large" })
    request.resume()
    return
  }

  void readJson(request)
    .then((body) => {
      if (!body || typeof body !== "object" || Array.isArray(body) || typeof (body as { value?: unknown }).value !== "string") {
        json(response, 400, { error: "Expected a string secret value" })
        return
      }
      const value = (body as { value: string }).value
      if (Buffer.byteLength(value, "utf8") > MAX_SECRET_BYTES) {
        json(response, 413, { error: "Secret payload is too large" })
        return
      }
      try {
        input.backend.set(id, value)
        noContent(response)
      } catch {
        json(response, 503, { error: "Secure storage is unavailable" })
      }
    })
    .catch((error: unknown) => {
      if (error instanceof RangeError) {
        json(response, 413, { error: "Secret payload is too large" })
        return
      }
      json(response, 400, { error: "Invalid JSON payload" })
    })
}

function closeServer(server: Server) {
  return new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()))
    server.closeAllConnections()
  })
}

function endpoint(host: string, port: number) {
  const formattedHost = isIP(host) === 6 ? `[${host}]` : host
  return `http://${formattedHost}:${port}`
}

export async function createAuthVaultBridge(input: {
  backend: AuthVaultBackend
  hosts?: string[]
}): Promise<AuthVaultBridge> {
  const token = randomBytes(32).toString("base64url")
  const hosts = [...new Set(["127.0.0.1", ...(input.hosts ?? [])])].filter((host) => isIP(host) !== 0)
  const servers: Server[] = []
  const urls: string[] = []

  for (const host of hosts) {
    const server = createServer((request, response) => handleRequest(request, response, { token, backend: input.backend }))
    server.requestTimeout = 10_000
    server.headersTimeout = 5_000
    try {
      const port = await new Promise<number>((resolve, reject) => {
        server.once("error", reject)
        server.listen(0, host, () => {
          server.off("error", reject)
          const address = server.address()
          if (!address || typeof address === "string") {
            reject(new Error("Auth vault listener did not receive an IP address"))
            return
          }
          resolve(address.port)
        })
      })
      servers.push(server)
      urls.push(endpoint(host, port))
    } catch (error) {
      try {
        server.close()
      } catch {}
      if (host === "127.0.0.1") {
        await Promise.all(servers.map(closeServer))
        throw error
      }
    }
  }

  let closed: Promise<void> | undefined

  return {
    urls,
    token,
    close: () => {
      if (!closed) closed = Promise.all(servers.map(closeServer)).then(() => undefined)
      return closed
    },
  }
}

import { AsyncLocalStorage } from "node:async_hooks"
import { isIP } from "node:net"
import { eq } from "drizzle-orm"
import { Effect, Semaphore } from "effect"
import type { Database } from "../../database/database"
import { SessionTable } from "../../session/sql"
import { SessionSchema } from "../../session/schema"
import { Message, LLMEvent, type ContentPart } from "@argos/llm"
import { EngagementPseudonymTable, PseudonymTable } from "./sql"

export { PseudonymTable, EngagementPseudonymTable }

/**
 * Propagates the current engagement/session ID across the async call chain
 * from `session/runner/llm.ts` (where it's known) down into `aisdk.ts`'s
 * fetch wrapper (which has no session context of its own), so the outgoing
 * HTTP request to the local LLM proxy can carry a deterministic
 * `x-engagement-id` header instead of relying on regex-guessing it from the
 * request body on the proxy side.
 */
export namespace EngagementContext {
  const storage = new AsyncLocalStorage<string>()

  export const run = <T>(engagementId: string, fn: () => T): T => storage.run(engagementId, fn)

  /**
   * Binds the engagement ID to the current async execution context for
   * everything scheduled from this point forward (no callback to wrap around
   * — needed because the turn's Effect program hasn't kicked off the actual
   * provider `fetch` yet when the session ID first becomes known).
   */
  export const enter = (engagementId: string): void => storage.enterWith(engagementId)

  export const current = (): string | undefined => storage.getStore()
}

export type EntityType = "ip" | "cidr" | "domain" | "email" | "username"
export type DatabaseInstance = Database.Interface["db"]

/**
 * The only providers real LLM traffic is allowed to reach. Anything not on
 * this list is deliberately kept out of the catalog/UI entirely (see
 * plugin/models-dev.ts) rather than reaching a provider the local
 * pseudonymization proxy (packages/argos/.../llm-proxy.ts) doesn't cover
 * — a provider nobody registered here can silently bypass the vault.
 */
export const PROXIED_PROVIDER_IDS = [
  "anthropic",
  "openai",
  "openrouter",
  "groq",
  "deepseek",
  "opencode",
  "opencode-go",
] as const

export type ProxiedProviderID = (typeof PROXIED_PROVIDER_IDS)[number]

/** Env var this provider's local-proxy base URL is passed through as (see aisdk.ts / server.ts). */
export function proxyBaseUrlEnvVar(providerID: string): string {
  return `LLM_PROXY_BASE_URL_${providerID.toUpperCase().replace(/-/g, "_")}`
}

export const TYPE_PREFIX_MAP: Record<EntityType, string> = {
  ip: "IP",
  cidr: "CIDR",
  domain: "DOM",
  email: "MAIL",
  username: "USER",
}

// Regex to identify generated tokens (e.g. ZXDOM001, ZXIP042, ZXMAIL003)
export const TOKEN_REGEX = /\bZX(IP|CIDR|DOM|MAIL|USER)(\d{3,})\b/g

// IPv4 pattern for free-text detection
export const IPV4_REGEX = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g

// CIDR pattern
export const CIDR_REGEX = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:[0-9]|[12][0-9]|3[0-2])\b/g

// Email pattern
export const EMAIL_REGEX = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g

// Domain / hostname pattern (e.g. host.internal.corp)
export const DOMAIN_REGEX = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi

// Secret patterns (Irreversible masking)
export const SECRET_PATTERNS = [
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
  /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
  /\b((?:api[_-]?key|access[_-]?token|bearer|secret|password|passwd|auth[_-]?token)[\s:=]+['"]?)([A-Za-z0-9_\-]{16,})(['"]?)/gi,
]

export function maskSecrets(text: string): string {
  let result = text
  for (const pattern of SECRET_PATTERNS) {
    if (pattern.source.includes("(?:api")) {
      result = result.replaceAll(pattern, (_match, prefix, _val, suffix) => `${prefix}[SECRET-REDACTED]${suffix}`)
    } else {
      result = result.replaceAll(pattern, "[SECRET-REDACTED]")
    }
  }
  return result
}

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
}

export interface EngagementVaultState {
  engagementId: string
  realToToken: Map<string, string>
  tokenToReal: Map<string, string>
  counters: Record<EntityType, number>
  loaded: boolean
  lock: Semaphore.Semaphore
}

const MAX_CACHED_ENGAGEMENTS = 100
const vaultCache = new Map<string, EngagementVaultState>()

export function getOrCreateVaultState(engagementId: string): EngagementVaultState {
  let state = vaultCache.get(engagementId)
  if (state) {
    vaultCache.delete(engagementId)
    vaultCache.set(engagementId, state)
    return state
  }

  if (vaultCache.size >= MAX_CACHED_ENGAGEMENTS) {
    const oldestKey = vaultCache.keys().next().value
    if (oldestKey) vaultCache.delete(oldestKey)
  }

  state = {
    engagementId,
    realToToken: new Map(),
    tokenToReal: new Map(),
    counters: { ip: 0, cidr: 0, domain: 0, email: 0, username: 0 },
    loaded: false,
    lock: Semaphore.makeUnsafe(1),
  }
  vaultCache.set(engagementId, state)
  return state
}

/**
 * Sliding window buffer for stream de-tokenization.
 *
 * A naive "always hold back the last N characters" scheme still splits a
 * token whenever it happens to START before that fixed cutoff — holding back
 * enough total length doesn't help if the boundary lands mid-token. This
 * instead holds back from the position of the last unresolved "Z" within the
 * tail window (the only character a token can start with), so nothing that
 * could still be growing into "ZX<TYPE><NNN>" ever gets emitted split. Text
 * that merely happens to contain "Z" without ever becoming a real token is
 * held slightly longer than strictly necessary (until it's flushed or more
 * input arrives) — a small latency cost, never a correctness one.
 */
export class SlidingWindowDetokenizer {
  private buffer = ""
  private readonly maxTokenLen = 20

  constructor(private readonly getRealValue: (token: string) => string | undefined) {}

  private safeEmitLength(): number {
    const tailStart = Math.max(0, this.buffer.length - this.maxTokenLen)
    const zIndex = this.buffer.indexOf("Z", tailStart)
    return zIndex === -1 ? this.buffer.length : zIndex
  }

  public processChunk(chunk: string): string {
    this.buffer += chunk
    const safeEnd = this.safeEmitLength()
    if (safeEnd <= 0) return ""

    const toProcess = this.buffer.slice(0, safeEnd)
    this.buffer = this.buffer.slice(safeEnd)

    return toProcess.replaceAll(TOKEN_REGEX, (token) => {
      return this.getRealValue(token) ?? token
    })
  }

  public flush(): string {
    const remaining = this.buffer
    this.buffer = ""
    return remaining.replaceAll(TOKEN_REGEX, (token) => {
      return this.getRealValue(token) ?? token
    })
  }
}

export namespace Pseudonymize {
  export const loadVault = (engagementId: string, db?: DatabaseInstance): Effect.Effect<EngagementVaultState, never, never> =>
    Effect.gen(function* () {
      const state = getOrCreateVaultState(engagementId)
      if (state.loaded) return state

      let shouldSeedScope = false
      yield* state.lock.withPermits(1)(
        Effect.gen(function* () {
          if (state.loaded) return
          if (!db) return

          const rows = yield* db
            .select()
            .from(EngagementPseudonymTable)
            .where(eq(EngagementPseudonymTable.engagement_id, engagementId))
            .all()
            .pipe(Effect.orDie)

          for (const row of rows) {
            state.realToToken.set(row.real_value.toLowerCase(), row.token)
            state.tokenToReal.set(row.token, row.real_value)

            const match = row.token.match(/^ZX(IP|CIDR|DOM|MAIL|USER)(\d+)$/)
            if (match) {
              const prefix = match[1]
              const num = parseInt(match[2], 10)
              const type = (Object.keys(TYPE_PREFIX_MAP) as EntityType[]).find((k) => TYPE_PREFIX_MAP[k] === prefix)
              if (type && num > state.counters[type]) {
                state.counters[type] = num
              }
            }
          }
          state.loaded = true
          shouldSeedScope = engagementId.startsWith("ses_")
        }),
      )

      // Pre-seed any scope configured on the session OUTSIDE the lock
      if (shouldSeedScope && db) {
        yield* seedSessionScope(db, SessionSchema.ID.make(engagementId))
      }

      return state
    })

  export const getOrAllocateToken = (
    engagementId: string,
    entityType: EntityType,
    realValue: string,
    db?: DatabaseInstance,
  ): Effect.Effect<string, never, never> =>
    Effect.gen(function* () {
      const state = yield* loadVault(engagementId, db)
      const normalized = realValue.trim().toLowerCase()
      if (!normalized) return realValue

      const existing = state.realToToken.get(normalized)
      if (existing) return existing

      return yield* state.lock.withPermits(1)(
        Effect.gen(function* () {
          const doubleCheck = state.realToToken.get(normalized)
          if (doubleCheck) return doubleCheck

          state.counters[entityType] += 1
          const prefix = TYPE_PREFIX_MAP[entityType]
          const numStr = String(state.counters[entityType]).padStart(3, "0")
          const token = `ZX${prefix}${numStr}`

          state.realToToken.set(normalized, token)
          state.tokenToReal.set(token, realValue.trim())

          if (db) {
            const id = `ps_${engagementId}_${token}`
            yield* db
              .insert(EngagementPseudonymTable)
              .values({
                id,
                engagement_id: engagementId,
                entity_type: entityType,
                token,
                real_value: realValue.trim(),
                time_created: Date.now(),
              })
              .onConflictDoNothing()
              .pipe(Effect.orDie)
          }

          return token
        }),
      )
    })

  export const registerEntity = (
    db: DatabaseInstance | undefined,
    sessionOrEngagementID: string,
    entityType: EntityType,
    realValue: string,
  ) => getOrAllocateToken(sessionOrEngagementID, entityType, realValue, db)

  export const seedTargetScope = (engagementId: string, target: string, db?: DatabaseInstance) =>
    Effect.gen(function* () {
      if (!target) return
      const clean = target.trim().replace(/^https?:\/\//i, "").split("/")[0].split(":")[0].toLowerCase()
      if (!clean) return

      if (isIP(clean)) {
        yield* getOrAllocateToken(engagementId, "ip", clean, db)
      } else if (clean.includes(".")) {
        yield* getOrAllocateToken(engagementId, "domain", clean, db)
      }
    })

  export const seedSessionScope = (db: DatabaseInstance, sessionID: SessionSchema.ID) =>
    Effect.gen(function* () {
      const session = yield* db
        .select({
          scopeDomains: SessionTable.scope_domains,
          scopeCidrs: SessionTable.scope_cidrs,
        })
        .from(SessionTable)
        .where(eq(SessionTable.id, sessionID))
        .get()
        .pipe(Effect.orDie)

      if (!session) return

      if (session.scopeDomains && Array.isArray(session.scopeDomains)) {
        for (const dom of session.scopeDomains) {
          yield* seedTargetScope(sessionID, dom, db)
        }
      }

      if (session.scopeCidrs && Array.isArray(session.scopeCidrs)) {
        for (const cidr of session.scopeCidrs) {
          yield* getOrAllocateToken(sessionID, "cidr", cidr, db)
        }
      }
    })

  export const registerFindingEntities = (
    db: DatabaseInstance | undefined,
    sessionID: SessionSchema.ID,
    target?: string,
    vector?: string,
  ): Effect.Effect<void, never, never> =>
    Effect.gen(function* () {
      const texts = [target, vector].filter((t): t is string => Boolean(t && typeof t === "string"))
      if (texts.length === 0) return

      for (const text of texts) {
        // Emails
        for (const m of text.matchAll(EMAIL_REGEX)) {
          yield* getOrAllocateToken(sessionID, "email", m[0], db)
        }

        // CIDRs
        for (const m of text.matchAll(CIDR_REGEX)) {
          yield* getOrAllocateToken(sessionID, "cidr", m[0], db)
        }

        // IPs
        for (const m of text.matchAll(IPV4_REGEX)) {
          if (m[0] !== "127.0.0.1" && m[0] !== "0.0.0.0") {
            yield* getOrAllocateToken(sessionID, "ip", m[0], db)
          }
        }

        // Target domains (stripping emails first to avoid false sub-matches)
        const noEmails = text.replace(EMAIL_REGEX, " ")
        const domainMatches = noEmails.matchAll(DOMAIN_REGEX)
        for (const dm of domainMatches) {
          const d = dm[0].toLowerCase()
          if (!isIP(d)) {
            yield* getOrAllocateToken(sessionID, "domain", d, db)
          }
        }
      }
    })

  export const tokenizeText = (engagementId: string, text: string, db?: DatabaseInstance): Effect.Effect<string, never, never> =>
    Effect.gen(function* () {
      if (!text || typeof text !== "string") return text

      // 1. Mask secrets
      let result = maskSecrets(text)

      // 2. Load vault
      const state = yield* loadVault(engagementId, db)

      // 3. Extract & allocate Emails
      const emails = [...result.matchAll(EMAIL_REGEX)].map((m) => m[0])
      for (const email of emails) {
        yield* getOrAllocateToken(engagementId, "email", email, db)
      }

      // 4. Extract & allocate CIDRs
      const cidrs = [...result.matchAll(CIDR_REGEX)].map((m) => m[0])
      for (const cidr of cidrs) {
        yield* getOrAllocateToken(engagementId, "cidr", cidr, db)
      }

      // 5. Extract & allocate IPv4 addresses (excluding 127.0.0.1 / 0.0.0.0)
      const ips = [...result.matchAll(IPV4_REGEX)].map((m) => m[0])
      for (const ip of ips) {
        if (ip === "127.0.0.1" || ip === "0.0.0.0") continue
        yield* getOrAllocateToken(engagementId, "ip", ip, db)
      }

      // 5.5. Extract & allocate domains/hostnames appearing for the first time
      // (e.g. in raw shell/MCP tool output that hasn't become a formal finding
      // yet) -- without this, a domain only gets tokenized once something else
      // has already registered it via registerFindingEntities/seedSessionScope.
      // Strip emails first so their domain part isn't double-registered as a
      // bare domain too.
      const noEmails = result.replace(EMAIL_REGEX, " ")
      const domains = [...noEmails.matchAll(DOMAIN_REGEX)].map((m) => m[0].toLowerCase())
      for (const domain of domains) {
        if (isIP(domain)) continue
        yield* getOrAllocateToken(engagementId, "domain", domain, db)
      }

      // 6. Replace all known real values in order of longest length first
      const sortedKnown = Array.from(state.realToToken.entries()).sort(
        (a, b) => b[0].length - a[0].length,
      )

      for (const [realVal, token] of sortedKnown) {
        const regex = new RegExp(escapeRegex(realVal), "gi")
        result = result.replace(regex, token)
      }

      return result
    })

  export const detokenizeText = (engagementId: string, text: string, db?: DatabaseInstance): Effect.Effect<string, never, never> =>
    Effect.gen(function* () {
      if (!text || typeof text !== "string") return text
      const state = yield* loadVault(engagementId, db)

      return text.replaceAll(TOKEN_REGEX, (token) => {
        return state.tokenToReal.get(token) ?? token
      })
    })

  export const tokenizeString = (db: DatabaseInstance | undefined, sessionOrEngagementID: string, text: string) =>
    tokenizeText(sessionOrEngagementID, text, db)

  export const detokenizeString = (db: DatabaseInstance | undefined, sessionOrEngagementID: string, text: string) =>
    detokenizeText(sessionOrEngagementID, text, db)

  export const tokenizeMessages = (
    db: DatabaseInstance | undefined,
    sessionOrEngagementID: string,
    messages: ReadonlyArray<Message>,
  ): Effect.Effect<Message[], never, never> =>
    Effect.gen(function* () {
      const out: Message[] = []
      for (const msg of messages) {
        if (!msg.content || !Array.isArray(msg.content)) {
          out.push(msg)
          continue
        }
        const tokenizedContent: ContentPart[] = []
        for (const part of msg.content) {
          if (part.type === "text" && typeof part.text === "string") {
            const tokenizedText = yield* tokenizeText(sessionOrEngagementID, part.text, db)
            tokenizedContent.push({ ...part, text: tokenizedText })
          } else {
            tokenizedContent.push(part)
          }
        }
        out.push(new Message({ ...msg, content: tokenizedContent }))
      }
      return out
    })

  export const detokenizeEvent = (
    db: DatabaseInstance | undefined,
    sessionOrEngagementID: string,
    event: LLMEvent,
  ): Effect.Effect<LLMEvent, never, never> =>
    Effect.gen(function* () {
      if (!event || typeof event !== "object") return event

      if (event.type === "text-delta") {
        const detok = yield* detokenizeText(sessionOrEngagementID, event.text, db)
        return { ...event, text: detok }
      }

      if (event.type === "reasoning-delta") {
        const detok = yield* detokenizeText(sessionOrEngagementID, event.text, db)
        return { ...event, text: detok }
      }

      if (event.type === "tool-input-delta" && typeof (event as any).text === "string") {
        const detok = yield* detokenizeText(sessionOrEngagementID, (event as any).text, db)
        return { ...event, text: detok }
      }

      if (event.type === "tool-result") {
        const e = event as any
        let result = e.result
        if (typeof result === "string") {
          result = yield* detokenizeText(sessionOrEngagementID, result, db)
        } else if (result && typeof result === "object") {
          result = yield* detokenizeJson(sessionOrEngagementID, result, db)
        }

        let output = e.output
        if (output && typeof output === "object") {
          output = yield* detokenizeJson(sessionOrEngagementID, output, db)
        }

        return { ...event, result, output }
      }

      return event
    })

  export const tokenizeJson = (engagementId: string, data: unknown, db?: DatabaseInstance): Effect.Effect<unknown, never, never> =>
    Effect.gen(function* () {
      if (data === null || data === undefined) return data
      if (typeof data === "string") {
        return yield* tokenizeText(engagementId, data, db)
      }
      if (Array.isArray(data)) {
        const out: unknown[] = []
        for (const item of data) {
          out.push(yield* tokenizeJson(engagementId, item, db))
        }
        return out
      }
      if (typeof data === "object") {
        const out: Record<string, unknown> = {}
        for (const [k, v] of Object.entries(data)) {
          out[k] = yield* tokenizeJson(engagementId, v, db)
        }
        return out
      }
      return data
    })

  export const detokenizeJson = (engagementId: string, data: unknown, db?: DatabaseInstance): Effect.Effect<unknown, never, never> =>
    Effect.gen(function* () {
      if (data === null || data === undefined) return data
      if (typeof data === "string") {
        return yield* detokenizeText(engagementId, data, db)
      }
      if (Array.isArray(data)) {
        const out: unknown[] = []
        for (const item of data) {
          out.push(yield* detokenizeJson(engagementId, item, db))
        }
        return out
      }
      if (typeof data === "object") {
        const out: Record<string, unknown> = {}
        for (const [k, v] of Object.entries(data)) {
          out[k] = yield* detokenizeJson(engagementId, v, db)
        }
        return out
      }
      return data
    })

  export const createDetokenizer = (engagementId: string, db?: DatabaseInstance) =>
    Effect.gen(function* () {
      const state = yield* loadVault(engagementId, db)
      return new SlidingWindowDetokenizer((token) => state.tokenToReal.get(token))
    })

  /**
   * Extracts engagement / campaign identifier from request headers or content
   */
  export const extractEngagementId = (
    rawBody: string,
    headers?: Headers | Record<string, string | string[] | undefined>,
  ): string => {
    // 1. Check explicit headers
    if (headers) {
      if (headers instanceof Headers) {
        const h =
          headers.get("x-engagement-id") ||
          headers.get("x-session-id") ||
          headers.get("x-campaign-id")
        if (h) return h
      } else {
        const h =
          (headers["x-engagement-id"] as string) ||
          (headers["x-session-id"] as string) ||
          (headers["x-campaign-id"] as string)
        if (h) return h
      }
    }

    // 2. Search body for session / campaign ID patterns
    if (rawBody && typeof rawBody === "string") {
      // Look for session identifier: e.g. ses_...
      const sesMatch = rawBody.match(/\b(ses_[0-9a-zA-Z_-]{16,})\b/)
      if (sesMatch) return sesMatch[1]

      // Look for explicit campaign/engagement/session JSON properties
      const engagementMatch = rawBody.match(/"(?:engagement|campaign|session)"\s*:\s*"([^"]+)"/)
      if (engagementMatch) return engagementMatch[1]
    }

    return "global_engagement"
  }
}

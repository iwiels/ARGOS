import { Effect, Stream } from "effect"
import { HttpServerRequest, HttpServerResponse } from "effect/unstable/http"
import { Database } from "@argos/core/database/database"
import { Pseudonymize, PROXIED_PROVIDER_IDS } from "@argos/core/security/pseudonymize"
import * as Log from "@argos/core/util/log"

const log = Log.create({ service: "llm-proxy" })

// Only these providers are ever proxied -- kept exactly in sync with
// PROXIED_PROVIDER_IDS (the same list plugin/models-dev.ts uses to filter the
// catalog, so nothing outside it is ever selectable). Any other providerID
// falls through to the "unsupported provider" 400 below instead of a guessed
// URL -- a provider not in this map must fail closed, not silently reach a
// real upstream unproxied.
const DEFAULT_PROVIDER_URLS: Record<string, string> = {
  anthropic: "https://api.anthropic.com",
  openai: "https://api.openai.com",
  openrouter: "https://openrouter.ai/api",
  groq: "https://api.groq.com/openai",
  deepseek: "https://api.deepseek.com",
  opencode: "https://opencode.ai/zen/v1",
  "opencode-go": "https://opencode.ai/zen/go/v1",
}

// Response headers that describe the ORIGINAL upstream body and must never be
// forwarded once that body has been rewritten (detokenized) — a stale
// Content-Length truncates or hangs the client, and a stale Content-Encoding
// claims the (now-plaintext) body is still compressed.
const STRIP_ON_REWRITE = new Set(["content-length", "content-encoding", "transfer-encoding"])

function stripRewrittenHeaders(headers: Headers): Headers {
  const out = new Headers(headers)
  for (const key of STRIP_ON_REWRITE) out.delete(key)
  return out
}

/** Allows tests (and operators) to redirect a given provider's upstream without editing the static map. */
function resolveUpstreamBase(providerID: string): string | undefined {
  const envOverride = process.env[`LLM_PROXY_UPSTREAM_${providerID.toUpperCase()}`]
  if (envOverride) return envOverride
  return DEFAULT_PROVIDER_URLS[providerID]
}

export function handleLlmProxy(request: HttpServerRequest.HttpServerRequest) {
  return Effect.gen(function* () {
    const { db } = yield* Database.Service

    const rawUrl = new URL(request.url, "http://127.0.0.1")
    const pathname = rawUrl.pathname // e.g. "/llm-proxy/anthropic/v1/messages"

    // Parse providerID and subPath from /llm-proxy/:providerID/*
    const match = pathname.match(/^\/llm-proxy\/([^/]+)(?:\/(.*))?$/)
    if (!match) {
      return HttpServerResponse.text("Invalid proxy route", { status: 400 })
    }

    const providerID = match[1].toLowerCase()
    if (!(PROXIED_PROVIDER_IDS as readonly string[]).includes(providerID)) {
      return HttpServerResponse.text(`Unsupported provider: ${providerID}`, { status: 400 })
    }
    const subPath = match[2] ?? ""
    const base = resolveUpstreamBase(providerID)
    if (!base) {
      return HttpServerResponse.text(`No upstream configured for provider: ${providerID}`, { status: 502 })
    }
    const targetUrl = subPath ? `${base}/${subPath}${rawUrl.search}` : `${base}${rawUrl.search}`

    const headers = request.headers

    // 1. Read request body and extract engagement ID from content/headers.
    // Pseudonymization is always on -- there is no opt-out. A caller cannot
    // disable the vault by sending a header.
    const rawBody = yield* Effect.orDie(request.text)
    const engagementId = Pseudonymize.extractEngagementId(rawBody, headers)

    let forwardedBody = rawBody
    if (rawBody.trim().length > 0) {
      try {
        const json = JSON.parse(rawBody)
        const tokenized = yield* Pseudonymize.tokenizeJson(engagementId, json, db)
        forwardedBody = JSON.stringify(tokenized)
      } catch {
        forwardedBody = yield* Pseudonymize.tokenizeText(engagementId, rawBody, db)
      }
    }

    // 2. Prepare headers for forwarding
    const forwardHeaders = new Headers()
    for (const [key, value] of Object.entries(headers)) {
      const lower = key.toLowerCase()
      if (lower === "host" || lower === "content-length" || lower.startsWith("x-engagement")) {
        continue
      }
      if (typeof value === "string") {
        forwardHeaders.set(key, value)
      }
    }

    log.info("Proxying LLM request", {
      providerID,
      targetUrl,
      engagementId,
      bodyLength: forwardedBody.length,
    })

    // 3. Execute upstream HTTP request
    const upstream = yield* Effect.tryPromise({
      try: () =>
        fetch(targetUrl, {
          method: request.method,
          headers: forwardHeaders,
          body: ["GET", "HEAD"].includes(request.method) ? undefined : forwardedBody,
        }),
      catch: (cause) => new Error(`Upstream fetch failed: ${cause}`),
    }).pipe(
      Effect.catch(() =>
        Effect.succeed(
          new Response(JSON.stringify({ error: { message: "Upstream gateway error" } }), {
            status: 502,
            headers: { "content-type": "application/json" },
          }),
        ),
      ),
    )

    const contentType = upstream.headers.get("content-type") ?? ""

    // 4. Handle SSE streaming response
    if (contentType.includes("text/event-stream") && upstream.body) {
      const detokenizer = yield* Pseudonymize.createDetokenizer(engagementId, db)
      const reader = upstream.body.getReader()
      const decoder = new TextDecoder()
      const encoder = new TextEncoder()

      const sseStream = Stream.fromAsyncIterable(
        (async function* () {
          try {
            while (true) {
              const { done, value } = await reader.read()
              if (done) {
                const flushed = detokenizer.flush()
                if (flushed.length > 0) {
                  yield encoder.encode(flushed)
                }
                break
              }
              const chunkText = decoder.decode(value, { stream: true })
              const processed = detokenizer.processChunk(chunkText)
              if (processed.length > 0) {
                yield encoder.encode(processed)
              }
            }
          } finally {
            reader.releaseLock()
          }
        })(),
        (err) => (err instanceof Error ? err : new Error(String(err))),
      )

      // Streaming bodies are chunked, not length-prefixed — Content-Encoding
      // still needs stripping since the bytes we emit are the decoded ones.
      return HttpServerResponse.stream(sseStream, {
        status: upstream.status,
        headers: stripRewrittenHeaders(upstream.headers),
      })
    }

    // 5. Handle standard non-streaming response
    const responseText = yield* Effect.promise(() => upstream.text())

    let detokenizedResponse = responseText
    if (responseText.trim().length > 0) {
      try {
        const json = JSON.parse(responseText)
        const detok = yield* Pseudonymize.detokenizeJson(engagementId, json, db)
        detokenizedResponse = JSON.stringify(detok)
      } catch {
        detokenizedResponse = yield* Pseudonymize.detokenizeText(engagementId, responseText, db)
      }
    }

    // The body was rewritten (length almost never matches the original, and
    // fetch() already transparently decompressed it) — let HttpServerResponse
    // compute a fresh Content-Length instead of forwarding the stale one.
    return HttpServerResponse.text(detokenizedResponse, {
      status: upstream.status,
      headers: stripRewrittenHeaders(upstream.headers),
    })
    // Self-provide Database rather than relying solely on the ambient layer
    // reaching this handler through the router's own composition — confirmed
    // by a real end-to-end test that the outer `Layer.provide` on the merged
    // route set does not reliably thread through for this raw HttpRouter route.
  }).pipe(Effect.provide(Database.defaultLayer))
}

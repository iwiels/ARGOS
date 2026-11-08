export * as WebBrowseTool from "./web-browse"

import { ToolFailure, toolText } from "@argos/llm"
import { Effect, Layer, Schema } from "effect"
import type { Browser, BrowserContextOptions, Page } from "playwright-core"
import { PermissionV2 } from "../permission"
import * as AuthSecretVault from "../security/auth-secret-vault"
import * as ScopeService from "../security/scope-service"
import {
  evaluateScopeTarget,
  extractTargetHost,
  isPrivateAddress,
  scopeAllowsPrivateHost,
} from "../security/scope-eval"
import { Tool } from "./tool"
import { Tools } from "./tools"

export const name = "web.browse"
export const actions = ["navigate", "login", "check_authz", "dom_xss"] as const
export type Action = (typeof actions)[number]

export const description = `Container-backed browser hunting and authenticated application security testing using Playwright.
Supports single-page apps (SPA), authenticated crawling, DOM XSS sink inspection, and authorization discrepancy analysis (BOLA/BFLA). A browser worker connected to the Argos scope gateway is required; host-browser fallback is disabled.`

export const Input = Schema.Struct({
  action: Schema.Literals(actions).annotate({
    description:
      "The browser action: navigate (crawl SPA/forms), login (auth session capture), check_authz (BOLA/BFLA matrix), dom_xss (DOM sink probing).",
  }),
  url: Schema.String.annotate({ description: "Target URL to open or test" }),
  authProfileID: Schema.optional(Schema.String).annotate({
    description: "Opaque ID of an authentication profile stored in the desktop secure vault",
  }),
  authzCompare: Schema.optional(
    Schema.Struct({
      roleAAuthProfileID: Schema.String,
      roleBAuthProfileID: Schema.String,
      endpointUrl: Schema.String,
    }),
  ).annotate({ description: "Two secure authentication profile IDs to compare authorization access (BOLA/BFLA)" }),
  xssParam: Schema.optional(Schema.String).annotate({
    description: "URL parameter or hash fragment name to probe for DOM XSS",
  }),
  timeoutSeconds: Schema.optional(Schema.Number).annotate({
    description: "Timeout in seconds (default 30, maximum 120)",
  }),
})

export const Output = Schema.Struct({
  action: Schema.String,
  url: Schema.String,
  success: Schema.Boolean,
  title: Schema.optional(Schema.String),
  links: Schema.optional(Schema.Array(Schema.String)),
  forms: Schema.optional(
    Schema.Array(
      Schema.Struct({
        action: Schema.String,
        method: Schema.String,
        inputs: Schema.Array(Schema.String),
      }),
    ),
  ),
  authProfileID: Schema.optional(Schema.String),
  authenticationStatus: Schema.optional(Schema.String),
  authzDiscrepancy: Schema.optional(
    Schema.Struct({
      roleAStatus: Schema.Number,
      roleBStatus: Schema.Number,
      roleABodyLength: Schema.Number,
      roleBBodyLength: Schema.Number,
      potentialBOLA: Schema.Boolean,
      details: Schema.String,
    }),
  ),
  domXssSinks: Schema.optional(
    Schema.Array(
      Schema.Struct({
        sink: Schema.String,
        payload: Schema.String,
        stack: Schema.optional(Schema.String),
      }),
    ),
  ),
  error: Schema.optional(Schema.String),
})

export type BrowserLauncher = () => Promise<Browser>

type StoredAuthProfile = {
  version: 1
  sessionID: string
  username: string
  password: string
  userSelector?: string
  passwordSelector?: string
  submitSelector?: string
  storageState?: Exclude<BrowserContextOptions["storageState"], string>
}

function parseAuthProfile(raw: string | null, sessionID: string): StoredAuthProfile {
  if (!raw) throw new Error("Authentication profile is unavailable")
  try {
    const value: unknown = JSON.parse(raw)
    if (
      !value ||
      typeof value !== "object" ||
      (value as StoredAuthProfile).version !== 1 ||
      (value as StoredAuthProfile).sessionID !== sessionID ||
      typeof (value as StoredAuthProfile).username !== "string" ||
      typeof (value as StoredAuthProfile).password !== "string"
    ) {
      throw new Error("Authentication profile is unavailable")
    }
    const profile = value as StoredAuthProfile
    if (profile.storageState !== undefined && (!profile.storageState || typeof profile.storageState !== "object")) {
      throw new Error("Authentication profile is unavailable")
    }
    return profile
  } catch {
    throw new Error("Authentication profile is unavailable")
  }
}

/** Veredicto del gate de scope: o pasa, o viene con su razón de rechazo. */
type ScopeVerdict = { allowed: true } | { allowed: false; error: ScopeService.ScopeViolationError }

export const defaultLauncher: BrowserLauncher = async () => {
  throw new Error(
    "Browser execution is unavailable until the containerized browser worker is connected; host browser execution is disabled.",
  )
}

let launcher: BrowserLauncher = defaultLauncher

/** Replaces the browser launcher. Tests inject a fake browser here. */
export const setBrowserLauncher = (next: BrowserLauncher) => {
  launcher = next
}

/**
 * Verdict for a single URL against the session scope.
 *
 * Invariante de seguridad: el navegador es un cliente HTTP que además sigue
 * redirecciones, dispara XHR, beacons y WebSockets. Por eso el control de
 * alcance no puede limitarse a la URL inicial — cada request en vuelo se
 * vuelve a pasar por acá.
 */
function createScopeGuard(policy: ScopeService.ScopePolicy | undefined) {
  return (rawUrl: string): boolean => {
    let parsed: URL
    try {
      parsed = new URL(rawUrl)
    } catch {
      return false
    }
    // Esquemas no-HTTP (file:, chrome:, about:, data:) nunca son un target
    // autorizado de un engagement.
    if (
      parsed.protocol !== "http:" &&
      parsed.protocol !== "https:" &&
      parsed.protocol !== "ws:" &&
      parsed.protocol !== "wss:"
    ) {
      return false
    }
    const check = evaluateScopeTarget(rawUrl, policy)
    if (!check.allowed) return false
    const host = extractTargetHost(rawUrl).host
    if (policy && isPrivateAddress(host) && !scopeAllowsPrivateHost(policy, host)) return false
    return true
  }
}

/** Installs the scope guard on a page: every request outside the scope is aborted. */
async function guardPage(page: Page, allows: (url: string) => boolean) {
  await page.route("**/*", async (route) => {
    if (!allows(route.request().url())) {
      await route.abort("blockedbyclient").catch(() => {})
      return
    }
    await route.continue().catch(() => {})
  })

  // El handshake de un WebSocket no pasa por el pipeline HTTP de las rutas, así
  // que necesita su propio control: fuera de alcance no se abre; dentro, se
  // proxía tal cual.
  const routeWebSocket = (
    page as unknown as { routeWebSocket?: (url: string, handler: (ws: any) => void) => Promise<void> }
  ).routeWebSocket
  if (typeof routeWebSocket !== "function") return
  await routeWebSocket
    .call(page, "**/*", (ws: any) => {
      const url = typeof ws?.url === "function" ? ws.url() : String(ws?.url ?? "")
      if (!allows(url)) {
        ws?.close?.()
        return
      }
      try {
        const server = ws.connectToServer()
        server?.onMessage?.((message: string) => ws.send?.(message))
        ws.onMessage?.((message: string) => server?.send?.(message))
      } catch {
        // sin proxy no hay conexión: preferible cortar que dejar abierto.
        ws?.close?.()
      }
    })
    .catch(() => {})
}

export const layerWithScopeService = Layer.effectDiscard(
  Effect.gen(function* () {
    const tools = yield* Tools.Service
    const permission = yield* PermissionV2.Service
    const scope = yield* ScopeService.Service
    const authVault = yield* AuthSecretVault.Service

    yield* tools
      .register({
        [name]: Tool.make({
          description,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [
            toolText({
              type: "text",
              text: JSON.stringify(output, null, 2),
            }),
          ],
          execute: (input, context) =>
            Effect.gen(function* () {
              yield* permission
                .assert({
                  action: `${name}:${input.action}`,
                  resources: [input.url, ...(input.authzCompare ? [input.authzCompare.endpointUrl] : [])],
                  save: ["*"],
                  metadata: input,
                  sessionID: context.sessionID,
                  agent: context.agent,
                  source: { type: "tool", messageID: context.assistantMessageID, callID: context.toolCallID },
                })
                .pipe(Effect.mapError((error) => new ToolFailure({ message: error.message })))

              // Pre-flight: la URL inicial tiene que estar autorizada antes de
              // abrir el navegador.
              const verdict: ScopeVerdict = yield* scope.assertTarget(context.sessionID, input.url).pipe(
                Effect.map(() => ({ allowed: true }) as const),
                Effect.catchTag("ScopeViolationError", (error) => Effect.succeed({ allowed: false, error } as const)),
              )

              if (!verdict.allowed) {
                return {
                  action: input.action,
                  url: input.url,
                  success: false,
                  error: `SCOPE ENFORCEMENT: ${verdict.error.reason}`,
                }
              }

              if (input.authzCompare) {
                const endpointVerdict = yield* scope
                  .assertTarget(context.sessionID, input.authzCompare.endpointUrl)
                  .pipe(
                    Effect.map(() => ({ allowed: true }) as const),
                    Effect.catchTag("ScopeViolationError", (error) =>
                      Effect.succeed({ allowed: false, error } as const),
                    ),
                  )
                if (!endpointVerdict.allowed) {
                  return {
                    action: input.action,
                    url: input.url,
                    success: false,
                    error: `SCOPE ENFORCEMENT: ${endpointVerdict.error.reason}`,
                  }
                }
              }

              const profileFor = (id: string) =>
                authVault.get(id).pipe(
                  Effect.mapError(() => new ToolFailure({ message: "Authentication profile is unavailable" })),
                  Effect.flatMap((raw) =>
                    Effect.try({
                      try: () => parseAuthProfile(raw, context.sessionID),
                      catch: () => new ToolFailure({ message: "Authentication profile is unavailable" }),
                    }),
                  ),
                )

              const authProfile = input.authProfileID ? yield* profileFor(input.authProfileID) : undefined
              const roleAProfile = input.authzCompare
                ? yield* profileFor(input.authzCompare.roleAAuthProfileID)
                : undefined
              const roleBProfile = input.authzCompare
                ? yield* profileFor(input.authzCompare.roleBAuthProfileID)
                : undefined

              if (input.action === "login" && !input.authProfileID) {
                return {
                  action: input.action,
                  url: input.url,
                  success: false,
                  error: "A secure authentication profile is required for login",
                }
              }
              if (
                (input.action === "navigate" && input.authProfileID && !authProfile?.storageState) ||
                (input.action === "check_authz" && (!roleAProfile?.storageState || !roleBProfile?.storageState))
              ) {
                return {
                  action: input.action,
                  url: input.url,
                  success: false,
                  error: "Authentication profile has no saved browser session",
                }
              }

              const policy = yield* scope.forSession(context.sessionID)
              const allows = createScopeGuard(policy)

              return yield* Effect.tryPromise({
                try: async () => {
                  let browser: Browser | null = null
                  try {
                    browser = await launcher()
                    const contextOptions: BrowserContextOptions = {}
                    if (input.action !== "check_authz" && authProfile?.storageState) {
                      contextOptions.storageState = authProfile.storageState
                    }

                    const browserCtx = await browser.newContext(contextOptions)
                    const page = await browserCtx.newPage()
                    page.setDefaultTimeout((input.timeoutSeconds ?? 30) * 1000)
                    await guardPage(page, allows)

                    switch (input.action) {
                      case "navigate": {
                        await page.goto(input.url, { waitUntil: "domcontentloaded" })
                        const title = await page.title()

                        const links = await page.$$eval("a[href]", (els) =>
                          els.map((el) => (el as HTMLAnchorElement).href).filter(Boolean),
                        )

                        const forms = await page.$$eval("form", (els) =>
                          els.map((f) => {
                            const inputs = Array.from(f.querySelectorAll("input, select, textarea")).map(
                              (i) => (i as HTMLInputElement).name || (i as HTMLInputElement).id || "unnamed",
                            )
                            return {
                              action: f.action || "",
                              method: f.method || "GET",
                              inputs,
                            }
                          }),
                        )

                        return {
                          action: "navigate",
                          url: input.url,
                          success: true,
                          title,
                          links: Array.from(new Set(links)).slice(0, 100),
                          forms,
                        }
                      }

                      case "login": {
                        await page.goto(input.url, { waitUntil: "domcontentloaded" })
                        const creds = authProfile!

                        const userSel =
                          creds.userSelector || "input[type='text'], input[type='email'], input[name*='user']"
                        const passSel = creds.passwordSelector || "input[type='password']"
                        const submitSel = creds.submitSelector || "button[type='submit'], input[type='submit']"

                        await page.fill(userSel, creds.username)
                        await page.fill(passSel, creds.password)
                        await Promise.all([
                          page.waitForLoadState("domcontentloaded").catch(() => {}),
                          page.click(submitSel).catch(() => page.keyboard.press("Enter")),
                        ])

                        const savedState = await browserCtx.storageState()
                        const updatedProfile = { ...authProfile!, storageState: savedState }
                        await Effect.runPromise(authVault.put(input.authProfileID!, JSON.stringify(updatedProfile)))
                        return {
                          action: "login",
                          url: input.url,
                          success: true,
                          title: await page.title(),
                          authProfileID: input.authProfileID,
                        }
                      }

                      case "check_authz": {
                        const authz = input.authzCompare
                        if (!authz) {
                          return {
                            action: "check_authz",
                            url: input.url,
                            success: false,
                            error: "authzCompare configuration required for check_authz",
                          }
                        }

                        const ctxA = await browser.newContext({ storageState: roleAProfile!.storageState })
                        const pageA = await ctxA.newPage()
                        await guardPage(pageA, allows)
                        const resA = await pageA.goto(authz.endpointUrl, { waitUntil: "domcontentloaded" })
                        const statusA = resA ? resA.status() : 0
                        const bodyA = (await pageA.content()).length

                        const ctxB = await browser.newContext({ storageState: roleBProfile!.storageState })
                        const pageB = await ctxB.newPage()
                        await guardPage(pageB, allows)
                        const resB = await pageB.goto(authz.endpointUrl, { waitUntil: "domcontentloaded" })
                        const statusB = resB ? resB.status() : 0
                        const bodyB = (await pageB.content()).length

                        await ctxA.close()
                        await ctxB.close()

                        const potentialBOLA = statusA === 200 && statusB === 200 && Math.abs(bodyA - bodyB) < 100
                        return {
                          action: "check_authz",
                          url: input.url,
                          success: true,
                          authzDiscrepancy: {
                            roleAStatus: statusA,
                            roleBStatus: statusB,
                            roleABodyLength: bodyA,
                            roleBBodyLength: bodyB,
                            potentialBOLA,
                            details: potentialBOLA
                              ? "Both roles accessed identical endpoint data with HTTP 200 - potential BOLA/IDOR vulnerability"
                              : "Access controls differentiated response correctly between roles",
                          },
                        }
                      }

                      case "dom_xss": {
                        const probeId = `argos_dom_${Date.now()}`
                        const sinksDetected: Array<{ sink: string; payload: string; stack?: string }> = []

                        await page.exposeFunction(
                          "__argos_sink_report",
                          (sink: string, payload: string, stack: string) => {
                            sinksDetected.push({ sink, payload, stack })
                          },
                        )

                        await page.addInitScript((probe) => {
                          const innerHTMLDescriptor = Object.getOwnPropertyDescriptor(Element.prototype, "innerHTML")
                          const originalInnerHTML = innerHTMLDescriptor ? Reflect.get(innerHTMLDescriptor, "set") : undefined
                          if (typeof originalInnerHTML === "function") {
                            Object.defineProperty(Element.prototype, "innerHTML", {
                              set(val) {
                                if (typeof val === "string" && val.includes(probe)) {
                                  ;(window as any).__argos_sink_report(
                                    "Element.innerHTML",
                                    val,
                                    new Error().stack || "",
                                  )
                                }
                                return Reflect.apply(originalInnerHTML, this, [val])
                              },
                            })
                          }

                          const originalDocumentWrite = document.write.bind(document)
                          document.write = function (...args) {
                            const str = args.join("")
                            if (str.includes(probe)) {
                              ;(window as any).__argos_sink_report("document.write", str, new Error().stack || "")
                            }
                            return originalDocumentWrite(...args)
                          }
                        }, probeId)

                        const separator = input.url.includes("?") ? "&" : "?"
                        const probeParam = input.xssParam || "q"
                        const targetUrlWithProbe = `${input.url}${separator}${probeParam}=${encodeURIComponent(probeId)}#${probeId}`

                        await page.goto(targetUrlWithProbe, { waitUntil: "domcontentloaded" })
                        await page.waitForTimeout(1000)

                        return {
                          action: "dom_xss",
                          url: input.url,
                          success: true,
                          title: await page.title(),
                          domXssSinks: sinksDetected,
                        }
                      }
                    }
                  } finally {
                    if (browser) {
                      await browser.close().catch(() => {})
                    }
                  }
                },
                catch: (err) =>
                  new ToolFailure({
                    message:
                      input.action === "login" || input.action === "check_authz"
                        ? "Browser authenticated operation failed"
                        : `Browser execution error: ${err instanceof Error ? err.message : String(err)}`,
                  }),
              })
            }).pipe(
              Effect.mapError((err) =>
                err instanceof ToolFailure ? err : new ToolFailure({ message: `Browser tool error: ${String(err)}` }),
              ),
            ),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

/**
 * Layer shipped to the runtime: the scope service is resolved from the
 * installation database.
 */
export const layer = layerWithScopeService.pipe(
  Layer.provide(ScopeService.defaultLayer),
  Layer.provide(AuthSecretVault.layer),
)

#!/usr/bin/env node
import { pathToFileURL } from "node:url"
import { resolve } from "node:path"

const actions = new Set(["navigate", "login", "check_authz", "dom_xss"])

export async function executeBrowserRequest(request, dependencies) {
  const proxyURL = validateScopeGatewayProxy(dependencies?.proxyURL)
  const chromium = dependencies?.chromium
  if (!chromium || typeof chromium.launch !== "function") throw new Error("Playwright Chromium is unavailable")
  if (!request || typeof request !== "object" || !actions.has(request.action)) {
    throw new Error("Browser action must be navigate, login, check_authz, or dom_xss")
  }
  const target = validateHTTPURL(request.url)
  const timeoutSeconds = request.timeoutSeconds ?? 30
  if (!Number.isInteger(timeoutSeconds) || timeoutSeconds < 1 || timeoutSeconds > 120) {
    throw new Error("timeoutSeconds must be between 1 and 120")
  }

  const browser = await chromium.launch({
    headless: true,
    chromiumSandbox: true,
    timeout: Math.min(timeoutSeconds * 1000, 30_000),
    proxy: { server: proxyURL, bypass: "" },
    args: [
      "--disable-background-networking",
      "--disable-component-update",
      "--disable-default-apps",
      "--disable-sync",
      "--no-default-browser-check",
      "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
    ],
  })
  const contexts = []
  const makeContext = async (storageState) => {
    const options = { acceptDownloads: false, serviceWorkers: "block" }
    if (storageState !== undefined) options.storageState = parseStorageState(storageState)
    const context = await browser.newContext(options)
    contexts.push(context)
    await installRequestGuards(context)
    return context
  }

  try {
    switch (request.action) {
      case "navigate": {
        const context = await makeContext(request.storageState)
        const page = await context.newPage()
        const assertScopeAllowed = monitorScopeGateway(page)
        page.setDefaultTimeout(timeoutSeconds * 1000)
        const response = await page.goto(target, { waitUntil: "domcontentloaded" })
        assertScopeAllowed(response)
        const title = await page.title()
        const links = await page.$$eval("a[href]", (elements) =>
          elements.map((element) => element.href).filter(Boolean),
        )
        const forms = await page.$$eval("form", (elements) =>
          elements.map((element) => {
            const inputs = Array.from(element.querySelectorAll("input, select, textarea")).map(
              (input) => input.name || input.id || "unnamed",
            )
            return { action: element.action || "", method: element.method || "GET", inputs }
          }),
        )
        return { action: request.action, url: target, success: true, title, links: [...new Set(links)].slice(0, 100), forms }
      }
      case "login": {
        if (!request.credentials || !request.credentials.username || !request.credentials.password) {
          throw new Error("credentials with username and password are required for login")
        }
        const context = await makeContext(request.storageState)
        const page = await context.newPage()
        const assertScopeAllowed = monitorScopeGateway(page)
        page.setDefaultTimeout(timeoutSeconds * 1000)
        const response = await page.goto(target, { waitUntil: "domcontentloaded" })
        assertScopeAllowed(response)
        const credentials = request.credentials
        const userSelector = credentials.userSelector || "input[type='text'], input[type='email'], input[name*='user']"
        const passwordSelector = credentials.passwordSelector || "input[type='password']"
        const submitSelector = credentials.submitSelector || "button[type='submit'], input[type='submit']"
        await page.fill(userSelector, credentials.username)
        await page.fill(passwordSelector, credentials.password)
        await Promise.all([
          page.waitForLoadState("domcontentloaded").catch(() => {}),
          page.click(submitSelector).catch(() => page.keyboard.press("Enter")),
        ])
        assertScopeAllowed()
        let authenticationStatus = "unverified"
        if (credentials.successSelector) {
          authenticationStatus = await page
            .locator(credentials.successSelector)
            .first()
            .waitFor({ state: "visible", timeout: Math.min(timeoutSeconds * 1000, 5_000) })
            .then(() => "authenticated")
            .catch(() => "not_authenticated")
        }
        return {
          action: request.action,
          url: target,
          success: true,
          authenticationStatus,
          title: await page.title(),
          storageState: JSON.stringify(await context.storageState()),
        }
      }
      case "check_authz": {
        const compare = request.authzCompare
        if (!compare) throw new Error("authzCompare is required for check_authz")
        const endpointURL = validateHTTPURL(compare.endpointUrl)
        const contextA = await makeContext(compare.roleAStorageState)
        const pageA = await contextA.newPage()
        const assertRoleAScopeAllowed = monitorScopeGateway(pageA)
        pageA.setDefaultTimeout(timeoutSeconds * 1000)
        const responseA = await pageA.goto(endpointURL, { waitUntil: "domcontentloaded" })
        assertRoleAScopeAllowed(responseA)
        const statusA = responseA ? responseA.status() : 0
        const bodyA = (await pageA.content()).length
        const contextB = await makeContext(compare.roleBStorageState)
        const pageB = await contextB.newPage()
        const assertRoleBScopeAllowed = monitorScopeGateway(pageB)
        pageB.setDefaultTimeout(timeoutSeconds * 1000)
        const responseB = await pageB.goto(endpointURL, { waitUntil: "domcontentloaded" })
        assertRoleBScopeAllowed(responseB)
        const statusB = responseB ? responseB.status() : 0
        const bodyB = (await pageB.content()).length
        const potentialBOLA = statusA === 200 && statusB === 200 && Math.abs(bodyA - bodyB) < 100
        return {
          action: request.action,
          url: target,
          success: true,
          authzDiscrepancy: {
            roleAStatus: statusA,
            roleBStatus: statusB,
            roleABodyLength: bodyA,
            roleBBodyLength: bodyB,
            potentialBOLA,
            details: potentialBOLA
              ? "Both roles accessed similar endpoint responses with HTTP 200; this is a potential BOLA/IDOR finding that requires independent validation."
              : "Access controls produced different responses for the two roles.",
          },
        }
      }
      case "dom_xss": {
        const context = await makeContext(request.storageState)
        const page = await context.newPage()
        const assertScopeAllowed = monitorScopeGateway(page)
        page.setDefaultTimeout(timeoutSeconds * 1000)
        const probeId = `argos_dom_${crypto.randomUUID()}`
        const sinksDetected = []
        await page.exposeFunction("__argos_sink_report", (sink, payload, stack) => {
          sinksDetected.push({ sink, payload, stack })
        })
        await page.addInitScript((probe) => {
          const innerHTMLSetter = Object.getOwnPropertyDescriptor(Element.prototype, "innerHTML")?.set
          if (innerHTMLSetter) {
            Object.defineProperty(Element.prototype, "innerHTML", {
              set(value) {
                if (typeof value === "string" && value.includes(probe)) {
                  window.__argos_sink_report("Element.innerHTML", value, new Error().stack || "")
                }
                return innerHTMLSetter.call(this, value)
              },
            })
          }
          const documentWrite = document.write
          document.write = function (...values) {
            const value = values.join("")
            if (value.includes(probe)) window.__argos_sink_report("document.write", value, new Error().stack || "")
            return documentWrite.apply(this, values)
          }
        }, probeId)

        const probeURL = new URL(target)
        const parameter = request.xssParam || "q"
        if (!/^[A-Za-z0-9_.-]{1,64}$/.test(parameter)) throw new Error("xssParam contains invalid characters")
        probeURL.searchParams.set(parameter, probeId)
        probeURL.hash = probeId
        await page.goto(probeURL.toString(), { waitUntil: "domcontentloaded" })
        await page.waitForTimeout(1000)
        assertScopeAllowed()
        return {
          action: request.action,
          url: target,
          success: true,
          title: await page.title(),
          domXssSinks: sinksDetected,
        }
      }
    }
  } finally {
    for (const context of contexts) await context.close().catch(() => {})
    await browser.close().catch(() => {})
  }
}

export async function preflightBrowser(chromium) {
  if (!chromium || typeof chromium.launch !== "function") throw new Error("Playwright Chromium is unavailable")
  const browser = await chromium.launch({
    headless: true,
    chromiumSandbox: true,
    timeout: 30_000,
    args: [
      "--disable-background-networking",
      "--disable-component-update",
      "--disable-default-apps",
      "--disable-sync",
      "--no-default-browser-check",
      "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
    ],
  })
  try {
    return { status: "ready", browserVersion: browser.version() }
  } finally {
    await browser.close()
  }
}

async function installRequestGuards(context) {
  if (typeof context.route !== "function" || typeof context.routeWebSocket !== "function") {
    throw new Error("Playwright request and WebSocket guards are unavailable")
  }
  await context.route("**/*", async (route) => {
    let protocol = ""
    try {
      protocol = new URL(route.request().url()).protocol
    } catch {
      await route.abort("blockedbyclient").catch(() => {})
      return
    }
    if (protocol !== "http:" && protocol !== "https:") {
      await route.abort("blockedbyclient").catch(() => {})
      return
    }
    await route.continue().catch(() => {})
  })
  await context.routeWebSocket("**/*", (socket) => {
    socket.close({ code: 1008, reason: "WebSocket traffic is disabled for scoped browser audits" })
  })
}

function monitorScopeGateway(page) {
  let blocked = false
  const observe = (response) => {
    const headers = response?.headers?.()
    if (
      headers &&
      Object.entries(headers).some(
        ([name, value]) => name.toLowerCase() === "x-argos-scope-blocked" && value.toLowerCase() === "true",
      )
    ) {
      blocked = true
    }
  }
  if (typeof page.on === "function") page.on("response", observe)
  return (response) => {
    observe(response)
    if (blocked) throw new Error("request blocked by Argos scope gateway")
  }
}

function validateScopeGatewayProxy(raw) {
  if (typeof raw !== "string" || raw.trim() === "") {
    throw new Error("Argos scope gateway proxy is unavailable; browser execution is blocked")
  }
  let proxy
  try {
    proxy = new URL(raw)
  } catch {
    throw new Error("Argos scope gateway proxy is invalid; browser execution is blocked")
  }
  if (
    proxy.protocol !== "http:" ||
    proxy.hostname !== "127.0.0.1" ||
    !proxy.port ||
    proxy.username ||
    proxy.password ||
    (proxy.pathname !== "" && proxy.pathname !== "/") ||
    proxy.search ||
    proxy.hash
  ) {
    throw new Error("Argos scope gateway proxy must be a loopback HTTP endpoint; browser execution is blocked")
  }
  return proxy.origin
}

function validateHTTPURL(raw) {
  let target
  try {
    target = new URL(raw)
  } catch {
    throw new Error("browser targets must be valid HTTP(S) URLs")
  }
  if ((target.protocol !== "http:" && target.protocol !== "https:") || target.username || target.password) {
    throw new Error("browser targets must use HTTP(S) and cannot contain URL credentials")
  }
  return target.toString()
}

function parseStorageState(raw) {
  const state = typeof raw === "string" ? JSON.parse(raw) : raw
  if (!state || typeof state !== "object" || Array.isArray(state)) {
    throw new Error("storage state must be a JSON object")
  }
  return state
}

async function main() {
  const playwrightModule = await import(process.env.ARGOS_PLAYWRIGHT_MODULE || "/opt/argos/browser/node_modules/playwright-core/index.mjs")
  const { chromium } = playwrightModule
  if (process.argv.includes("--version")) {
    process.stdout.write(`${process.env.ARGOS_WORKER_VERSION || "dev"} playwright-core/${process.env.ARGOS_PLAYWRIGHT_VERSION || "unknown"}\n`)
    return
  }
  if (process.argv.includes("--preflight")) {
    process.stdout.write(`${JSON.stringify(await preflightBrowser(chromium))}\n`)
    return
  }
  const chunks = []
  let inputSize = 0
  for await (const chunk of process.stdin) {
    inputSize += chunk.length
    if (inputSize > 1 << 20) throw new Error("browser request exceeds the 1 MiB input limit")
    chunks.push(chunk)
  }
  const request = JSON.parse(Buffer.concat(chunks).toString("utf8"))
  const output = await executeBrowserRequest(request, {
    chromium,
    proxyURL: process.env.ARGOS_WORKER_PROXY_URL,
  })
  process.stdout.write(`${JSON.stringify(output)}\n`)
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`)
    process.exitCode = 1
  })
}

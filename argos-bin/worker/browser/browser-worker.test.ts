import { describe, expect, it } from "bun:test"
import { executeBrowserRequest } from "./browser-worker.mjs"

describe("container browser worker", () => {
  it("refuses to launch unless the controller scope gateway provides a loopback proxy", async () => {
    let launches = 0
    const chromium = {
      launch: async () => {
        launches++
        throw new Error("must not launch")
      },
    }

    await expect(
      executeBrowserRequest(
        { action: "navigate", url: "https://app.example.test" },
        { chromium, proxyURL: "http://proxy.example.test:8080" },
      ),
    ).rejects.toThrow("scope gateway proxy")
    expect(launches).toBe(0)
  })

  it("routes browser traffic through the relay, blocks service workers and returns real navigation data", async () => {
    let launchOptions: Record<string, any> | undefined
    let contextOptions: Record<string, any> | undefined
    let requestRoute: ((route: any) => Promise<void>) | undefined
    let websocketRoute: ((route: any) => void) | undefined
    let browserClosed = false
    let contextClosed = false
    const page = {
      timeout: 0,
      setDefaultTimeout(milliseconds: number) {
        this.timeout = milliseconds
      },
      async goto(url: string) {
        return { status: () => (url.includes("/app") ? 200 : 0) }
      },
      async title() {
        return "Controlled app"
      },
      async $$eval(selector: string, callback: (elements: any[]) => any) {
        if (selector === "a[href]") return callback([{ href: "https://app.example.test/account" }])
        if (selector === "form") return callback([])
        return []
      },
    }
    const context = {
      async route(_pattern: string, handler: (route: any) => Promise<void>) {
        requestRoute = handler
      },
      async routeWebSocket(_pattern: string, handler: (route: any) => void) {
        websocketRoute = handler
      },
      async newPage() {
        return page
      },
      async close() {
        contextClosed = true
      },
    }
    const browser = {
      async newContext(options: Record<string, any>) {
        contextOptions = options
        return context
      },
      async close() {
        browserClosed = true
      },
    }
    const chromium = {
      async launch(options: Record<string, any>) {
        launchOptions = options
        return browser
      },
    }

    const result = await executeBrowserRequest(
      { action: "navigate", url: "https://app.example.test/app", timeoutSeconds: 12 },
      { chromium, proxyURL: "http://127.0.0.1:43127" },
    )

    expect(launchOptions?.proxy).toEqual({ server: "http://127.0.0.1:43127", bypass: "" })
    expect(launchOptions?.chromiumSandbox).toBe(true)
    expect(contextOptions).toMatchObject({ serviceWorkers: "block", acceptDownloads: false })
    expect(requestRoute).toBeFunction()
    expect(websocketRoute).toBeFunction()
    expect(page.timeout).toBe(12_000)
    expect(result).toMatchObject({
      action: "navigate",
      url: "https://app.example.test/app",
      success: true,
      title: "Controlled app",
      links: ["https://app.example.test/account"],
      forms: [],
    })
    expect(contextClosed).toBe(true)
    expect(browserClosed).toBe(true)
  })

  it("reports a scope-gateway denial as a failed navigation", async () => {
    let responseHandler: ((response: any) => void) | undefined
    const page = {
      on(event: string, handler: (response: any) => void) {
        if (event === "response") responseHandler = handler
      },
      setDefaultTimeout() {},
      async goto() {
        const response = {
          status: () => 403,
          headers: () => ({ "x-argos-scope-blocked": "true" }),
        }
        responseHandler?.(response)
        return response
      },
      async title() {
        return "Forbidden"
      },
      async $$eval() {
        return []
      },
    }
    const context = {
      async route() {},
      async routeWebSocket() {},
      async newPage() {
        return page
      },
      async close() {},
    }
    const chromium = {
      async launch() {
        return { newContext: async () => context, close: async () => {} }
      },
    }

    await expect(
      executeBrowserRequest(
        { action: "navigate", url: "http://127.0.0.1/admin/secret" },
        { chromium, proxyURL: "http://127.0.0.1:43127" },
      ),
    ).rejects.toThrow("blocked by Argos scope gateway")
  })

  it("aborts a request that leaves HTTP(S) before a browser page can navigate it", async () => {
    let requestRoute: ((route: any) => Promise<void>) | undefined
    const page = {
      setDefaultTimeout() {},
      async goto() {
        return { status: () => 200 }
      },
      async title() {
        return "Controlled app"
      },
      async $$eval() {
        return []
      },
    }
    const context = {
      async route(_pattern: string, handler: (route: any) => Promise<void>) {
        requestRoute = handler
      },
      async routeWebSocket(_pattern: string, handler: (route: any) => void) {
        handler({ close() {} })
      },
      async newPage() {
        return page
      },
      async close() {},
    }
    const chromium = {
      async launch() {
        return { newContext: async () => context, close: async () => {} }
      },
    }
    await executeBrowserRequest(
      { action: "navigate", url: "https://app.example.test" },
      { chromium, proxyURL: "http://127.0.0.1:43127" },
    )

    let aborted = false
    await requestRoute?.({
      request: () => ({ url: () => "file:///etc/passwd" }),
      abort: async () => {
        aborted = true
      },
      continue: async () => {
        throw new Error("unsafe request continued")
      },
    })
    expect(aborted).toBe(true)
  })

  it("does not claim login succeeded without an explicit visible success selector", async () => {
    const page = {
      setDefaultTimeout() {},
      async goto() {
        return { status: () => 200 }
      },
      async fill() {},
      async waitForLoadState() {},
      async click() {},
      keyboard: { async press() {} },
      async title() {
        return "Login"
      },
      locator(selector: string) {
        return {
          first() {
            return {
              async waitFor() {
                if (selector !== "[data-testid='signed-in']") throw new Error("selector not found")
              },
            }
          },
        }
      },
    }
    const context = {
      async route() {},
      async routeWebSocket() {},
      async newPage() {
        return page
      },
      async storageState() {
        return { cookies: [], origins: [] }
      },
      async close() {},
    }
    const chromium = {
      async launch() {
        return {
          async newContext() {
            return context
          },
          async close() {},
        }
      },
    }
    const dependencies = { chromium, proxyURL: "http://127.0.0.1:43127" }
    const request = {
      action: "login",
      url: "https://app.example.test/login",
      credentials: { username: "alice", password: "secret" },
    }

    const unverified = await executeBrowserRequest(request, dependencies)
    const verified = await executeBrowserRequest(
      { ...request, credentials: { ...request.credentials, successSelector: "[data-testid='signed-in']" } },
      dependencies,
    )

    expect(unverified).toMatchObject({ success: true, authenticationStatus: "unverified" })
    expect(verified).toMatchObject({ success: true, authenticationStatus: "authenticated" })
  })
})

import { expect, test } from "@playwright/test"
import AxeBuilder from "@axe-core/playwright"
import { base64Encode } from "@/core/encode"
import { fixture, pageMessages } from "./session-timeline.fixture"
import { mockOpenCodeServer } from "../utils/mock-server"

test("primary frontend routes render, pass axe, and have no DevTools runtime errors", async ({ page }) => {
  const errors: string[] = []
  const devtools = await page.context().newCDPSession(page)
  await devtools.send("Log.enable")
  await devtools.send("Runtime.enable")
  devtools.on("Log.entryAdded", ({ entry }) => {
    if (entry.level === "error") errors.push(`${entry.text} (${entry.url}:${entry.lineNumber})`)
  })
  devtools.on("Runtime.exceptionThrown", ({ exceptionDetails }) => {
    errors.push(
      `${exceptionDetails.exception?.description ?? exceptionDetails.text} (${exceptionDetails.url}:${exceptionDetails.lineNumber})`,
    )
  })
  page.on("requestfailed", (request) => {
    const url = new URL(request.url())
    const errorText = request.failure()?.errorText
    if (url.pathname === "/global/event" && errorText === "net::ERR_ABORTED") return
    errors.push(`request failed: ${request.method()} ${request.url()} (${errorText})`)
  })
  page.on("response", (response) => {
    if (response.status() >= 400) errors.push(`HTTP ${response.status()}: ${response.url()}`)
  })
  page.on("pageerror", (error) => {
    if (!errors.some((item) => item.includes(error.message))) {
      errors.push(error.stack ?? error.message)
    }
  })
  await mockOpenCodeServer(page, {
    sessions: fixture.sessions,
    provider: fixture.provider,
    directory: fixture.directory,
    project: fixture.project,
    pageMessages,
  })

  const directory = `/${base64Encode(fixture.directory)}`
  const routes = [
    "/",
    `${directory}/session/${fixture.sourceID}`,
    `${directory}/findings`,
    `${directory}/topology`,
    `${directory}/reports`,
    `${directory}/compliance`,
    `${directory}/governance`,
    `${directory}/status`,
  ]

  for (const route of routes) {
    await page.goto(route)
    const heading = page.locator("main h1")
    await expect(heading, `page heading missing at ${route}`).toHaveCount(1)
    await expect(heading).not.toBeEmpty()
    const accessibility = await new AxeBuilder({ page }).exclude(".terminal").analyze()
    expect(accessibility.violations, `accessibility violations at ${route}`).toEqual([])
    if (route === "/") {
      await expect(page.getByRole("button", { name: "Abrir carpeta..." })).toBeVisible()
      await expect(page.locator("#prompt-attachment-input")).toHaveAttribute("name", "prompt-attachment-input")
    }
    expect(errors, `runtime errors at ${route}`).toEqual([])
    if (route === "/") {
      await expect(page.getByText("Local server", { exact: true })).toBeVisible()
      await expect(page.getByText("Windows Host", { exact: true })).toHaveCount(0)
      await expect(page.getByRole("button", { name: /configure scope/i })).toHaveCount(0)
      await expect(page.getByText("Open a project before configuring the audit scope.")).toBeVisible()
    }
  }
})

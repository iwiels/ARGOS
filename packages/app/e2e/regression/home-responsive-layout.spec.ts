import { expect, test } from "@playwright/test"
import { mockOpenCodeServer } from "../utils/mock-server"
import { fixture, pageMessages } from "../smoke/session-timeline.fixture"

test("home dashboard stays readable at the desktop minimum window size", async ({ page }) => {
  await page.setViewportSize({ width: 720, height: 480 })
  await mockOpenCodeServer(page, {
    sessions: fixture.sessions,
    provider: fixture.provider,
    directory: fixture.directory,
    project: fixture.project,
    pageMessages,
  })

  await page.goto("/")
  await expect(page.locator("main h1")).toBeVisible()

  const summary = page.locator("main .grid-cols-2").first()
  await expect
    .poll(() => summary.evaluate((element) => getComputedStyle(element).gridTemplateColumns.split(" ").length))
    .toBe(2)

  const description = page.getByText(/scans stay blocked|los escaneos permanecen bloqueados/i)
  const scopeNotice = description.locator("xpath=../../..")
  await expect(scopeNotice).toHaveCSS("flex-direction", "column")
  await expect(page.locator("html")).toHaveJSProperty("scrollWidth", 720)
})

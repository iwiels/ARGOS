import { expect, test } from "@playwright/test"
import AxeBuilder from "@axe-core/playwright"
import { mockOpenCodeServer } from "../utils/mock-server"
import { fixture } from "./session-timeline.fixture"

test.describe("smoke: accessibility E2E audit", () => {
  test("connection error page should have no automatically detectable WCAG violations", async ({ page }) => {
    await page.goto("/")
    await page.locator("h1").waitFor({ timeout: 15000 })

    // Run axe builder on connection error state
    const results = await new AxeBuilder({ page }).analyze()
    expect(results.violations).toEqual([])
  })

  test("main project dashboard should have no automatically detectable WCAG violations", async ({ page }) => {
    // Mock the backend Argos server to load the primary dashboard
    await mockOpenCodeServer(page, {
      sessions: fixture.sessions,
      provider: fixture.provider,
      directory: fixture.directory,
      project: fixture.project,
      pageMessages: [],
    })

    await page.goto("/")
    await page.locator("h1").waitFor({ timeout: 15000 })

    // Run accessibility scan
    const results = await new AxeBuilder({ page })
      .exclude(".terminal") // Exclude terminal component if any dynamic content is active
      .analyze()

    expect(results.violations).toEqual([])
  })
})


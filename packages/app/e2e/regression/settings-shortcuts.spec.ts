import { expect, test } from "@playwright/test"
import { mockOpenCodeServer } from "../utils/mock-server"
import { fixture, pageMessages } from "../smoke/session-timeline.fixture"

test("settings shortcuts tab renders its searchable keybinds", async ({ page }) => {
  await mockOpenCodeServer(page, {
    sessions: fixture.sessions,
    provider: fixture.provider,
    directory: fixture.directory,
    project: fixture.project,
    pageMessages,
  })

  await page.goto("/")
  await page.locator("main h1").waitFor()
  await page.getByRole("button", { name: /command palette|paleta de comandos/i }).click()
  await page.getByRole("option", { name: /open settings|abrir ajustes/i }).click()

  const dialog = page.getByRole("dialog", { name: /settings|ajustes/i })
  await dialog.getByRole("tab", { name: /shortcuts|atajos/i }).click()

  const panel = dialog.getByRole("tabpanel", { name: /shortcuts|atajos/i })
  await expect(panel.getByRole("heading", { name: /keyboard shortcuts|atajos de teclado/i })).toBeVisible()
  const search = panel.getByRole("searchbox", { name: /search shortcuts|buscar atajos/i })
  await expect(search).toBeVisible()
  await expect(search).toHaveAttribute("id", "settings-shortcuts-search")
  await expect(search).toHaveAttribute("name", "settings-shortcuts-search")
})

test("settings font fields have stable form identifiers", async ({ page }) => {
  await mockOpenCodeServer(page, {
    sessions: fixture.sessions,
    provider: fixture.provider,
    directory: fixture.directory,
    project: fixture.project,
    pageMessages,
  })

  await page.goto("/")
  await page.locator("main h1").waitFor()
  await page.getByRole("button", { name: /command palette|paleta de comandos/i }).click()
  await page.getByRole("option", { name: /open settings|abrir ajustes/i }).click()

  const dialog = page.getByRole("dialog", { name: /settings|ajustes/i })
  await expect(dialog.locator('input[name="settings-ui-font"]')).toHaveAttribute("id", "settings-ui-font")
  await expect(dialog.locator('input[name="settings-code-font"]')).toHaveAttribute("id", "settings-code-font")
  await expect(dialog.locator('input[name="settings-terminal-font"]')).toHaveAttribute("id", "settings-terminal-font")
})

test("Escape closes a settings dropdown without closing settings", async ({ page }) => {
  await mockOpenCodeServer(page, {
    sessions: fixture.sessions,
    provider: fixture.provider,
    directory: fixture.directory,
    project: fixture.project,
    pageMessages,
  })

  await page.goto("/")
  await page.locator("main h1").waitFor()
  await page.getByRole("button", { name: /command palette|paleta de comandos/i }).click()
  await page.getByRole("option", { name: /open settings|abrir ajustes/i }).click()

  const dialog = page.getByRole("dialog", { name: /settings|ajustes/i })
  const themeSelect = dialog.getByRole("button", { name: /system|sistema/i })
  await themeSelect.click()
  await expect(themeSelect).toHaveAttribute("aria-expanded", "true")
  await page.keyboard.press("Escape")
  await expect(themeSelect).toHaveAttribute("aria-expanded", "false")
  await expect(dialog).toBeVisible()
})

test("settings model search has stable form identifiers", async ({ page }) => {
  await mockOpenCodeServer(page, {
    sessions: fixture.sessions,
    provider: fixture.provider,
    directory: fixture.directory,
    project: fixture.project,
    pageMessages,
  })

  await page.goto("/")
  await page.locator("main h1").waitFor()
  await page.getByRole("button", { name: /command palette|paleta de comandos/i }).click()
  await page.getByRole("option", { name: /open settings|abrir ajustes/i }).click()

  const dialog = page.getByRole("dialog", { name: /settings|ajustes/i })
  await dialog.getByRole("tab", { name: /models|modelos/i }).click()
  const search = dialog.getByRole("searchbox", { name: /search models|buscar modelos/i })
  await expect(search).toBeVisible()
  await expect(search).toHaveAttribute("id", "settings-model-search")
  await expect(search).toHaveAttribute("name", "settings-model-search")
  await search.fill("no-such-model")
  const clear = dialog.getByRole("button", { name: /clear search|limpiar búsqueda/i })
  await expect(clear).toBeVisible()
  await expect(clear).toHaveCSS("width", "24px")
  await expect(clear).toHaveCSS("height", "24px")
  await clear.click()
  await expect(search).toHaveValue("")
})

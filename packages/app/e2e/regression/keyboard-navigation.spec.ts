import { expect, test, type Page } from "@playwright/test"
import { mockOpenCodeServer } from "../utils/mock-server"
import { expectAppVisible, expectSessionTitle } from "../utils/waits"

const directory = "C:/OpenCode/KeyboardNavigation"
const projectID = "proj_keyboard_navigation"
const sessionID = "ses_keyboard_navigation"
const sessionTitle = "Keyboard navigation"

// Verified against DEFAULT_PALETTE_KEYBIND ("mod+shift+p") in src/context/command.tsx;
// review panel toggle is registered with "mod+shift+r" in pages/session/use-session-commands.tsx.
const paletteKeybind = process.platform === "darwin" ? "Meta+Shift+P" : "Control+Shift+P"
const reviewPanelKeybind = process.platform === "darwin" ? "Meta+Shift+R" : "Control+Shift+R"

test.describe("regression: keyboard navigation", () => {
  test("tab cycles focus through distinct interactive elements and shift-tab reverses", async ({ page }) => {
    await page.goto("/")
    await page.waitForLoadState("domcontentloaded")

    await page.keyboard.press("Tab")
    const first = await readFocusState(page)
    expect(first.tag === "BODY" || first.tag === "NONE").toBe(false)
    expect(first.interactive).toBe(true)
    expect(first.hidden).toBe(false)

    const visited = new Map([[first.html, first]])
    for (let step = 0; step < 20; step++) {
      await page.keyboard.press("Tab")
      const current = await readFocusState(page)
      if (current.tag === "BODY" || current.tag === "NONE") break
      expect(current.interactive).toBe(true)
      expect(current.hidden).toBe(false)
      if (visited.has(current.html)) break
      visited.set(current.html, current)
    }
    expect(visited.size).toBeGreaterThanOrEqual(2)

    const beforeShift = await readFocusState(page)
    await page.keyboard.press("Shift+Tab")
    const afterShift = await readFocusState(page)
    expect(afterShift.tag === "BODY" || afterShift.tag === "NONE").toBe(false)
    expect(afterShift.html).not.toBe(beforeShift.html)
    expect(visited.has(afterShift.html)).toBe(true)
  })

  test("command palette traps focus, moves active option with arrows, selects with Enter and closes with Escape", async ({
    page,
  }) => {
    await page.setViewportSize({ width: 1400, height: 900 })
    await mockSessionBackend(page)
    await page.goto(`/${base64Encode(directory)}/session/${sessionID}`)
    await expectSessionTitle(page, sessionTitle)

    const dialog = page.locator('[data-slot="dialog-content"]')
    await expect(dialog).toHaveCount(0)

    await page.keyboard.press(paletteKeybind)
    await expectAppVisible(dialog)

    const search = dialog.locator("input")
    await expect(search).toBeFocused()

    // Tab presses must stay trapped inside the modal dialog.
    for (let step = 0; step < 4; step++) {
      await page.keyboard.press("Tab")
      const trapped = await page.evaluate(() => !!document.activeElement?.closest('[data-slot="dialog-content"]'))
      expect(trapped, `Tab #${step + 1} escaped the dialog`).toBe(true)
    }

    // ArrowDown moves the active option: aria-activedescendant follows data-active.
    const initialId = await search.getAttribute("aria-activedescendant")
    expect(initialId, "palette should open with an active option").toBeTruthy()
    await page.keyboard.press("ArrowDown")
    const nextId = await search.getAttribute("aria-activedescendant")
    expect(nextId).toBeTruthy()
    expect(nextId, "ArrowDown should move the active option").not.toBe(initialId)
    await expect(dialog.locator('[data-slot="list-item"][data-active="true"]')).toHaveAttribute("id", nextId!)

    // Enter commits the active option and dismisses the palette.
    await page.keyboard.press("Enter")
    await expect(dialog).toHaveCount(0)

    // Escape closes it again. Programmatic dialogs have no Kobalte trigger ref,
    // so focus falls back to <body> instead of a trigger element.
    await page.getByRole("button", { name: "Command palette" }).click()
    await expectAppVisible(dialog)
    await page.keyboard.press("Escape")
    await expect(dialog).toHaveCount(0)
    await expect.poll(() => page.evaluate(() => document.activeElement?.tagName ?? "")).toBe("BODY")
  })

  test("resize handle adjusts panel size with arrow keys", async ({ page }) => {
    await page.setViewportSize({ width: 1400, height: 900 })
    await mockSessionBackend(page)
    await page.goto(`/${base64Encode(directory)}/session/${sessionID}`)
    await expectSessionTitle(page, sessionTitle)

    // Open the review side panel; the horizontal resizer renders along its edge.
    await page.keyboard.press(reviewPanelKeybind)
    const handle = page.locator('[data-component="resize-handle"][data-direction="horizontal"]').first()
    await expectAppVisible(handle)

    await handle.focus()
    await expect(handle).toHaveAttribute("role", "separator")

    // Horizontal handles step by 20px: ArrowRight grows, ArrowLeft shrinks back.
    const before = Number(await handle.getAttribute("aria-valuenow"))
    await page.keyboard.press("ArrowRight")
    await expect(handle).toHaveAttribute("aria-valuenow", String(before + 20))
    await page.keyboard.press("ArrowLeft")
    await expect(handle).toHaveAttribute("aria-valuenow", String(before))
  })
})

async function mockSessionBackend(page: Page) {
  await mockOpenCodeServer(page, {
    directory,
    project: {
      id: projectID,
      worktree: directory,
      vcs: "git",
      name: "keyboard-navigation",
      time: { created: 1700000000000, updated: 1700000000000 },
      sandboxes: [],
    },
    provider: {
      all: [
        {
          id: "opencode",
          name: "OpenCode",
          models: { "claude-opus-4-6": { id: "claude-opus-4-6", name: "Claude Opus 4.6", limit: { context: 200_000 } } },
        },
      ],
      connected: ["opencode"],
      default: { providerID: "opencode", modelID: "claude-opus-4-6" },
    },
    sessions: [
      {
        id: sessionID,
        slug: "keyboard-navigation",
        projectID,
        directory,
        title: sessionTitle,
        version: "dev",
        time: { created: 1700000000000, updated: 1700000000000 },
      },
    ],
    pageMessages: () => ({ items: [] }),
  })
}

async function readFocusState(page: Page) {
  return page.evaluate(() => {
    const element = document.activeElement
    const style = element ? getComputedStyle(element) : undefined
    return {
      tag: element?.tagName ?? "NONE",
      html: element?.outerHTML ?? "",
      interactive: !!element?.matches(
        'a[href],button:not(:disabled),input:not(:disabled),textarea:not(:disabled),select:not(:disabled),[contenteditable="true"],[tabindex]:not([tabindex="-1"])',
      ),
      hidden:
        !element ||
        !!element.closest('[aria-hidden="true"],[inert]') ||
        style?.visibility === "hidden" ||
        style?.display === "none" ||
        element.getClientRects().length === 0,
    }
  })
}

function base64Encode(value: string) {
  return Buffer.from(value, "utf8").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "")
}

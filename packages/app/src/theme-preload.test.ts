import { beforeEach, describe, expect, test } from "bun:test"

const src = await Bun.file(new URL("../public/argos-theme-preload.js", import.meta.url)).text()

const run = () => Function(src)()

beforeEach(() => {
  document.head.innerHTML = ""
  document.documentElement.removeAttribute("data-color-scheme")
  localStorage.clear()
  Object.defineProperty(window, "matchMedia", {
    value: () =>
      ({
        matches: false,
      }) as MediaQueryList,
    configurable: true,
  })
})

describe("theme preload", () => {
  test("dark loads dark preferences", () => {
    localStorage.setItem("argos-color-scheme", "dark")

    run()

    expect(document.documentElement.dataset.colorScheme).toBe("dark")
  })

  test("light loads light preferences", () => {
    localStorage.setItem("argos-color-scheme", "light")

    run()

    expect(document.documentElement.dataset.colorScheme).toBe("light")
  })

  test("system resolves from matchMedia (light)", () => {
    run()

    expect(document.documentElement.dataset.colorScheme).toBe("light")
  })

  test("system resolves from matchMedia (dark)", () => {
    Object.defineProperty(window, "matchMedia", {
      value: () =>
        ({
          matches: true,
        }) as MediaQueryList,
      configurable: true,
    })

    run()

    expect(document.documentElement.dataset.colorScheme).toBe("dark")
  })

  test("sets theme-color meta to match mode", () => {
    document.head.innerHTML = '<meta name="theme-color" content="#0A0F0C" />'

    localStorage.setItem("argos-color-scheme", "light")
    run()
    expect(document.querySelector('meta[name="theme-color"]')?.getAttribute("content")).toBe("#fafafa")

    localStorage.setItem("argos-color-scheme", "dark")
    run()
    expect(document.querySelector('meta[name="theme-color"]')?.getAttribute("content")).toBe("#121212")
  })

  test("never sets data-theme (unified on data-color-scheme only)", () => {
    localStorage.setItem("argos-color-scheme", "dark")

    run()

    expect(document.documentElement.hasAttribute("data-theme")).toBe(false)
    expect(document.documentElement.dataset.colorScheme).toBe("dark")
  })
})

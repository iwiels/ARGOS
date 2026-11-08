import { describe, expect, test } from "bun:test"
import * as fc from "fast-check"
import { formatKeybind, matchKeybind, parseKeybind } from "./command"

describe("command keybind helpers", () => {
  test("parseKeybind handles aliases and multiple combos", () => {
    const keybinds = parseKeybind("control+option+k, mod+shift+comma")

    expect(keybinds).toHaveLength(2)
    expect(keybinds[0]).toEqual({
      key: "k",
      ctrl: true,
      meta: false,
      shift: false,
      alt: true,
    })
    expect(keybinds[1]?.shift).toBe(true)
    expect(keybinds[1]?.key).toBe("comma")
    expect(keybinds[1]?.ctrl || keybinds[1]?.meta).toBeTruthy()
  })

  test("parseKeybind treats none and empty as disabled", () => {
    expect(parseKeybind("none")).toEqual([])
    expect(parseKeybind("")).toEqual([])
  })

  test("matchKeybind normalizes punctuation keys", () => {
    const keybinds = parseKeybind("ctrl+comma, shift+plus, meta+space")

    expect(matchKeybind(keybinds, new KeyboardEvent("keydown", { key: ",", ctrlKey: true }))).toBe(true)
    expect(matchKeybind(keybinds, new KeyboardEvent("keydown", { key: "+", shiftKey: true }))).toBe(true)
    expect(matchKeybind(keybinds, new KeyboardEvent("keydown", { key: " ", metaKey: true }))).toBe(true)
    expect(matchKeybind(keybinds, new KeyboardEvent("keydown", { key: ",", ctrlKey: true, altKey: true }))).toBe(false)
  })

  test("matchKeybind supports bracket keys", () => {
    const keybinds = parseKeybind("mod+alt+[, mod+alt+]")
    const prev = keybinds[0]
    const next = keybinds[1]

    expect(
      matchKeybind(
        keybinds,
        new KeyboardEvent("keydown", { key: "[", ctrlKey: prev?.ctrl, metaKey: prev?.meta, altKey: true }),
      ),
    ).toBe(true)
    expect(
      matchKeybind(
        keybinds,
        new KeyboardEvent("keydown", { key: "]", ctrlKey: next?.ctrl, metaKey: next?.meta, altKey: true }),
      ),
    ).toBe(true)
  })

  test("formatKeybind returns human readable output", () => {
    const display = formatKeybind("ctrl+alt+arrowup")

    expect(display).toContain("↑")
    expect(display.includes("Ctrl") || display.includes("⌃")).toBe(true)
    expect(display.includes("Alt") || display.includes("⌥")).toBe(true)
    expect(formatKeybind("none")).toBe("")
  })

  test("formatKeybind prefers the first combo", () => {
    const display = formatKeybind("mod+k,mod+p")

    expect(display.includes("K") || display.includes("k")).toBe(true)
    expect(display.includes("P") || display.includes("p")).toBe(false)
  })
})

describe("parseKeybind property tests", () => {
  test("invariance: all parsed keybinds have required fields", () => {
    fc.assert(
      fc.property(
        fc
          .record({
            key: fc.string({ minLength: 1, maxLength: 20 }),
            modifiers: fc.array(fc.constantFrom("ctrl", "alt", "shift", "meta", "mod")),
          })
          .map(({ key, modifiers }) => [...modifiers, key].join("+")),
        (input) => {
          const result = parseKeybind(input)
          for (const kb of result) {
            expect(typeof kb.key).toBe("string")
            expect(typeof kb.ctrl).toBe("boolean")
            expect(typeof kb.meta).toBe("boolean")
            expect(typeof kb.shift).toBe("boolean")
            expect(typeof kb.alt).toBe("boolean")
          }
        },
      ),
    )
  })

  test("invariance: each combo with a real key produces exactly one keybind", () => {
    fc.assert(
      fc.property(
        fc
          .tuple(
            fc.string({ minLength: 1, maxLength: 10 }).filter((s) => s.trim().length > 0),
            fc.array(fc.constantFrom("ctrl", "alt", "shift", "meta")),
          )
          .map(([key, mods]) => [...mods, key].join("+")),
        (combo) => {
          const [parsed] = parseKeybind(combo)
          expect(parsed).toBeDefined()
          if (parsed) expect(typeof parsed.key).toBe("string")
        },
      ),
    )
  })

  test("invariance: none and empty return empty array", () => {
    expect(parseKeybind("none")).toEqual([])
    expect(parseKeybind("")).toEqual([])
  })

  test("round-trip: formatKeybind(parseKeybind(x)) is non-empty for valid combos", () => {
    fc.assert(
      fc.property(
        fc
          .tuple(
            fc.constantFrom("a", "b", "c", "x", "y", "z", "1", "2", "3", "comma", "enter", "space", "esc", "tab", "delete"),
            fc.array(fc.constantFrom("ctrl", "alt", "shift", "meta")),
          )
          .map(([key, mods]) => [...mods, key].join("+")),
        (combo) => {
          const formatted = formatKeybind(combo)
          expect(formatted.length).toBeGreaterThan(0)
        },
      ),
    )
  })
})



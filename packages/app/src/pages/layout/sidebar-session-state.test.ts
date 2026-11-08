import { describe, expect, test } from "bun:test"
import { focusSessionTitleEditor, transitionSessionInteraction, type SessionInteraction } from "./sidebar-session-state"

const idle: SessionInteraction = { type: "idle" }

describe("sidebar session interaction", () => {
  test("focuses and selects the title as soon as rename starts", () => {
    const input = document.createElement("input")
    input.value = "Existing session title"
    document.body.append(input)

    try {
      focusSessionTitleEditor(input)

      expect(document.activeElement).toBe(input)
      expect(input.selectionStart).toBe(0)
      expect(input.selectionEnd).toBe(input.value.length)
    } finally {
      input.remove()
    }
  })

  test("keeps only one menu or rename active at a time", () => {
    const renaming: SessionInteraction = { type: "rename", sessionID: "session-a" }

    expect(transitionSessionInteraction(renaming, { type: "open-menu", sessionID: "session-b" })).toEqual({
      type: "menu",
      sessionID: "session-b",
    })
  })

  test("a delayed close from a previous menu cannot cancel a rename", () => {
    const renaming: SessionInteraction = { type: "rename", sessionID: "session-a" }

    expect(transitionSessionInteraction(renaming, { type: "close-menu", sessionID: "session-a" })).toEqual(renaming)
  })

  test("choosing rename replaces the menu state", () => {
    const menu: SessionInteraction = { type: "menu", sessionID: "session-a" }

    expect(transitionSessionInteraction(menu, { type: "start-rename", sessionID: "session-a" })).toEqual({
      type: "rename",
      sessionID: "session-a",
    })
  })

  test("closing a menu only closes that session's menu", () => {
    const menu: SessionInteraction = { type: "menu", sessionID: "session-b" }

    expect(transitionSessionInteraction(menu, { type: "close-menu", sessionID: "session-a" })).toEqual(menu)
    expect(transitionSessionInteraction(menu, { type: "close-menu", sessionID: "session-b" })).toEqual(idle)
  })

  test("only the active session can finish renaming", () => {
    const renaming: SessionInteraction = { type: "rename", sessionID: "session-a" }

    expect(transitionSessionInteraction(renaming, { type: "finish-rename", sessionID: "session-b" })).toEqual(renaming)
    expect(transitionSessionInteraction(renaming, { type: "finish-rename", sessionID: "session-a" })).toEqual(idle)
  })
})

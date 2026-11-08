import { describe, expect, it } from "vitest"
import { render } from "@solidjs/testing-library"
import { TextInput } from "@/components/text-input"

const root = () => document.querySelector("[data-component='text-input']") as HTMLElement
const input = () => root().querySelector("input") as HTMLInputElement

describe("TextInput (DOM contract)", () => {
  it("renders the value into a labelled text input", () => {
    render(() => <TextInput value="192.168.1.1" aria-label="IP" />)
    expect(root().getAttribute("data-component")).toBe("text-input")
    expect(input().value).toBe("192.168.1.1")
    expect(input().getAttribute("aria-label")).toBe("IP")
  })

  it("invalid state reaches wrapper attribute and aria-invalid", () => {
    render(() => <TextInput invalid aria-label="campo" />)
    expect(root().hasAttribute("data-invalid")).toBe(true)
    expect(input().getAttribute("aria-invalid")).toBe("true")
  })

  it("disabled propagates to wrapper and input", () => {
    render(() => <TextInput disabled aria-label="campo" />)
    expect(root().hasAttribute("data-disabled")).toBe(true)
    expect(input().disabled).toBe(true)
  })

  it("optional copy action is labelled and clickable", async () => {
    let clicks = 0
    render(() => <TextInput showCopyButton copyLabel="Copiar IP" onCopyClick={() => clicks++} aria-label="ip" />)
    const copy = root().querySelector<HTMLButtonElement>("button[data-slot='text-input-icon-button']")
    copy?.click()
    expect(copy?.getAttribute("aria-label")).toBe("Copiar IP")
    expect(clicks).toBe(1)
  })
})

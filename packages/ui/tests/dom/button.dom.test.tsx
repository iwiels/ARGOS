import { describe, expect, it } from "vitest"
import { render, screen } from "@solidjs/testing-library"
import { Button } from "@/components/button"

describe("Button (DOM contract)", () => {
  it("renders a native button with component/variant/size data attributes", () => {
    render(() => <Button>Guardar</Button>)
    const el = screen.getByRole("button", { name: "Guardar" })
    expect(el.getAttribute("data-component")).toBe("button")
    expect(el.getAttribute("data-variant")).toBe("secondary")
    expect(el.getAttribute("data-size")).toBe("normal")
  })

  it("keeps primary as its own honest variant (same treatment as contrast)", () => {
    render(() => <Button variant="primary">a</Button>)
    expect(screen.getByRole("button").getAttribute("data-variant")).toBe("primary")
  })

  it("propagates disabled to the native control", () => {
    render(() => <Button disabled>x</Button>)
    expect((screen.getByRole("button") as HTMLButtonElement).disabled).toBe(true)
  })
})

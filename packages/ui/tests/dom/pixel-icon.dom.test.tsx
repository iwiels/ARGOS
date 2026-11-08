import { describe, expect, it } from "vitest"
import { render } from "@solidjs/testing-library"
import { PixelIcon } from "@/components/pixel-icon"
import { PIXEL_ICONS } from "@/components/pixel-icons.data"

describe("PixelIcon (DOM contract)", () => {
  it("exposes core tactical SecOps icon paths", () => {
    for (const name of ["alert-triangle", "shield-check", "terminal", "bug", "folder"]) {
      expect(PIXEL_ICONS[name], name).toBeDefined()
    }
  })

  it("renders an svg with data-icon marker", () => {
    const { container } = render(() => <PixelIcon name="shield-check" size={20} />)
    const svg = container.querySelector('svg[data-component="pixel-icon"]')
    expect(svg).not.toBeNull()
    expect(svg?.getAttribute("data-icon")).toBe("shield-check")
    expect(svg?.getAttribute("width")).toBe("20")
    expect(svg?.querySelector("path")?.getAttribute("d")?.length).toBeGreaterThan(0)
  })
})

import { describe, expect, it } from "vitest"
import { render, screen } from "@solidjs/testing-library"
import { DossierCard, DossierFolder, DossierFolderSheet, FolderTab } from "@/components/folder-tab"
import { PixelWindRose } from "@/components/pixel-compass"

describe("FolderTab (DOM contract)", () => {
  it("renders a static label without an interactive role", () => {
    const { container } = render(() => <FolderTab label="EXPEDIENTES" />)
    const el = container.querySelector('[data-component="folder-tab"]')!
    expect(el.textContent).toContain("EXPEDIENTES")
    expect(el.getAttribute("data-component")).toBe("folder-tab")
    expect(el.getAttribute("data-active")).toBe("false")
    expect(screen.queryByRole("button", { name: "EXPEDIENTES" })).toBeNull()
  })

  it("marks active tabs and renders badge", () => {
    render(() => <FolderTab label="HALLAZGOS" active badge={12} />)
    const el = screen.getByText("HALLAZGOS").closest('[data-component="folder-tab"]')!
    expect(el.getAttribute("data-active")).toBe("true")
    expect(el.textContent).toContain("12")
  })

  it("renders dossier folder anatomy markers", () => {
    const { container } = render(() => (
      <DossierFolder>
        <FolderTab label="A" />
        <DossierFolderSheet>
          <DossierCard title="T">x</DossierCard>
        </DossierFolderSheet>
      </DossierFolder>
    ))
    expect(container.querySelector('[data-component="dossier-folder"]')).not.toBeNull()
    expect(container.querySelector('[data-component="dossier-folder-sheet"]')).not.toBeNull()
    expect(container.querySelector('[data-component="dossier-card"]')).not.toBeNull()
  })
})

describe("PixelWindRose (DOM contract)", () => {
  it("renders a compass svg marker", () => {
    const { container } = render(() => <PixelWindRose size={20} />)
    const svg = container.querySelector('svg[data-component="pixel-wind-rose"]')
    expect(svg).not.toBeNull()
    expect(svg?.getAttribute("width")).toBe("20")
  })
})

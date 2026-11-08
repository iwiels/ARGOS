import { describe, expect, it } from "vitest"
import { render, screen } from "@solidjs/testing-library"
import { List } from "@/components/list"

describe("List accessibility", () => {
  it("renders an announced empty state without an empty listbox", async () => {
    render(() => (
      <List
        items={[]}
        key={(item) => item}
        search={{ placeholder: "Buscar carpetas" }}
        emptyMessage="No se encontraron carpetas"
      >
        {(item) => item}
      </List>
    ))

    expect(await screen.findByText("No se encontraron carpetas")).not.toBeNull()
    expect(screen.queryByRole("listbox")).toBeNull()
    expect(screen.getByRole("status").textContent).toBe("No se encontraron carpetas")
  })

  it("names the listbox from its search label when options are present", async () => {
    render(() => (
      <List
        items={["Proyecto"]}
        key={(item) => item}
        search={{ placeholder: "Buscar carpetas" }}
      >
        {(item) => item}
      </List>
    ))

    expect(await screen.findByRole("listbox", { name: "Buscar carpetas" })).not.toBeNull()
    expect(await screen.findByRole("option", { name: "Proyecto" })).not.toBeNull()
  })
})

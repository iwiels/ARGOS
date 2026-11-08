import { createSignal, Show } from "solid-js"
import { describe, expect, it, vi } from "vitest"
import { render, screen, waitFor } from "@solidjs/testing-library"
import { DialogProvider, useDialog } from "@/context/dialog"

function NestedDialog() {
  const [menuOpen, setMenuOpen] = createSignal(true)
  const menuId = "nested-menu"

  return (
    <div role="dialog" aria-label="Ajustes">
      <button
        aria-controls={menuId}
        aria-expanded={menuOpen()}
        onKeyDown={(event) => {
          if (event.key === "Escape") setMenuOpen(false)
        }}
      >
        Opciones
      </button>
      <Show when={menuOpen()}>
        <div role="menu" id={menuId}>
          <button role="menuitem">Editar</button>
        </div>
      </Show>
    </div>
  )
}

function DialogOpener() {
  const dialog = useDialog()
  return <button onClick={() => void dialog.show(() => <NestedDialog />)}>Abrir diálogo</button>
}

function NestedListboxDialog() {
  const [listboxOpen, setListboxOpen] = createSignal(true)
  const listboxId = "nested-listbox"

  return (
    <div role="dialog" aria-label="Ajustes con selector">
      <button
        aria-controls={listboxId}
        aria-expanded={listboxOpen()}
        onKeyDown={(event) => {
          if (event.key === "Escape") setListboxOpen(false)
        }}
      >
        Esquema de color
      </button>
      <Show when={listboxOpen()}>
        <div role="listbox" id={listboxId}>
          <div role="option">Oscuro</div>
        </div>
      </Show>
    </div>
  )
}

function ListboxDialogOpener() {
  const dialog = useDialog()
  return <button onClick={() => void dialog.show(() => <NestedListboxDialog />)}>Abrir ajustes</button>
}

function CallbackDialog(props: { onClosed: () => void }) {
  const dialog = useDialog()
  return (
    <div role="dialog" aria-label="Diálogo con callback">
      <button onClick={() => dialog.close(props.onClosed)}>Cerrar diálogo</button>
    </div>
  )
}

function CallbackDialogOpener(props: { onClosed: () => void }) {
  const dialog = useDialog()
  return (
    <button onClick={() => void dialog.show(() => <CallbackDialog onClosed={props.onClosed} />)}>
      Abrir diálogo con callback
    </button>
  )
}

describe("Dialog keyboard behavior", () => {
  it("lets an open nested menu consume Escape before closing its dialog", async () => {
    render(() => (
      <DialogProvider>
        <DialogOpener />
      </DialogProvider>
    ))

    screen.getByRole("button", { name: "Abrir diálogo" }).click()
    const trigger = await screen.findByRole("button", { name: "Opciones" })
    trigger.focus()
    trigger.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true }))
    await new Promise((resolve) => setTimeout(resolve, 150))

    expect(screen.queryByRole("menu")).toBeNull()
    expect(screen.queryByRole("dialog", { name: "Ajustes" })).not.toBeNull()
  })

  it("lets an open nested listbox consume Escape before closing its dialog", async () => {
    render(() => (
      <DialogProvider>
        <ListboxDialogOpener />
      </DialogProvider>
    ))

    screen.getByRole("button", { name: "Abrir ajustes" }).click()
    const trigger = await screen.findByRole("button", { name: "Esquema de color" })
    trigger.focus()
    trigger.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true }))
    await new Promise((resolve) => setTimeout(resolve, 150))

    expect(screen.queryByRole("listbox")).toBeNull()
    expect(screen.queryByRole("dialog", { name: "Ajustes con selector" })).not.toBeNull()
  })

  it("runs a close callback after the dialog is removed", async () => {
    const onClosed = vi.fn()
    render(() => (
      <DialogProvider>
        <CallbackDialogOpener onClosed={onClosed} />
      </DialogProvider>
    ))

    screen.getByRole("button", { name: "Abrir diálogo con callback" }).click()
    await screen.findByRole("dialog", { name: "Diálogo con callback" })
    screen.getByRole("button", { name: "Cerrar diálogo" }).click()

    await waitFor(() => expect(onClosed).toHaveBeenCalledOnce())
    expect(screen.queryByRole("dialog", { name: "Diálogo con callback" })).toBeNull()
  })
})

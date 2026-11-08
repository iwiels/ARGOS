import { useDialog } from "@argos/ui/context/dialog"
import { ServerConnection } from "@/context/server"
import { usePlatform } from "@/context/platform"
import { DialogSelectDirectory } from "./dialog-select-directory"
import { directoryPickerKind } from "./directory-picker-policy"

type DirectoryPickerInput = {
  server: ServerConnection.Any
  title?: string
  multiple?: boolean
  onSelect: (result: string | string[] | null) => void
}

export function useDirectoryPicker() {
  const platform = usePlatform()
  const dialog = useDialog()

  return (input: DirectoryPickerInput) => {
    if (directoryPickerKind(platform.platform, input.server) === "native" && platform.platform === "desktop") {
      void platform.openDirectoryPickerDialog({ title: input.title, multiple: input.multiple }).then(input.onSelect)
      return
    }

    const active = document.activeElement
    const menu = active instanceof HTMLElement ? active.closest<HTMLElement>('[role="menu"]') : null
    let focusTarget: HTMLElement | undefined
    if (menu?.id) {
      focusTarget = Array.from(document.querySelectorAll<HTMLElement>("[aria-controls]")).find(
        (element) => element.getAttribute("aria-controls") === menu.id,
      )
      focusTarget?.focus({ preventScroll: true })
    }

    void dialog.show(
      () => <DialogSelectDirectory {...input} />,
      () => input.onSelect(null),
      focusTarget,
    )
  }
}



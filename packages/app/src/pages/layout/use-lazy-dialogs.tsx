import { onCleanup } from "solid-js"
import { useDialog } from "@argos/ui/context/dialog"
import type { ServerConnection } from "@/context/server"
import type { LocalProject } from "@/context/layout"

/**
 * Lazy-loaded dialogs with a shared stale-run guard: if two dialogs are
 * requested while a chunk is still loading, only the newest request wins.
 */
export function useLazyDialogs() {
  const dialog = useDialog()

  let run = 0
  let dead = false

  onCleanup(() => {
    dead = true
    run += 1
  })

  function connectProvider() {
    const ticket = ++run
    void import("@/components/dialog-select-provider").then((x) => {
      if (dead || run !== ticket) return
      void dialog.show(() => <x.DialogSelectProvider />)
    })
  }

  function openServer() {
    const ticket = ++run
    void import("@/components/dialog-select-server").then((x) => {
      if (dead || run !== ticket) return
      void dialog.show(() => <x.DialogSelectServer />)
    })
  }

  function openSettings() {
    const ticket = ++run
    void import("@/components/settings").then((x) => {
      if (dead || run !== ticket) return
      void dialog.show(() => <x.DialogSettings />)
    })
  }

  function showEditProjectDialog(conn: ServerConnection.Any, project: LocalProject) {
    const ticket = ++run
    void import("@/components/dialog-edit-project").then((x) => {
      if (dead || run !== ticket) return
      void dialog.show(() => <x.DialogEditProject server={conn} project={project} />)
    })
  }

  return { connectProvider, openServer, openSettings, showEditProjectDialog }
}

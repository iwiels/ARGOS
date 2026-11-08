import { createEffect, createMemo, onCleanup, onMount } from "solid-js"
import type { SetStoreFunction, Store } from "solid-js/store"
import { makeEventListener } from "@solid-primitives/event-listener"
import { useLayout } from "@/context/layout"
import { useServerSync } from "@/context/server-sync"
import { createAim } from "@/utils/aim"

/** Ephemeral (non-persisted) UI state owned by the Layout page. */
export type LayoutEphemeralState = {
  autoselect: boolean
  busyWorkspaces: Record<string, boolean>
  hoverProject: string | undefined
  nav: HTMLElement | undefined
  sizing: boolean
  peek: string | undefined
  peeked: boolean
}

/**
 * Sidebar hover/AIM/peek interaction layer: rail aiming, hover-project
 * tracking, peek card timing and the window-level dismissal listeners.
 */
export function useSidebarHoverPeek(options: {
  layout: ReturnType<typeof useLayout>
  serverSync: ReturnType<typeof useServerSync>
  state: Store<LayoutEphemeralState>
  setState: SetStoreFunction<LayoutEphemeralState>
}) {
  const { layout, serverSync, state, setState } = options

  const navLeave = { current: undefined as number | undefined }

  const aim = createAim({
    enabled: () => !layout.sidebar.opened(),
    active: () => state.hoverProject,
    el: () => state.nav?.querySelector<HTMLElement>("[data-component='sidebar-rail']") ?? state.nav,
    onActivate: (directory) => {
      serverSync.child(directory)
      setState("hoverProject", directory)
    },
  })

  onCleanup(() => {
    if (navLeave.current !== undefined) clearTimeout(navLeave.current)
    if (peekt !== undefined) clearTimeout(peekt)
    aim.reset()
  })

  onMount(() => {
    const stop = () => setState("sizing", false)
    const blur = () => reset()
    const hide = () => {
      if (document.visibilityState !== "hidden") return
      reset()
    }
    makeEventListener(window, "pointerup", stop)
    makeEventListener(window, "pointercancel", stop)
    makeEventListener(window, "blur", stop)
    makeEventListener(window, "blur", blur)
    makeEventListener(document, "visibilitychange", hide)
  })

  const sidebarHovering = createMemo(() => !layout.sidebar.opened() && state.hoverProject !== undefined)
  const sidebarExpanded = createMemo(() => layout.sidebar.opened() || sidebarHovering())
  const setHoverProject = (value: string | undefined) => {
    setState("hoverProject", value)
    if (value !== undefined) return
    aim.reset()
  }
  const clearHoverProjectSoon = () => queueMicrotask(() => setHoverProject(undefined))

  const disarm = () => {
    if (navLeave.current === undefined) return
    clearTimeout(navLeave.current)
    navLeave.current = undefined
  }

  const reset = () => {
    disarm()
    setHoverProject(undefined)
  }

  let peekt: number | undefined

  const hoverProjectData = createMemo(() => {
    const id = state.hoverProject
    if (!id) return
    return layout.projects.list().find((project) => project.worktree === id)
  })

  createEffect(() => {
    const p = hoverProjectData()
    if (p) {
      if (peekt !== undefined) {
        clearTimeout(peekt)
        peekt = undefined
      }
      setState("peek", p.worktree)
      setState("peeked", true)
      return
    }

    setState("peeked", false)
    if (state.peek === undefined) return
    if (peekt !== undefined) clearTimeout(peekt)
    peekt = window.setTimeout(() => {
      peekt = undefined
      setState("peek", undefined)
    }, 180)
  })

  createEffect(() => {
    if (!layout.sidebar.opened()) return
    setHoverProject(undefined)
  })

  const clearSidebarHoverState = () => {
    if (layout.sidebar.opened()) return
    reset()
  }

  return {
    aim,
    sidebarHovering,
    sidebarExpanded,
    setHoverProject,
    clearHoverProjectSoon,
    hoverProjectData,
    clearSidebarHoverState,
    reset,
  }
}

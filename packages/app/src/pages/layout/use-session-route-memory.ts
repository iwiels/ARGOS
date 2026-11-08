import { createEffect, createSignal, on, untrack } from "solid-js"
import { useParams } from "@solidjs/router"
import { produce, type SetStoreFunction, type Store } from "solid-js/store"
import { useLayout } from "@/context/layout"
import { useServerSync } from "@/context/server-sync"
import { useServer } from "@/context/server"
import { useNotification } from "@/context/notification"
import { pathKey } from "@/utils/path-key"
import type { LayoutPageStore } from "./helpers"

type RouteInfo = { slug?: string; dir: string }
type ProjectRef = { worktree: string }

/**
 * Per-root last-session memory: directory→project-root resolution,
 * route-sync bookkeeping (markViewed / workspace expansion / recents) and
 * scroll-to-session plumbing.
 *
 * ⚠ Call order matters: this hook must run BEFORE `useWorkspaceActions`,
 * whose options consume `projectRoot`/`clearLastProjectSession` (previously
 * satisfied by hoisted function declarations).
 */
export function useSessionRouteMemory(options: {
  store: Store<LayoutPageStore>
  setStore: SetStoreFunction<LayoutPageStore>
  route: () => RouteInfo
  currentDir: () => string
  currentProject: () => ProjectRef | undefined
  pageReady: () => boolean
}) {
  const { store, setStore } = options
  const layout = useLayout()
  const serverSync = useServerSync()
  const server = useServer()
  const notification = useNotification()
  const params = useParams()

  let scrollContainerRef: HTMLDivElement | undefined
  const [scrollSessionKey, setScrollSessionKey] = createSignal<string | undefined>(undefined)

  const setScrollContainerRef = (el: HTMLDivElement | undefined) => {
    scrollContainerRef = el
  }

  function scrollToSession(sessionId: string, sessionKey: string) {
    if (!scrollContainerRef) return
    if (scrollSessionKey() === sessionKey) return
    const element = scrollContainerRef.querySelector(`[data-session-id="${sessionId}"]`)
    if (!element) return
    const containerRect = scrollContainerRef.getBoundingClientRect()
    const elementRect = element.getBoundingClientRect()
    if (elementRect.top >= containerRect.top && elementRect.bottom <= containerRect.bottom) {
      setScrollSessionKey(sessionKey)
      return
    }
    setScrollSessionKey(sessionKey)
    element.scrollIntoView({ block: "nearest", behavior: "smooth" })
  }

  function projectRoot(directory: string) {
    const key = pathKey(directory)
    const project = layout.projects
      .list()
      .find((item) => pathKey(item.worktree) === key || item.sandboxes?.some((sandbox) => pathKey(sandbox) === key))
    if (project) return project.worktree

    const known = Object.entries(store.workspaceOrder).find(
      ([root, dirs]) => pathKey(root) === key || dirs.some((item) => pathKey(item) === key),
    )
    if (known) return known[0]

    const [child] = serverSync.child(directory, { bootstrap: false })
    const id = child.project
    if (!id) return directory

    const meta = serverSync.data.project.find((item) => item.id === id)
    return meta?.worktree ?? directory
  }

  function activeProjectRoot(directory: string) {
    return options.currentProject()?.worktree ?? projectRoot(directory)
  }

  function rememberSessionRoute(directory: string, id: string, root = activeProjectRoot(directory)) {
    setStore("lastProjectSession", root, { directory, id, at: Date.now() })
    return root
  }

  function clearLastProjectSession(root: string) {
    if (!store.lastProjectSession[root]) return
    setStore(
      "lastProjectSession",
      produce((draft) => {
        delete draft[root]
      }),
    )
  }

  function syncSessionRoute(directory: string, id: string, root = activeProjectRoot(directory)) {
    rememberSessionRoute(directory, id, root)
    notification.session.markViewed(id)
    const expanded = untrack(() => store.workspaceExpanded[directory])
    if (!expanded) {
      setStore("workspaceExpanded", directory, true)
    }
    requestAnimationFrame(() => scrollToSession(id, `${directory}:${id}`))
    return root
  }

  const activeRoute = {
    session: "",
    sessionProject: "",
    directory: "",
  }

  createEffect(
    on(
      () => {
        return [
          options.pageReady(),
          options.route().slug,
          params.id,
          options.currentProject()?.worktree,
          options.currentDir(),
        ] as const
      },
      ([ready, slug, id, root, dir]) => {
        if (!ready || !slug || !dir) {
          activeRoute.session = ""
          activeRoute.sessionProject = ""
          activeRoute.directory = ""
          return
        }

        if (!id) {
          activeRoute.session = ""
          activeRoute.sessionProject = ""
          activeRoute.directory = ""
          return
        }

        const session = `${slug}/${id}`

        if (!root) {
          activeRoute.session = session
          activeRoute.directory = dir
          activeRoute.sessionProject = ""
          return
        }

        if (server.projects.last() !== root) server.projects.touch(root)

        const changed = session !== activeRoute.session || dir !== activeRoute.directory
        if (changed) {
          activeRoute.session = session
          activeRoute.directory = dir
          activeRoute.sessionProject = syncSessionRoute(dir, id, root)
          return
        }

        if (root === activeRoute.sessionProject) return
        activeRoute.directory = dir
        activeRoute.sessionProject = rememberSessionRoute(dir, id, root)
      },
    ),
  )

  return {
    projectRoot,
    activeProjectRoot,
    rememberSessionRoute,
    clearLastProjectSession,
    syncSessionRoute,
    setScrollContainerRef,
  }
}

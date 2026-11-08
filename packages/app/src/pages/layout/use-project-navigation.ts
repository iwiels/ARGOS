export type ProjectRef = { worktree: string }

import { base64Encode } from "@/core/encode"
import { getFilename } from "@/core/path"
import { setSessionHandoff } from "@/pages/session/handoff"
import { SessionRouteKey, SessionStateKey } from "@/utils/server-scope"
import { pathKey } from "@/utils/path-key"
import { useNavigate } from "@solidjs/router"
import type { Session } from "@argos/sdk/client"
import { useDirectoryPicker } from "@/components/directory-picker"
import { ServerConnection, useServer } from "@/context/server"
import { useServerSync } from "@/context/server-sync"
import { useServerSDK } from "@/context/server-sdk"
import { useLayout, type LocalProject } from "@/context/layout"
import { useNotification } from "@/context/notification"
import { useLanguage } from "@/context/language"
import { displayName, effectiveWorkspaceOrder, latestRootSession, type LayoutPageStore } from "./helpers"
import type { SetStoreFunction, Store } from "solid-js/store"

/**
 * Project open/navigate/close/rename flows, including the last-session
 * restore cascade inside navigateToProject. Offset navigators stay in
 * Layout (they depend on prefetch + unseen counts).
 */
export function useProjectNavigation(options: {
  store: Store<LayoutPageStore>
  setStore: SetStoreFunction<LayoutPageStore>
  currentDir: () => string
  currentProject: () => ProjectRef | undefined
  navigateWithSidebarReset: (href: string) => void
  projectRoot: (directory: string) => string
  clearLastProjectSession: (root: string) => void
}) {
  const { store, setStore } = options
  const layout = useLayout()
  const serverSync = useServerSync()
  const serverSDK = useServerSDK()
  const server = useServer()
  const language = useLanguage()
  const navigate = useNavigate()
  const pickDirectory = useDirectoryPicker()

  async function navigateToProject(directory: string | undefined) {
    if (!directory) return
    const root = options.projectRoot(directory)
    server.projects.touch(root)
    setStore("recentProjects", (prev) => {
      const next = [{ worktree: root, at: Date.now() }, ...(prev ?? []).filter((item) => item.worktree !== root)]
      return next.slice(0, 5)
    })
    const project = layout.projects.list().find((item) => item.worktree === root)
    let dirs = project
      ? effectiveWorkspaceOrder(root, [root, ...(project.sandboxes ?? [])], store.workspaceOrder[root])
      : [root]
    const canOpen = (value: string | undefined) => {
      if (!value) return false
      return dirs.some((item) => pathKey(item) === pathKey(value))
    }
    const refreshDirs = async (target?: string) => {
      if (!target || target === root || canOpen(target)) return canOpen(target)
      const listed = await serverSDK.client.worktree
        .list({ directory: root })
        .then((x) => x.data ?? [])
        .catch(() => [] as string[])
      dirs = effectiveWorkspaceOrder(root, [root, ...listed], store.workspaceOrder[root])
      return canOpen(target)
    }
    const openSession = async (target: { directory: string; id: string }) => {
      if (!canOpen(target.directory)) return false
      const [data] = serverSync.child(target.directory, { bootstrap: false })
      if (data.session.some((item) => item.id === target.id)) {
        setStore("lastProjectSession", root, { directory: target.directory, id: target.id, at: Date.now() })
        options.navigateWithSidebarReset(`/${base64Encode(target.directory)}/session/${target.id}`)
        return true
      }
      const resolved = await serverSDK.client.session
        .get({ sessionID: target.id })
        .then((x) => x.data)
        .catch(() => undefined)
      if (!resolved?.directory) return false
      if (!canOpen(resolved.directory)) return false
      setStore("lastProjectSession", root, { directory: resolved.directory, id: resolved.id, at: Date.now() })
      options.navigateWithSidebarReset(`/${base64Encode(resolved.directory)}/session/${resolved.id}`)
      return true
    }

    const projectSession = store.lastProjectSession[root]
    if (projectSession?.id) {
      await refreshDirs(projectSession.directory)
      const opened = await openSession(projectSession)
      if (opened) return
      options.clearLastProjectSession(root)
    }

    const latest = latestRootSession(
      dirs.map((item) => serverSync.child(item, { bootstrap: false })[0]),
      Date.now(),
    )
    if (latest && (await openSession(latest))) {
      return
    }

    const fetched = latestRootSession(
      await Promise.all(
        dirs.map(async (item) => ({
          path: { directory: item },
          session: await serverSDK.client.session
            .list({ directory: item })
            .then((x) => x.data ?? [])
            .catch(() => []),
        })),
      ),
      Date.now(),
    )
    if (fetched && (await openSession(fetched))) {
      return
    }

    options.navigateWithSidebarReset(`/${base64Encode(root)}/session`)
  }

  function navigateToSession(session: Session | undefined) {
    if (!session) return
    options.navigateWithSidebarReset(`/${base64Encode(session.directory)}/session/${session.id}`)
  }

  function openProject(directory: string, navigate = true) {
    layout.projects.open(directory)
    if (navigate) return navigateToProject(directory)
  }

  const openNewSessionLink = (link: { directory: string; prompt?: string }) => {
    void openProject(link.directory, false)
    const slug = base64Encode(link.directory)
    if (link.prompt) {
      setSessionHandoff(SessionStateKey.from(server.scope(), SessionRouteKey.fromLegacy(slug)), {
        prompt: link.prompt,
      })
    }
    const href = link.prompt ? `/${slug}/session?prompt=${encodeURIComponent(link.prompt)}` : `/${slug}/session`
    options.navigateWithSidebarReset(href)
  }

  async function renameProject(project: LocalProject, next: string) {
    const current = displayName(project)
    if (next === current) return
    const name = next === getFilename(project.worktree) ? "" : next

    if (project.id && project.id !== "global") {
      await serverSDK.client.project.update({ projectID: project.id, directory: project.worktree, name })
      return
    }

    serverSync.project.meta(project.worktree, { name })
  }

  function closeProject(directory: string) {
    const list = layout.projects.list()
    const key = pathKey(directory)
    const index = list.findIndex((x) => pathKey(x.worktree) === key)
    const active = pathKey(options.currentProject()?.worktree ?? "") === key
    if (index === -1) return

    if (!active) {
      layout.projects.close(directory)
      return
    }

    if (list.length === 1) {
      layout.projects.close(directory)
      navigate("/")
      return
    }

    const next = list[index + 1] ?? list[index - 1]

    options.navigateWithSidebarReset(`/${base64Encode(next.worktree)}/session`)
    layout.projects.close(directory)
    queueMicrotask(() => {
      void navigateToProject(next.worktree)
    })
  }

  function chooseProject() {
    const conn = server.current
    if (!conn) return
    function resolve(result: string | string[] | null) {
      if (Array.isArray(result)) {
        for (const directory of result) {
          void openProject(directory, false)
        }
        void navigateToProject(result[0])
      } else if (result) {
        void openProject(result)
      }
    }

    pickDirectory({
      server: conn,
      title: language.t("command.project.open"),
      multiple: true,
      onSelect: resolve,
    })
  }

  return {
    openNewSessionLink,
    navigateToProject,
    navigateToSession,
    openProject,
    renameProject,
    closeProject,
    chooseProject,
  }
}

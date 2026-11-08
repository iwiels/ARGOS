import {
  createEffect,
  createMemo,
  createResource,
  on,
  onCleanup,
  onMount,
  ParentProps,
  Show,
  untrack,
} from "solid-js"
import { useNavigate, useParams } from "@solidjs/router"
import { useLayout } from "@/context/layout"
import { useServerSync } from "@/context/server-sync"
import { makeEventListener } from "@solid-primitives/event-listener"
import { Persist, persisted } from "@/utils/persist"
import { base64Encode } from "@/core/encode"
import { decode64 } from "@/utils/base64"
import { getFilename } from "@/core/path"
import { Session } from "@argos/sdk/client"
import { usePlatform } from "@/context/platform"
import { useSettings } from "@/context/settings"
import { createStore, produce } from "solid-js/store"
import { showToast, ToastRegion } from "@/utils/toast"
import { useServerSDK } from "@/context/server-sdk"
import { useNotification } from "@/context/notification"
import { usePermission } from "@/context/permission"
import { Binary } from "@/core/binary"
import { setNavigate } from "@/utils/notification-click"
import { setSessionHandoff } from "@/pages/session/handoff"
import { SessionRouteKey, SessionStateKey } from "@/utils/server-scope"

import { useDialog } from "@argos/ui/context/dialog"
import { useTheme, type ColorScheme } from "@argos/ui/theme/context"
import { useCommand } from "@/context/command"
import { DebugBar } from "@/components/debug-bar"
import { Titlebar, type TitlebarUpdate } from "@/components/titlebar"
import { useDirectoryPicker } from "@/components/directory-picker"
import { ServerConnection, useServer } from "@/context/server"
import { useLanguage, type Locale } from "@/context/language"
import { pathKey } from "@/utils/path-key"
import {
  displayName,
  effectiveWorkspaceOrder,
  latestRootSession,
  sortedRootSessions,
  type LayoutPageStore,
} from "./layout/helpers"
import {
  collectNewSessionDeepLinks,
  collectOpenProjectDeepLinks,
  deepLinkEvent,
  drainPendingDeepLinks,
} from "./layout/deep-links"
import { DialogDeepLinkConfirm } from "./layout/dialog-deeplink-confirm"
import { SidebarContent } from "./layout/sidebar-shell"
import { useSessionPrefetch } from "./layout/use-session-prefetch"
import { useSdkNotificationToasts } from "./layout/use-sdk-notification-toasts"
import { useWorkspaceActions } from "./layout/use-workspace-actions"
import { useAppearanceCycle } from "./layout/use-appearance-cycle"
import { useLazyDialogs } from "./layout/use-lazy-dialogs"
import { useSortTicker } from "./layout/use-sort-ticker"
import { useSidebarHoverPeek, type LayoutEphemeralState } from "./layout/use-sidebar-hover-peek"
import { useSessionRouteMemory } from "./layout/use-session-route-memory"
import { useProjectNavigation } from "./layout/use-project-navigation"
import { registerLayoutCommands } from "./layout/register-layout-commands"

export default function Layout(props: ParentProps) {
  const serverSDK = useServerSDK()
  const [store, setStore, , ready] = persisted(
    Persist.serverGlobal(serverSDK.scope, "layout.page", ["layout.page.v1"]),
    createStore<LayoutPageStore>({
      lastProjectSession: {},
      activeProject: undefined,
      activeWorkspace: undefined,
      workspaceOrder: {},
      workspaceName: {},
      workspaceBranchName: {},
      workspaceExpanded: {},
      gettingStartedDismissed: false,
      recentProjects: [],
      sectionsCollapsed: {},
    }),
  )

  const pageReady = createMemo(() => ready())


  const params = useParams()
  const serverSync = useServerSync()
  const layout = useLayout()
  const layoutReady = createMemo(() => layout.ready())
  const platform = usePlatform()
  const pickDirectory = useDirectoryPicker()
  const settings = useSettings()
  const server = useServer()
  const notification = useNotification()
  const permission = usePermission()
  const navigate = useNavigate()
  setNavigate(navigate)
  const dialog = useDialog()
  const command = useCommand()
  const theme = useTheme()
  const language = useLanguage()
  const { colorSchemeOrder, colorSchemeLabel, cycleColorScheme, setLocale, cycleLanguage } = useAppearanceCycle()
  const { connectProvider, openServer, openSettings, showEditProjectDialog } = useLazyDialogs()
  const sortNow = useSortTicker()
  const route = createMemo(() => {
    const slug = params.dir
    if (!slug) return { slug, dir: "" }
    const dir = decode64(slug)
    if (!dir) return { slug, dir: "" }
    const store = serverSync.peek(dir, { bootstrap: false })
    return {
      slug,
      store,
      dir: store[0].path.directory || dir,
    }
  })
  const currentDir = createMemo(() => route().dir)

  const [state, setState] = createStore<LayoutEphemeralState>({
    autoselect: false,
    busyWorkspaces: {} as Record<string, boolean>,
    hoverProject: undefined as string | undefined,
    nav: undefined as HTMLElement | undefined,
    sizing: false,
    peek: undefined as string | undefined,
    peeked: false,
  })

  const updateVersion = () => {
    const state = platform.updater?.state()
    if (state?.status !== "ready") return
    return state.version
  }
  const installUpdate = () => void platform.updater?.install()
  const titlebarUpdate: TitlebarUpdate = {
    version: updateVersion,
    installing: () => platform.updater?.state().status === "installing",
    install: installUpdate,
  }

  const setBusy = (directory: string, value: boolean) => {
    const key = pathKey(directory)
    if (value) {
      setState("busyWorkspaces", key, true)
      return
    }
    setState(
      "busyWorkspaces",
      produce((draft) => {
        delete draft[key]
      }),
    )
  }
  const { clearSidebarHoverState } = useSidebarHoverPeek({ layout, serverSync, state, setState })

  createEffect(() => {
    if (!state.autoselect) return
    const dir = params.dir
    if (!dir) return
    const directory = decode64(dir)
    if (!directory) return
    setState("autoselect", false)
  })

  useSdkNotificationToasts({
    serverSDK,
    serverSync,
    settings,
    platform,
    permission,
    language,
    navigate,
    params,
    currentDir,
    setBusy,
  })

  const currentProject = createMemo(() => {
    const directory = currentDir()
    if (!directory) return
    const key = pathKey(directory)

    const projects = layout.projects.list()

    const sandbox = projects.find((p) => p.sandboxes?.some((item) => pathKey(item) === key))
    if (sandbox) return sandbox

    const direct = projects.find((p) => pathKey(p.worktree) === key)
    if (direct) return direct

    const [child] = serverSync.child(directory, { bootstrap: false })
    const id = child.project
    if (!id) return

    const meta = serverSync.data.project.find((p) => p.id === id)
    const root = meta?.worktree
    if (!root) return

    return projects.find((p) => p.worktree === root)
  })

  const navigateWithSidebarReset = (href: string) => {
    clearSidebarHoverState()
    navigate(href)
    layout.mobileSidebar.hide()
  }

  const {
    projectRoot,
    clearLastProjectSession,
    syncSessionRoute,
  } = useSessionRouteMemory({
    store,
    setStore,
    route,
    currentDir,
    currentProject,
    pageReady,
  })

  const { openProject, openNewSessionLink, navigateToProject, navigateToSession, chooseProject } =
    useProjectNavigation({
      store,
      setStore,
      currentDir,
      currentProject,
      navigateWithSidebarReset,
      projectRoot,
      clearLastProjectSession,
    })

  const [autoselecting] = createResource(async () => {
    await ready.promise
    await layout.ready.promise
    if (!untrack(() => state.autoselect)) return

    const list = layout.projects.list()
    const last = server.projects.last()

    if (list.length === 0) {
      if (!last) return
      await openProject(last, true)
    } else {
      const next = list.find((project) => project.worktree === last) ?? list[0]
      if (!next) return
      await openProject(next.worktree, true)
    }
  })

  const { createWorkspace, workspaceIds } = useWorkspaceActions({
    store,
    setStore,
    serverSDK,
    serverSync,
    layout,
    language,
    platform,
    params,
    navigate,
    currentDir,
    currentProject,
    projectRoot,
    setBusy,
    clearLastProjectSession,
    clearSidebarHoverState,
    navigateWithSidebarReset,
  })

  const workspaceSetting = createMemo(() => {
    const project = currentProject()
    if (!project) return false
    if (project.vcs !== "git") return false
    return layout.sidebar.workspaces(project.worktree)()
  })

  const visibleSessionDirs = createMemo(() => {
    const project = currentProject()
    if (!project) return [] as string[]
    if (!workspaceSetting()) return [project.worktree]

    const activeDir = currentDir()
    return workspaceIds(project).filter((directory) => {
      const expanded = store.workspaceExpanded[directory] ?? directory === project.worktree
      const active = pathKey(directory) === pathKey(activeDir)
      return expanded || active
    })
  })

  createEffect(() => {
    if (!pageReady()) return
    if (!layoutReady()) return
    const projects = layout.projects.list()
    for (const [directory, expanded] of Object.entries(store.workspaceExpanded)) {
      if (!expanded) continue
      const key = pathKey(directory)
      const project = projects.find(
        (item) => pathKey(item.worktree) === key || item.sandboxes?.some((sandbox) => pathKey(sandbox) === key),
      )
      if (!project) continue
      if (project.vcs === "git" && layout.sidebar.workspaces(project.worktree)()) continue
      setStore("workspaceExpanded", directory, false)
    }
  })

  const currentSessions = createMemo(() => {
    const now = sortNow() || Date.now()
    const dirs = visibleSessionDirs()
    if (dirs.length === 0) return [] as Session[]

    const result: Session[] = []
    for (const dir of dirs) {
      const [dirStore] = serverSync.child(dir, { bootstrap: true })
      const dirSessions = sortedRootSessions(dirStore, now)
      result.push(...dirSessions)
    }
    return result
  })


  const { prefetchSession, warm } = useSessionPrefetch({
    serverSync,
    serverSDK,
    route,
    currentDir,
    visibleSessionDirs,
    currentSessions,
    sessionID: () => params.id,
  })

  function navigateSessionByOffset(offset: number) {
    const sessions = currentSessions()
    if (sessions.length === 0) return

    const sessionIndex = params.id ? sessions.findIndex((s) => s.id === params.id) : -1

    let targetIndex: number
    if (sessionIndex === -1) {
      targetIndex = offset > 0 ? 0 : sessions.length - 1
    } else {
      targetIndex = (sessionIndex + offset + sessions.length) % sessions.length
    }

    const session = sessions[targetIndex]
    if (!session) return

    prefetchSession(session, "high")
    warm(sessions, targetIndex)

    navigateToSession(session)
  }

  function navigateProjectByOffset(offset: number) {
    const projects = layout.projects.list()
    if (projects.length === 0) return

    const current = currentProject()?.worktree
    const fallback = currentDir() ? projectRoot(currentDir()) : undefined
    const active = current ?? fallback
    const index = active ? projects.findIndex((project) => project.worktree === active) : -1

    const target =
      index === -1
        ? offset > 0
          ? projects[0]
          : projects[projects.length - 1]
        : projects[(index + offset + projects.length) % projects.length]
    if (!target) return

    // warm up child store to prevent flicker
    serverSync.child(target.worktree)
    void openProject(target.worktree)
  }


  function navigateSessionByUnseen(offset: number) {
    const sessions = currentSessions()
    if (sessions.length === 0) return

    const hasUnseen = sessions.some((session) => notification.session.unseenCount(session.id) > 0)
    if (!hasUnseen) return

    const activeIndex = params.id ? sessions.findIndex((s) => s.id === params.id) : -1
    const start = activeIndex === -1 ? (offset > 0 ? -1 : 0) : activeIndex

    for (let i = 1; i <= sessions.length; i++) {
      const index = offset > 0 ? (start + i) % sessions.length : (start - i + sessions.length) % sessions.length
      const session = sessions[index]
      if (!session) continue
      if (notification.session.unseenCount(session.id) === 0) continue

      prefetchSession(session, "high")
      warm(sessions, index)

      navigateToSession(session)
      return
    }
  }

  async function archiveSession(session: Session) {
    const [store, setStore] = serverSync.child(session.directory)
    const sessions = store.session ?? []
    const index = sessions.findIndex((s) => s.id === session.id)
    const nextSession = sessions[index + 1] ?? sessions[index - 1]

    await serverSDK.client.session.update({
      directory: session.directory,
      sessionID: session.id,
      time: { archived: Date.now() },
    })
    setStore(
      produce((draft) => {
        const match = Binary.search(draft.session, session.id, (s) => s.id)
        if (match.found) draft.session.splice(match.index, 1)
      }),
    )
    if (session.id === params.id) {
      if (nextSession) {
        navigate(`/${params.dir}/session/${nextSession.id}`)
      } else {
        navigate(`/${params.dir}/session`)
      }
    }
  }

  async function renameSession(session: Session, title: string) {
    const trimmed = title.trim()
    if (!trimmed) return
    const [store, setStore] = serverSync.child(session.directory)
    await serverSDK.client.session.update({
      directory: session.directory,
      sessionID: session.id,
      title: trimmed,
    })
    setStore(
      produce((draft) => {
        const match = Binary.search(draft.session, session.id, (s) => s.id)
        if (match.found) draft.session[match.index].title = trimmed
      }),
    )
    await serverSync.child(session.directory)
    void store
  }

  async function setSessionPinned(session: Session, pinned: boolean) {
    const [, setStore] = serverSync.child(session.directory)
    const metadata = { ...(session.metadata ?? {}), pinned: pinned || undefined }
    await serverSDK.client.session.update({
      directory: session.directory,
      sessionID: session.id,
      metadata,
    })
    setStore(
      produce((draft) => {
        const match = Binary.search(draft.session, session.id, (s) => s.id)
        if (match.found) draft.session[match.index].metadata = metadata
      }),
    )
  }

  async function deleteSession(session: Session) {
    const [store, setStore] = serverSync.child(session.directory)
    const sessions = store.session ?? []
    const index = sessions.findIndex((s) => s.id === session.id)
    const nextSession = sessions[index + 1] ?? sessions[index - 1]

    await serverSDK.client.session.delete({
      directory: session.directory,
      sessionID: session.id,
    })
    setStore(
      produce((draft) => {
        const match = Binary.search(draft.session, session.id, (s) => s.id)
        if (match.found) draft.session.splice(match.index, 1)
      }),
    )
    if (session.id === params.id) {
      if (nextSession) {
        navigate(`/${params.dir}/session/${nextSession.id}`)
      } else {
        navigate(`/${params.dir}/session`)
      }
    }
  }

  registerLayoutCommands(command, {
    language,
    platform,
    layout,
    theme,
    params,
    currentSessions,
    currentProject,
    workspaceSetting,
    colorSchemeOrder,
    colorSchemeLabel,
    chooseProject,
    editProject: (proj) => {
      const conn = server.current
      if (conn) showEditProjectDialog(conn, proj)
    },
    connectProvider,
    openServer,
    openSettings,
    archiveSession,
    createWorkspace,
    cycleColorScheme,
    cycleLanguage,
    setLocale,
    navigateProjectByOffset,
    navigateSessionByOffset,
    navigateSessionByUnseen,
  })

  const handleDeepLinks = (urls: string[]) => {
    if (!server.isLocal()) return

    for (const directory of collectOpenProjectDeepLinks(urls)) {
      void openProject(directory)
    }

    for (const link of collectNewSessionDeepLinks(urls)) {
      // Prompt-carrying links get an in-app confirmation: the OS gate only
      // covers "open this app?", not silently seeding an AI prompt into an
      // arbitrary directory.
      if (link.prompt) {
        void dialog.show(() => (
          <DialogDeepLinkConfirm
            directory={link.directory}
            prompt={link.prompt}
            onConfirm={() => openNewSessionLink(link)}
          />
        ))
        continue
      }
      openNewSessionLink(link)
    }
  }

  const closeSidebar = () => {
    document.querySelector<HTMLElement>("[data-sidebar-toggle]")?.focus()
    layout.sidebar.close()
  }

  onMount(() => {
    makeEventListener(window, "keydown", (event) => {
      if (event.key !== "Escape" || !window.matchMedia("(max-width: 640px)").matches) return
      if (layout.sidebar.opened()) closeSidebar()
    })

    const handler = (event: Event) => {
      const detail = (event as CustomEvent<{ urls: string[] }>).detail
      const urls = detail?.urls ?? []
      if (urls.length === 0) return
      handleDeepLinks(urls)
    }

    handleDeepLinks(drainPendingDeepLinks(window))
    makeEventListener(window, deepLinkEvent, handler as EventListener)
  })

  createEffect(() => {
    document.documentElement.style.setProperty("--dialog-left-margin", "0px")
  })

  const loadedSessionDirs = new Set<string>()

  createEffect(
    on(
      visibleSessionDirs,
      (dirs) => {
        if (dirs.length === 0) {
          loadedSessionDirs.clear()
          return
        }

        const next = new Set(dirs)
        for (const directory of next) {
          if (loadedSessionDirs.has(directory)) continue
          void serverSync.project.loadSessions(directory)
        }

        loadedSessionDirs.clear()
        for (const directory of next) {
          loadedSessionDirs.add(directory)
        }
      },
      { defer: true },
    ),
  )

  const projects = () => layout.projects.list()
  const sidebarContent = (mobile?: boolean) => (
    <SidebarContent
      mobile={mobile}
      opened={() => layout.sidebar.opened()}
      projects={projects}
      openProjectLabel={language.t("command.project.open")}
      onOpenProject={chooseProject}
      onNewSession={(directory) => openNewSessionLink({ directory })}
      navigateToProject={navigateToProject}
      onEditProject={(proj) => showEditProjectDialog(server.current!, proj)}
      sectionsCollapsed={() => store.sectionsCollapsed}
      onToggleSection={(key) => setStore("sectionsCollapsed", key, (value) => !value)}
      onNavigateToSession={(directory, id) =>
        navigateWithSidebarReset(`/${base64Encode(directory)}/session/${id}`)
      }
      onArchiveSession={(session) => void archiveSession(session)}
      onRenameSession={(session, title) => void renameSession(session, title)}
      onPinSession={(session, pinned) => void setSessionPinned(session, pinned)}
      onDeleteSession={(session) => void deleteSession(session)}
      settingsLabel={() => language.t("sidebar.settings")}
      onOpenSettings={openSettings}
      helpLabel={() => language.t("sidebar.help")}
      onOpenHelp={() => platform.openLink("https://github.com/iwiels/ARGOS")}
    />
  )

  return (
    <div class="relative bg-bg-base flex-1 min-h-0 min-w-0 flex flex-col select-none [&_input]:select-text [&_textarea]:select-text [&_[contenteditable]]:select-text">
      {autoselecting() ?? ""}
      <Titlebar update={titlebarUpdate} />
      <div class="relative flex-1 min-h-0 min-w-0 flex" data-component="layout-columns">
        {sidebarContent()}
        <Show when={layout.sidebar.opened()}>
          <div
            aria-hidden="true"
            class="layout-sidebar-backdrop"
            onClick={closeSidebar}
          />
        </Show>
        <main class="relative z-10 flex h-full min-h-0 min-w-0 w-full flex-1 flex-col overflow-x-hidden bg-bg-base contain-strict">
          <Show when={!autoselecting.loading} fallback={<div class="size-full" />}>
            {props.children}
          </Show>
        </main>
      </div>
      {import.meta.env.DEV && <DebugBar />}
      <ToastRegion />
    </div>
  )
}



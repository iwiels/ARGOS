import type { Session } from "@argos/sdk/v2"
import { batch, createEffect, createMemo } from "solid-js"
import { createStore } from "solid-js/store"
import { useQuery } from "@tanstack/solid-query"
import { useLocation, useNavigate } from "@solidjs/router"
import { useLayout, type LocalProject } from "@/context/layout"
import { ServerConnection, useServer } from "@/context/server"
import { useServerSync } from "@/context/server-sync"
import { useGlobal } from "@/context/global"
import { base64Encode } from "@/core/encode"
import {
  displayName,
  homeProjectNavigation,
  type HomeProjectSelection,
  projectForSession,
  sortedRootSessions,
} from "@/pages/layout/helpers"
import { pathKey } from "@/utils/path-key"
import { useDirectoryPicker } from "@/components/directory-picker"
import { setSessionHandoff } from "@/pages/session/handoff"
import { useLanguage } from "@/context/language"
import { SessionRouteKey, SessionStateKey } from "@/utils/server-scope"
import type { AuditSession } from "@/components/home"

export const HOME_SESSION_LIMIT = 64

const PRESET_TO_COMMAND: Record<string, string> = {
  recon: "/auditoria-recon",
  web: "/auditoria-web",
  red: "/auditoria-red",
  full: "/auditoria-completa",
}

let pendingHomeNavigation: { server: ServerConnection.Key; href: string } | undefined

function buildHomeSessionRecords(input: {
  sync: Pick<ReturnType<typeof useServerSync>, "child">
  projectDirectories: () => string[]
  projects: () => LocalProject[]
  projectByID: () => Map<string, LocalProject>
}) {
  return [
    ...new Map(
      input
        .projectDirectories()
        .flatMap((directory) => sortedRootSessions(input.sync.child(directory, { bootstrap: false })[0], Date.now()))
        .map((session) => [`${pathKey(session.directory)}:${session.id}`, session] as const),
    ).values(),
  ]
    .sort((a, b) => (b.time.updated ?? b.time.created) - (a.time.updated ?? a.time.created))
    .flatMap((session) => {
      const project = projectForSession(session, input.projects(), input.projectByID())
      if (!project) return []
      return {
        session: session as AuditSession,
        project,
        projectName: displayName(project),
      }
    })
}

export function useHomeData() {
  const location = useLocation()
  const isHome = () => location.pathname === "/"
  const isAuditList = () => location.pathname === "/auditorias"
  const sync = useServerSync()
  const layout = useLayout()
  const navigate = useNavigate()
  const server = useServer()
  const global = useGlobal()
  const [state, setState] = createStore({
    search: "",
    selection: { server: server.key } as HomeProjectSelection,
  })
  const pickDirectory = useDirectoryPicker()
  const language = useLanguage()

  const focusedServer = createMemo(
    () => global.servers.list().find((conn) => ServerConnection.key(conn) === state.selection.server) ?? server.current,
  )
  const focusedServerCtx = createMemo(() => {
    const conn = focusedServer()
    if (!conn) return
    return global.createServerCtx(conn)
  })
  const focusedSync = () => focusedServerCtx()?.sync ?? sync
  const projects = createMemo(() => focusedServerCtx()?.projects.list() ?? layout.projects.list())
  const selectedProject = createMemo(() => projects().find((project) => project.worktree === state.selection.directory))
  const newSessionProject = createMemo(
    () =>
      selectedProject() ??
      projects().find((project) => project.worktree === focusedServerCtx()?.projects.last()) ??
      projects()[0],
  )
  const directories = (project: LocalProject) => [project.worktree, ...(project.sandboxes ?? [])]
  const projectDirectories = createMemo(() => {
    const project = selectedProject()
    if (!project) return projects().flatMap(directories)
    return directories(project)
  })
  const sessionLoad = useQuery(() => ({
    queryKey: ["home", "sessions", state.selection.server, ...projectDirectories()] as const,
    queryFn: async () => {
      await Promise.all(
        projectDirectories().map((directory) =>
          focusedSync().project.loadSessions(directory, { limit: HOME_SESSION_LIMIT }),
        ),
      )
      return null
    },
  }))

  const projectByID = createMemo(
    () => new Map(projects().flatMap((project) => (project.id ? [[project.id, project] as const] : []))),
  )
  const allRecords = createMemo(() =>
    buildHomeSessionRecords({
      sync: focusedSync(),
      projectDirectories,
      projects,
      projectByID,
    }),
  )
  const records = createMemo(() => allRecords().slice(0, HOME_SESSION_LIMIT))

  function setSelection(next: HomeProjectSelection) {
    batch(() => {
      if (state.selection.server !== next.server) setState("selection", "server", next.server)
      if (state.selection.directory !== next.directory) setState("selection", "directory", next.directory)
    })
  }

  createEffect(() => {
    const list = global.servers.list()
    if (list.some((conn) => ServerConnection.key(conn) === state.selection.server)) return
    const conn = list.find((conn) => ServerConnection.key(conn) === server.key) ?? list[0]
    if (conn) setSelection({ server: ServerConnection.key(conn) })
  })

  createEffect(() => {
    const pending = pendingHomeNavigation
    if (!pending || pending.server !== server.key) return
    pendingHomeNavigation = undefined
    navigate(pending.href)
  })

  function navigateOnServer(conn: ServerConnection.Any, href: string) {
    const next = homeProjectNavigation(server.key, ServerConnection.key(conn), href)
    if (!next.server) {
      navigate(next.href)
      return
    }
    pendingHomeNavigation = next
    server.setActive(next.server)
  }

  function openSession(session: Session) {
    const project = projectForSession(session, projects(), projectByID())
    const conn = focusedServer()
    if (!conn) return
    const directory = project?.worktree ?? session.directory
    const ctx = global.createServerCtx(conn)
    ctx.projects.open(directory)
    ctx.projects.touch(directory)
    navigateOnServer(conn, `/${base64Encode(session.directory)}/session/${session.id}`)
  }

  /**
   * Lanza un preset de auditoría: abre una sesión nueva en el alcance activo
   * con el comando correspondiente como handoff (sin saturar el input del
   * usuario). Si aún no hay alcance, primero pide elegir la carpeta.
   */
  function launchPreset(type: string) {
    const command = PRESET_TO_COMMAND[type]
    if (!command) return
    const conn = focusedServer()
    if (!conn) return

    const go = (directory: string) => {
      const ctx = global.createServerCtx(conn)
      ctx.projects.open(directory)
      ctx.projects.touch(directory)
      const slug = base64Encode(directory)
      setSessionHandoff(SessionStateKey.from(server.scope(), SessionRouteKey.fromLegacy(slug)), {
        prompt: command,
      })
      navigateOnServer(conn, `/${slug}/session`)
    }

    const directory = newSessionProject()?.worktree
    if (directory) {
      go(directory)
      return
    }
    pickDirectory({
      server: conn,
      title: language.t("command.project.open"),
      multiple: false,
      onSelect: (result) => {
        const dir = typeof result === "string" ? result : Array.isArray(result) ? result[0] : undefined
        if (dir) go(dir)
      },
    })
  }

  /** Abre la carpeta de un alcance existente en su composer de sesión nueva (sin preset ni sesión previa que continuar). */
  function openProjectComposer(directory: string) {
    const conn = focusedServer()
    if (!conn) return
    const ctx = global.createServerCtx(conn)
    ctx.projects.open(directory)
    ctx.projects.touch(directory)
    navigateOnServer(conn, `/${base64Encode(directory)}/session`)
  }

  /** Abre el selector de carpeta para agregar un alcance nuevo al panel. */
  function addProject() {
    const conn = focusedServer()
    if (!conn) return
    pickDirectory({
      server: conn,
      title: language.t("command.project.open"),
      multiple: false,
      onSelect: (result) => {
        const dir = typeof result === "string" ? result : Array.isArray(result) ? result[0] : undefined
        if (dir) openProjectComposer(dir)
      },
    })
  }

  return {
    isHome,
    isAuditList,
    search: () => state.search,
    onSearch: (value: string) => setState("search", value),
    records,
    isLoading: () => sessionLoad.isLoading,
    openSession,
    launchPreset,
    newSessionProject,
    projects,
    openProjectComposer,
    addProject,
  }
}

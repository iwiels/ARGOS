import { getFilename } from "@/core/path"
import { type Session } from "@argos/sdk/client"
import { pathKey } from "@/utils/path-key"
import type { ServerConnection } from "@/context/server"

export type LayoutPageStore = {
  lastProjectSession: { [directory: string]: { directory: string; id: string; at: number } }
  activeProject: string | undefined
  activeWorkspace: string | undefined
  workspaceOrder: Record<string, string[]>
  workspaceName: Record<string, string>
  workspaceBranchName: Record<string, Record<string, string>>
  workspaceExpanded: Record<string, boolean>
  gettingStartedDismissed: boolean
  recentProjects: { worktree: string; at: number }[]
  sectionsCollapsed: Record<string, boolean>
}

type SessionStore = {
  session?: Session[]
  path: { directory: string }
}

function sortSessions(now: number) {
  const oneMinuteAgo = now - 60 * 1000
  return (a: Session, b: Session) => {
    const aPinned = !!(a.metadata as Record<string, unknown> | undefined)?.pinned
    const bPinned = !!(b.metadata as Record<string, unknown> | undefined)?.pinned
    if (aPinned !== bPinned) return aPinned ? -1 : 1
    const aUpdated = a.time.updated ?? a.time.created
    const bUpdated = b.time.updated ?? b.time.created
    const aRecent = aUpdated > oneMinuteAgo
    const bRecent = bUpdated > oneMinuteAgo
    if (aRecent && bRecent) return a.id < b.id ? -1 : a.id > b.id ? 1 : 0
    if (aRecent && !bRecent) return -1
    if (!aRecent && bRecent) return 1
    return bUpdated - aUpdated
  }
}

const isRootVisibleSession = (session: Session, directory: string) =>
  pathKey(session.directory) === pathKey(directory) && !session.parentID && !session.time?.archived

export const roots = (store: SessionStore) =>
  (store.session ?? []).filter((session) => isRootVisibleSession(session, store.path.directory))

export const sortedRootSessions = (store: SessionStore, now: number) => roots(store).sort(sortSessions(now))

export const latestRootSession = (stores: SessionStore[], now: number) =>
  stores.flatMap(roots).sort(sortSessions(now))[0]

export function hasProjectPermissions<T>(
  request: Record<string, T[] | undefined> | undefined,
  include: (item: T) => boolean = () => true,
) {
  return Object.values(request ?? {}).some((list) => list?.some(include))
}

export const childSessionOnPath = (sessions: Session[] | undefined, rootID: string, activeID?: string) => {
  if (!activeID || activeID === rootID) return
  const map = new Map((sessions ?? []).map((session) => [session.id, session]))
  let id = activeID

  while (id) {
    const session = map.get(id)
    if (!session?.parentID) return
    if (session.parentID === rootID) return session
    id = session.parentID
  }
}

export function collectSessionFamilyIds(
  sessions: { id: string; parentID?: string }[] | undefined,
  rootID: string | undefined,
): string[] {
  if (!rootID) return []
  const list = sessions ?? []
  const childrenMap = new Map<string, string[]>()
  for (const s of list) {
    if (s.parentID) {
      const existing = childrenMap.get(s.parentID)
      if (existing) existing.push(s.id)
      else childrenMap.set(s.parentID, [s.id])
    }
  }

  const visited = new Set<string>([rootID])
  const queue = [rootID]
  const result: string[] = [rootID]

  while (queue.length > 0) {
    const current = queue.shift()!
    const children = childrenMap.get(current)
    if (children) {
      for (const childId of children) {
        if (!visited.has(childId)) {
          visited.add(childId)
          result.push(childId)
          queue.push(childId)
        }
      }
    }
  }
  return result
}

export const displayName = (project: { name?: string; worktree: string }) =>
  project.name || getFilename(project.worktree) || project.worktree

export type HomeProjectSelection = { server: ServerConnection.Key; directory?: string }

export function toggleHomeProjectSelection(
  current: HomeProjectSelection | undefined,
  server: ServerConnection.Key,
  directory: string,
): HomeProjectSelection {
  if (current?.server === server && current.directory === directory) return { server }
  return { server, directory }
}

export function closeHomeProject(
  selected: HomeProjectSelection | undefined,
  server: ServerConnection.Key,
  projects: { close: (directory: string) => void },
  directory: string,
) {
  projects.close(directory)
  if (selected?.server === server && selected.directory === directory) return { server }
  return selected
}

export function homeProjectNavigation(active: ServerConnection.Key, server: ServerConnection.Key, href: string) {
  if (active === server) return { href }
  return { server, href }
}

export function homeProjectDirectories(result: string | string[] | null) {
  if (!result) return []
  return Array.isArray(result) ? result : [result]
}

export function homeSessionServerStatus(active: boolean, status: () => { working: boolean; tint?: string }) {
  if (!active) return { working: false, tint: undefined }
  return status()
}

const OPENCODE_PROJECT_ID = "4b0ea68d7af9a6031a7ffda7ad66e0cb83315750"

export function getProjectAvatarSource(id?: string, icon?: { color?: string; url?: string; override?: string }) {
  if (id === OPENCODE_PROJECT_ID) return undefined
  if (icon?.override) return icon.override
  if (icon?.color) return undefined
  return icon?.url
}

export function projectForSession<T extends { id?: string; worktree: string; sandboxes?: string[] }>(
  session: Session,
  projects: T[],
  byID: Map<string, T> = new Map(projects.flatMap((project) => (project.id ? [[project.id, project] as const] : []))),
) {
  const direct = byID.get(session.projectID)
  if (direct) return direct
  const directory = pathKey(session.directory)
  return projects.find(
    (project) =>
      pathKey(project.worktree) === directory || project.sandboxes?.some((sandbox) => pathKey(sandbox) === directory),
  )
}

export const errorMessage = (err: unknown, fallback: string) => {
  if (err && typeof err === "object" && "data" in err) {
    const data = (err as { data?: { message?: string } }).data
    if (data?.message) return data.message
  }
  if (err instanceof Error) return err.message
  return fallback
}

export const effectiveWorkspaceOrder = (local: string, dirs: string[], persisted?: string[]) => {
  const root = pathKey(local)
  const live = new Map<string, string>()

  for (const dir of dirs) {
    const key = pathKey(dir)
    if (key === root) continue
    if (!live.has(key)) live.set(key, dir)
  }

  if (!persisted?.length) return [local, ...live.values()]

  const result = [local]
  for (const dir of persisted) {
    const key = pathKey(dir)
    if (key === root) continue
    const match = live.get(key)
    if (!match) continue
    result.push(match)
    live.delete(key)
  }

  return [...result, ...live.values()]
}



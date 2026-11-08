import type { Store, SetStoreFunction } from "solid-js/store"
import { produce } from "solid-js/store"
import { useNavigate, useParams } from "@solidjs/router"
import type { Session } from "@argos/sdk/client"
import { toaster } from "@argos/ui/toast"
import { showToast } from "@/utils/toast"
import { base64Encode } from "@/core/encode"
import { getFilename } from "@/core/path"
import { pathKey } from "@/utils/path-key"
import { Worktree as WorktreeState } from "@/utils/worktree"
import { clearWorkspaceTerminals } from "@/context/terminal"
import { useLayout, type LocalProject } from "@/context/layout"
import { useServerSDK } from "@/context/server-sdk"
import { useServerSync } from "@/context/server-sync"
import { usePlatform } from "@/context/platform"
import { useLanguage } from "@/context/language"
import { effectiveWorkspaceOrder, errorMessage, type LayoutPageStore } from "./helpers"

export type UseWorkspaceActionsOptions = {
  store: Store<LayoutPageStore>
  setStore: SetStoreFunction<LayoutPageStore>
  serverSDK: ReturnType<typeof useServerSDK>
  serverSync: ReturnType<typeof useServerSync>
  layout: ReturnType<typeof useLayout>
  language: ReturnType<typeof useLanguage>
  platform: ReturnType<typeof usePlatform>
  params: ReturnType<typeof useParams>
  navigate: ReturnType<typeof useNavigate>
  currentDir: () => string
  currentProject: () => LocalProject | undefined
  projectRoot: (directory: string) => string
  setBusy: (directory: string, value: boolean) => void
  clearLastProjectSession: (root: string) => void
  clearSidebarHoverState: () => void
  navigateWithSidebarReset: (href: string) => void
}

export function useWorkspaceActions(options: UseWorkspaceActionsOptions) {
  const {
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
  } = options

  const workspaceName = (directory: string, projectId?: string, branch?: string) => {
    const key = pathKey(directory)
    const direct = store.workspaceName[key] ?? store.workspaceName[directory]
    if (direct) return direct
    if (!projectId) return
    if (!branch) return
    return store.workspaceBranchName[projectId]?.[branch]
  }

  const setWorkspaceName = (directory: string, next: string, projectId?: string, branch?: string) => {
    const key = pathKey(directory)
    setStore("workspaceName", key, next)
    if (!projectId) return
    if (!branch) return
    if (!store.workspaceBranchName[projectId]) {
      setStore("workspaceBranchName", projectId, {})
    }
    setStore("workspaceBranchName", projectId, branch, next)
  }

  const workspaceLabel = (directory: string, branch?: string, projectId?: string) =>
    workspaceName(directory, projectId, branch) ?? branch ?? getFilename(directory)

  const renameWorkspace = (directory: string, next: string, projectId?: string, branch?: string) => {
    const current = workspaceName(directory, projectId, branch) ?? branch ?? getFilename(directory)
    if (current === next) return
    setWorkspaceName(directory, next, projectId, branch)
  }

  const deleteWorkspace = async (root: string, directory: string, leaveDeletedWorkspace = false) => {
    if (directory === root) return

    const current = currentDir()
    const currentKey = pathKey(current)
    const deletedKey = pathKey(directory)
    const shouldLeave = leaveDeletedWorkspace || (!!params.dir && currentKey === deletedKey)
    if (!leaveDeletedWorkspace && shouldLeave) {
      navigateWithSidebarReset(`/${base64Encode(root)}/session`)
    }

    setBusy(directory, true)

    const result = await serverSDK.client.worktree
      .remove({ directory: root, worktreeRemoveInput: { directory } })
      .then((x) => x.data)
      .catch((err) => {
        showToast({
          title: language.t("workspace.delete.failed.title"),
          description: errorMessage(err, language.t("common.requestFailed")),
        })
        return false
      })

    setBusy(directory, false)

    if (!result) return

    if (pathKey(store.lastProjectSession[root]?.directory ?? "") === pathKey(directory)) {
      clearLastProjectSession(root)
    }

    serverSync.set(
      "project",
      produce((draft) => {
        const project = draft.find((item) => item.worktree === root)
        if (!project) return
        project.sandboxes = (project.sandboxes ?? []).filter((sandbox) => sandbox !== directory)
      }),
    )
    setStore("workspaceOrder", root, (order) => (order ?? []).filter((workspace) => workspace !== directory))

    layout.projects.close(directory)
    layout.projects.open(root)

    if (shouldLeave) return

    const nextCurrent = currentDir()
    const nextKey = pathKey(nextCurrent)
    const project = layout.projects.list().find((item) => item.worktree === root)
    const dirs = project
      ? effectiveWorkspaceOrder(root, [root, ...(project.sandboxes ?? [])], store.workspaceOrder[root])
      : [root]
    const valid = dirs.some((item) => pathKey(item) === nextKey)

    if (params.dir && projectRoot(nextCurrent) === root && !valid) {
      navigateWithSidebarReset(`/${base64Encode(root)}/session`)
    }
  }

  const resetWorkspace = async (root: string, directory: string) => {
    if (directory === root) return
    setBusy(directory, true)

    const progress = showToast({
      persistent: true,
      title: language.t("workspace.resetting.title"),
      description: language.t("workspace.resetting.description"),
    })
    const dismiss = () => toaster.dismiss(progress)

    const sessions: Session[] = await serverSDK.client.session
      .list({ directory })
      .then((x) => x.data ?? [])
      .catch(() => [])

    clearWorkspaceTerminals(
      directory,
      sessions.map((s) => s.id),
      platform,
      serverSDK.scope,
    )
    await serverSDK.client.instance.dispose({ directory }).catch(() => undefined)

    const result = await serverSDK.client.worktree
      .reset({ directory: root, worktreeResetInput: { directory } })
      .then((x) => x.data)
      .catch((err) => {
        showToast({
          title: language.t("workspace.reset.failed.title"),
          description: errorMessage(err, language.t("common.requestFailed")),
        })
        return false
      })

    if (!result) {
      setBusy(directory, false)
      dismiss()
      return
    }

    const archivedAt = Date.now()
    await Promise.all(
      sessions
        .filter((session) => session.time.archived === undefined)
        .map((session) =>
          serverSDK.client.session
            .update({
              sessionID: session.id,
              directory: session.directory,
              time: { archived: archivedAt },
            })
            .catch(() => undefined),
        ),
    )

    setBusy(directory, false)
    dismiss()

    showToast({
      title: language.t("workspace.reset.success.title"),
      description: language.t("workspace.reset.success.description"),
      actions: [
        {
          label: language.t("command.session.new"),
          onClick: () => {
            const href = `/${base64Encode(directory)}/session`
            navigate(href)
            layout.mobileSidebar.hide()
          },
        },
        {
          label: language.t("common.dismiss"),
          onClick: "dismiss",
        },
      ],
    })
  }

  const createWorkspace = async (project: LocalProject) => {
    clearSidebarHoverState()
    const created = await serverSDK.client.worktree
      .create({ directory: project.worktree })
      .then((x) => x.data)
      .catch((err) => {
        showToast({
          title: language.t("workspace.create.failed.title"),
          description: errorMessage(err, language.t("common.requestFailed")),
        })
        return undefined
      })

    if (!created?.directory) return

    setWorkspaceName(created.directory, created.branch ?? getFilename(created.directory), project.id, created.branch)

    const local = project.worktree
    const key = pathKey(created.directory)
    const root = pathKey(local)

    setBusy(created.directory, true)
    WorktreeState.pending(serverSDK.scope, created.directory)
    setStore("workspaceExpanded", key, true)
    if (key !== created.directory) {
      setStore("workspaceExpanded", created.directory, true)
    }
    setStore("workspaceOrder", project.worktree, (prev) => {
      const existing = prev ?? []
      const next = existing.filter((item) => {
        const id = pathKey(item)
        return id !== root && id !== key
      })
      return [created.directory, ...next]
    })

    serverSync.child(created.directory)
    navigateWithSidebarReset(`/${base64Encode(created.directory)}/session`)
  }

  function toggleProjectWorkspaces(project: LocalProject) {
    const enabled = layout.sidebar.workspaces(project.worktree)()
    if (enabled) {
      layout.sidebar.toggleWorkspaces(project.worktree)
      return
    }
    if (project.vcs !== "git") return
    layout.sidebar.toggleWorkspaces(project.worktree)
  }

  function workspaceIds(project: LocalProject | undefined) {
    if (!project) return []
    const local = project.worktree
    const dirs = [local, ...(project.sandboxes ?? [])]
    const active = currentProject()
    const directory = pathKey(active?.worktree ?? "") === pathKey(project.worktree) ? currentDir() : undefined
    const extra =
      directory && pathKey(directory) !== pathKey(local) && !dirs.some((item) => pathKey(item) === pathKey(directory))
        ? directory
        : undefined
    const pending = extra ? WorktreeState.get(serverSDK.scope, extra)?.status === "pending" : false

    const ordered = effectiveWorkspaceOrder(local, dirs, store.workspaceOrder[project.worktree])
    if (pending && extra) return [local, extra, ...ordered.filter((item) => item !== local)]
    if (!extra) return ordered
    if (pending) return ordered
    return [...ordered, extra]
  }

  return {
    workspaceName,
    setWorkspaceName,
    workspaceLabel,
    renameWorkspace,
    deleteWorkspace,
    resetWorkspace,
    createWorkspace,
    toggleProjectWorkspaces,
    workspaceIds,
  }
}

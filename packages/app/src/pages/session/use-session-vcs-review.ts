import { createMemo, onCleanup, type Accessor } from "solid-js"
import { createQuery, skipToken, useQueryClient } from "@tanstack/solid-query"
import { debounce } from "@solid-primitives/scheduled"
import type { UserMessage } from "@argos/sdk/client"
import { useSDK } from "@/context/sdk"
import { useSync } from "@/context/sync"
import { diffs as list } from "@/utils/diffs"

export type ChangeMode = "git" | "branch" | "turn"
export type VcsMode = "git" | "branch"

export function useSessionVcsReview(input: {
  changes: () => ChangeMode
  wantsReview: () => boolean
  lastUserMessage: Accessor<UserMessage | undefined>
}) {
  const sdk = useSDK()
  const sync = useSync()
  const queryClient = useQueryClient()

  const turnDiffs = createMemo(() => list(input.lastUserMessage()?.summary?.diffs))
  const changesOptions = createMemo<ChangeMode[]>(() => {
    const list: ChangeMode[] = []
    if (sync.project?.vcs === "git") list.push("git")
    if (
      sync.project?.vcs === "git" &&
      sync.data.vcs?.branch &&
      sync.data.vcs?.default_branch &&
      sync.data.vcs.branch !== sync.data.vcs.default_branch
    ) {
      list.push("branch")
    }
    list.push("turn")
    return list
  })
  const vcsMode = createMemo<VcsMode | undefined>(() => {
    const changes = input.changes()
    if (changes === "git" || changes === "branch") return changes
  })
  const vcsKey = createMemo(
    () => ["session-vcs", sdk.directory, sync.data.vcs?.branch ?? "", sync.data.vcs?.default_branch ?? ""] as const,
  )
  const vcsQuery = createQuery(() => {
    const mode = vcsMode()
    const enabled = input.wantsReview() && sync.project?.vcs === "git"

    return {
      queryKey: [...vcsKey(), mode] as const,
      enabled,
      queryFn: mode
        ? () =>
            sdk.client.vcs
              .diff({ mode })
              .then((result) => list(result.data))
              .catch((error) => {
                console.debug("[session-review] failed to load vcs diff", { mode, error })
                return []
              })
        : skipToken,
    }
  })
  const refreshVcs = debounce(() => void queryClient.invalidateQueries({ queryKey: vcsKey() }), 100)
  const reviewDiffs = () => {
    if (input.changes() === "git" || input.changes() === "branch")
      // avoids suspense
      return vcsQuery.isFetched ? (vcsQuery.data ?? []) : []
    return turnDiffs()
  }
  const reviewCount = () => reviewDiffs().length
  const hasReview = () => reviewCount() > 0
  const reviewReady = () => {
    if (input.changes() === "git" || input.changes() === "branch") return !vcsQuery.isPending
    return true
  }

  const stopVcs = sdk.event.listen((evt) => {
    if (evt.details.type !== "file.watcher.updated") return
    const props =
      typeof evt.details.properties === "object" && evt.details.properties
        ? (evt.details.properties as Record<string, unknown>)
        : undefined
    const file = typeof props?.file === "string" ? props.file : undefined
    if (!file || file.startsWith(".git/")) return
    refreshVcs()
  })
  onCleanup(stopVcs)

  return {
    changesOptions,
    vcsMode,
    reviewDiffs,
    reviewCount,
    hasReview,
    reviewReady,
    refreshVcs,
  }
}

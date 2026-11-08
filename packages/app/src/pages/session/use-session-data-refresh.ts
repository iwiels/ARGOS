import { createEffect, createResource, on, onCleanup, untrack } from "solid-js"
import { getSessionPrefetch, SESSION_PREFETCH_TTL } from "@/context/global-sync/session-prefetch"
import { useServerSync } from "@/context/server-sync"
import { useServerSDK } from "@/context/server-sdk"
import { useSDK } from "@/context/sdk"
import { useSync } from "@/context/sync"

export function useSessionDataRefresh(input: {
  sessionID: () => string | undefined
  blocked: () => boolean
}) {
  const sdk = useSDK()
  const serverSDK = useServerSDK()
  const sync = useSync()
  const serverSync = useServerSync()

  let refreshFrame: number | undefined
  let refreshTimer: number | undefined
  let todoFrame: number | undefined
  let todoTimer: number | undefined

  const [sessionSync] = createResource(
    () => [sdk.directory, input.sessionID()] as const,
    ([directory, id]) => {
      if (refreshFrame !== undefined) cancelAnimationFrame(refreshFrame)
      if (refreshTimer !== undefined) window.clearTimeout(refreshTimer)
      refreshFrame = undefined
      refreshTimer = undefined
      if (!id) return

      const cached = untrack(() => sync.data.message[id] !== undefined)
      const stale = !cached
        ? false
        : (() => {
            const info = getSessionPrefetch(serverSDK.scope, directory, id)
            if (!info) return true
            return Date.now() - info.at > SESSION_PREFETCH_TTL
          })()

      refreshFrame = requestAnimationFrame(() => {
        refreshFrame = undefined
        refreshTimer = window.setTimeout(() => {
          refreshTimer = undefined
          if (input.sessionID() !== id) return
          untrack(() => {
            if (stale) void sync.session.sync(id, { force: true })
          })
        }, 0)
      })

      return sync.session.sync(id)
    },
  )

  createEffect(
    on(
      () => {
        const id = input.sessionID()
        return [
          sdk.directory,
          id,
          id ? (sync.data.session_status[id]?.type ?? "idle") : "idle",
          id ? input.blocked() : false,
        ] as const
      },
      ([dir, id, status, blocked]) => {
        if (todoFrame !== undefined) cancelAnimationFrame(todoFrame)
        if (todoTimer !== undefined) window.clearTimeout(todoTimer)
        todoFrame = undefined
        todoTimer = undefined
        if (!id) return
        if (status === "idle" && !blocked) return
        const cached = untrack(() => sync.data.todo[id] !== undefined || serverSync.data.session_todo[id] !== undefined)

        todoFrame = requestAnimationFrame(() => {
          todoFrame = undefined
          todoTimer = window.setTimeout(() => {
            todoTimer = undefined
            if (sdk.directory !== dir || input.sessionID() !== id) return
            untrack(() => {
              void sync.session.todo(id, cached ? { force: true } : undefined)
            })
          }, 0)
        })
      },
      { defer: true },
    ),
  )

  onCleanup(() => {
    if (refreshFrame !== undefined) cancelAnimationFrame(refreshFrame)
    if (refreshTimer !== undefined) window.clearTimeout(refreshTimer)
    if (todoFrame !== undefined) cancelAnimationFrame(todoFrame)
    if (todoTimer !== undefined) window.clearTimeout(todoTimer)
  })

  return { sessionSync }
}

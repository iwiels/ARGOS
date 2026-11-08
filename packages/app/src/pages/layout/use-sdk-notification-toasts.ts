import { createEffect, onCleanup, onMount } from "solid-js"
import { useNavigate, useParams } from "@solidjs/router"
import type { PermissionRequest } from "@argos/sdk/client"
import { toaster } from "@argos/ui/toast"
import { showToast } from "@/utils/toast"
import { base64Encode } from "@/core/encode"
import { getFilename } from "@/core/path"
import { pathKey } from "@/utils/path-key"
import { playSoundById } from "@/utils/sound"
import { Worktree as WorktreeState } from "@/utils/worktree"
import { useServerSDK } from "@/context/server-sdk"
import { useServerSync } from "@/context/server-sync"
import { useSettings } from "@/context/settings"
import { usePlatform } from "@/context/platform"
import { usePermission } from "@/context/permission"
import { useLanguage } from "@/context/language"

export type UseSdkNotificationToastsOptions = {
  serverSDK: ReturnType<typeof useServerSDK>
  serverSync: ReturnType<typeof useServerSync>
  settings: ReturnType<typeof useSettings>
  platform: ReturnType<typeof usePlatform>
  permission: ReturnType<typeof usePermission>
  language: ReturnType<typeof useLanguage>
  navigate: ReturnType<typeof useNavigate>
  params: ReturnType<typeof useParams>
  currentDir: () => string
  setBusy: (directory: string, value: boolean) => void
}

export function useSdkNotificationToasts(options: UseSdkNotificationToastsOptions) {
  const { serverSDK, serverSync, settings, platform, permission, language, navigate, params, currentDir, setBusy } =
    options

  onMount(() => {
    const toastBySession = new Map<string, number>()
    const alertedAtBySession = new Map<string, number>()
    const cooldownMs = 5000

    const dismissSessionAlert = (sessionKey: string) => {
      const toastId = toastBySession.get(sessionKey)
      if (toastId === undefined) return
      toaster.dismiss(toastId)
      toastBySession.delete(sessionKey)
      alertedAtBySession.delete(sessionKey)
    }

    const unsub = serverSDK.event.listen((e) => {
      if (e.details?.type === "worktree.ready") {
        setBusy(e.name, false)
        WorktreeState.ready(serverSDK.scope, e.name)
        return
      }

      if (e.details?.type === "worktree.failed") {
        setBusy(e.name, false)
        WorktreeState.failed(
          serverSDK.scope,
          e.name,
          e.details.properties?.message ?? language.t("common.requestFailed"),
        )
        return
      }

      if (
        e.details?.type === "question.replied" ||
        e.details?.type === "question.rejected" ||
        e.details?.type === "permission.replied"
      ) {
        const props = e.details.properties as { sessionID: string }
        const sessionKey = `${e.name}:${props.sessionID}`
        dismissSessionAlert(sessionKey)
        return
      }

      if (e.details?.type !== "permission.asked" && e.details?.type !== "question.asked") return
      const title =
        e.details.type === "permission.asked"
          ? language.t("notification.permission.title")
          : language.t("notification.question.title")
      const icon = e.details.type === "permission.asked" ? ("checklist" as const) : ("bubble-5" as const)
      const directory = e.name
      const props = e.details.properties
      if (e.details.type === "permission.asked" && permission.autoResponds(e.details.properties as PermissionRequest, directory)) return

      const [store] = serverSync.child(directory, { bootstrap: false })
      const session = store.session.find((s) => s.id === props.sessionID)
      const sessionKey = `${directory}:${props.sessionID}`

      const sessionTitle = session?.title ?? language.t("command.session.new")
      const projectName = getFilename(directory)
      const description =
        e.details.type === "permission.asked"
          ? language.t("notification.permission.description", { sessionTitle, projectName })
          : language.t("notification.question.description", { sessionTitle, projectName })
      const href = `/${base64Encode(directory)}/session/${props.sessionID}`

      const now = Date.now()
      const lastAlerted = alertedAtBySession.get(sessionKey) ?? 0
      if (now - lastAlerted < cooldownMs) return
      alertedAtBySession.set(sessionKey, now)

      if (e.details.type === "permission.asked") {
        if (settings.sounds.permissionsEnabled()) {
          void playSoundById(settings.sounds.permissions())
        }
        if (settings.notifications.permissions()) {
          void platform.notify(title, description, href)
        }
      }

      if (e.details.type === "question.asked") {
        if (settings.notifications.agent()) {
          void platform.notify(title, description, href)
        }
      }

      const currentSession = params.id
      if (pathKey(directory) === pathKey(currentDir()) && props.sessionID === currentSession) return
      if (pathKey(directory) === pathKey(currentDir()) && session?.parentID === currentSession) return

      dismissSessionAlert(sessionKey)

      const toastId = showToast({
        persistent: true,
        icon,
        title,
        description,
        actions: [
          {
            label: language.t("notification.action.goToSession"),
            onClick: () => navigate(href),
          },
          {
            label: language.t("common.dismiss"),
            onClick: "dismiss",
          },
        ],
      })
      toastBySession.set(sessionKey, toastId)
    })
    onCleanup(unsub)

    createEffect(() => {
      const currentSession = params.id
      if (!currentDir() || !currentSession) return
      const sessionKey = `${currentDir()}:${currentSession}`
      dismissSessionAlert(sessionKey)
      const [store] = serverSync.child(currentDir(), { bootstrap: false })
      const childSessions = store.session.filter((s) => s.parentID === currentSession)
      for (const child of childSessions) {
        dismissSessionAlert(`${currentDir()}:${child.id}`)
      }
    })
  })
}

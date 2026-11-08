// @refresh reload

import {
  ACCEPTED_FILE_EXTENSIONS,
  AppBaseProviders,
  AppInterface,
  handleNotificationClick,
  loadLocaleDict,
  normalizeLocale,
  type Locale,
  type Platform,
  PlatformProvider,
  ServerConnection,
  useCommand,
  useLanguage,
  useWslServers,
  type WslToolAvailability,
} from "@argos/app"
import type { UpdaterState } from "@argos/app/updater"
import * as Sentry from "@sentry/solid"
import type { AsyncStorage } from "@solid-primitives/storage"
import { MemoryRouter } from "@solidjs/router"
import { createEffect, createMemo, createResource, createSignal, onCleanup, onMount, Show } from "solid-js"
import { render } from "solid-js/web"
import pkg from "../../package.json"
import { WSL_MULTI_SERVER_MANAGEMENT_ENABLED } from "../shared/feature-flags"
import { initI18n, t } from "./i18n"
import { initializationData } from "./initialization"
import { resetZoom, setPinchZoomEnabled, webviewZoom, zoomIn, zoomOut } from "./webview-zoom"
import { availableStartupServer, primaryServerConnection, readyWslConnections } from "./wsl/connections"
import "./styles.css"
import { ThinkingOrb } from "@argos/ui/thinking-orb"
import { Button } from "@argos/ui/button"
import { useTheme } from "@argos/ui/theme/context"

const root = document.getElementById("root")

function RuntimeCapabilityNotice(props: {
  reason: string
  onRetry?: () => void | Promise<void>
  onRestart?: () => void | Promise<void>
}) {
  const language = useLanguage()
  return (
    <div role="status" class="mx-4 mt-3 rounded-md border border-icon-warning-base/40 bg-bg-surface px-4 py-3">
      <div class="text-13-medium text-icon-warning-base">{language.t("runtime.webAudit.disabled")}</div>
      <div class="mt-1 text-12-regular text-text-weak whitespace-pre-wrap break-words">{props.reason}</div>
      <div class="mt-3 flex items-center gap-3">
        <Show when={props.onRetry}>
          <Button size="normal" variant="secondary" onClick={() => void props.onRetry?.()}>
            {language.t("wsl.onboarding.refresh")}
          </Button>
        </Show>
        <Button size="normal" variant="ghost" onClick={() => void props.onRestart?.()}>
          {language.t("error.page.action.restart")}
        </Button>
      </div>
    </div>
  )
}

if (typeof window !== "undefined" && !window.api) {
  const noopProxy = new Proxy(() => {}, {
    get: (target, prop) => {
      if (prop === "then") return undefined
      return noopProxy
    },
    apply: () => Promise.resolve(null),
  })
  window.api = noopProxy as any
}
if (import.meta.env.DEV && !(root instanceof HTMLElement)) {
  throw new Error(t("error.dev.rootNotFound"))
}

if (import.meta.env.VITE_SENTRY_DSN) {
  Sentry.init({
    dsn: import.meta.env.VITE_SENTRY_DSN,
    environment: import.meta.env.VITE_SENTRY_ENVIRONMENT ?? import.meta.env.MODE,
    release: import.meta.env.VITE_SENTRY_RELEASE ?? `desktop@${pkg.version}`,
    initialScope: {
      tags: {
        platform: "desktop",
      },
    },
    integrations: (integrations) => {
      return integrations.filter(
        (i) =>
          i.name !== "Breadcrumbs" &&
          !(
            import.meta.env.OPENCODE_CHANNEL === "prod" &&
            (i.name === "GlobalHandlers" || i.name === "BrowserApiErrors")
          ),
      )
    },
  })
}

void initI18n()

const [updaterState, setUpdaterState] = createSignal<UpdaterState>({ status: "disabled" })
void window.api.updater.subscribe(setUpdaterState)

const deepLinkEvent = "opencode:deep-link"

const emitDeepLinks = (urls: string[] | null) => {
  if (!urls || urls.length === 0) return
  window.__ARGOS__ ??= {}
  const pending = window.__ARGOS__.deepLinks ?? []
  window.__ARGOS__.deepLinks = [...pending, ...urls]
  window.dispatchEvent(new CustomEvent(deepLinkEvent, { detail: { urls } }))
}

const listenForDeepLinks = () => {
  void window.api.consumeInitialDeepLinks().then((urls) => emitDeepLinks(urls))
  return window.api.onDeepLink((urls) => emitDeepLinks(urls))
}

const createPlatform = (): Platform => {
  const os = (() => {
    const ua = navigator.userAgent
    if (ua.includes("Mac")) return "macos"
    if (ua.includes("Windows")) return "windows"
    if (ua.includes("Linux")) return "linux"
    return undefined
  })()

  const runDesktopMenuAction: Platform["runDesktopMenuAction"] = (action) => {
    switch (action) {
      case "view.resetZoom":
        resetZoom()
        return
      case "view.zoomIn":
        zoomIn()
        return
      case "view.zoomOut":
        zoomOut()
        return
    }

    return window.api.runDesktopMenuAction(action)
  }

  const storage = (() => {
    const cache = new Map<string, AsyncStorage>()

    const createStorage = (name: string) => {
      const api: AsyncStorage = {
        getItem: (key: string) => window.api.storeGet(name, key),
        setItem: (key: string, value: string) => window.api.storeSet(name, key, value),
        removeItem: (key: string) => window.api.storeDelete(name, key),
        clear: () => window.api.storeClear(name),
        key: async (index: number) => (await window.api.storeKeys(name))[index],
        getLength: () => window.api.storeLength(name),
        get length() {
          return api.getLength()
        },
      }
      return api
    }

    return (name = "default.dat") => {
      const cached = cache.get(name)
      if (cached) return cached
      const api = createStorage(name)
      cache.set(name, api)
      return api
    }
  })()

  const wslServersApi = WSL_MULTI_SERVER_MANAGEMENT_ENABLED && os === "windows" ? window.api.wslServers : undefined
  const wslSetupApi =
    os === "windows"
      ? {
          getState: () => window.api.wslServers.getState(),
          probeRuntime: () => window.api.wslServers.probeRuntime(),
          installWsl: () => window.api.wslServers.installWsl(),
        }
      : undefined

  return {
    platform: "desktop",
    os,
    version: pkg.version,

    async openDirectoryPickerDialog(opts) {
      return window.api.openDirectoryPicker({
        multiple: opts?.multiple ?? false,
        title: opts?.title ?? t("desktop.dialog.chooseFolder"),
      })
    },

    async openAttachmentPickerDialog(opts, onFile) {
      const result = await window.api.openFilePicker({
        multiple: opts?.multiple ?? false,
        title: opts?.title ?? t("desktop.dialog.chooseFile"),
        defaultPath: opts?.defaultPath,
        extensions: opts?.extensions ?? ACCEPTED_FILE_EXTENSIONS,
      })
      if (!result) return
      try {
        for (const file of result.files) {
          await onFile(new File([await window.api.readPickedFile(result.token, file.path)], file.name))
        }
      } finally {
        await window.api.releasePickedFiles(result.token)
      }
    },

    async saveFilePickerDialog(opts) {
      return window.api.saveFilePicker({
        title: opts?.title ?? t("desktop.dialog.saveFile"),
        defaultPath: opts?.defaultPath,
      })
    },

    openLink(url: string) {
      window.api.openLink(url)
    },
    async openPath(path: string, app?: string) {
      // App-name resolution (e.g. locating the Windows executable for a
      // given editor) happens inside the main process's "open-path" IPC
      // handler now, against a validated allowlist of identifiers - the
      // renderer must not be trusted to hand main a pre-resolved executable
      // path to run.
      return window.api.openPath(path, app)
    },

    back() {
      window.history.back()
    },

    forward() {
      window.history.forward()
    },

    storage,

    updater: {
      state: updaterState,
      check: () => window.api.updater.check(),
      install: () => window.api.updater.install(),
    },

    exportDebugLogs: () => window.api.exportDebugLogs(),

    recordFatalRendererError: (error) => window.api.recordFatalRendererError(error),

    restart: async () => {
      await window.api.killSidecar().catch(() => undefined)
      if (import.meta.env.DEV) {
        window.location.reload()
      } else {
        window.api.relaunch()
      }
    },

    notify: async (title, description, href) => {
      const focused = await window.api.getWindowFocused().catch(() => document.hasFocus())
      if (focused) return

      const notification = new Notification(title, {
        body: description ?? "",
      })
      notification.onclick = () => {
        void window.api.showWindow()
        void window.api.setWindowFocus()
        handleNotificationClick(href)
        notification.close()
      }
    },

    fetch: (input, init) => {
      if (input instanceof Request) return fetch(input)
      return fetch(input, init)
    },

    getDefaultServer: async () => {
      const url = await window.api.getDefaultServerUrl().catch(() => null)
      if (!url) return null
      return ServerConnection.Key.make(url)
    },

    setDefaultServer: async (url: string | null) => {
      await window.api.setDefaultServerUrl(url)
    },

    wslServers: wslServersApi,
    wslSetup: wslSetupApi,

    refreshRuntimeTools: () => window.api.refreshRuntimeTools(),

    getDisplayBackend: async () => {
      return window.api.getDisplayBackend().catch(() => null)
    },

    setDisplayBackend: async (backend) => {
      await window.api.setDisplayBackend(backend)
    },

    webviewZoom,

    getPinchZoomEnabled: () => window.api.getPinchZoomEnabled(),

    setPinchZoomEnabled,

    runDesktopMenuAction,

    checkAppExists: async (appName: string) => {
      return window.api.checkAppExists(appName)
    },

    async readClipboardImage() {
      const image = await window.api.readClipboardImage().catch(() => null)
      if (!image) return null
      const blob = new Blob([image.buffer], { type: "image/png" })
      return new File([blob], `pasted-image-${Date.now()}.png`, {
        type: "image/png",
      })
    },
  }
}

let menuTrigger = null as null | ((id: string) => void)
window.api.onMenuCommand((id) => {
  menuTrigger?.(id)
})
listenForDeepLinks()

render(() => {
  const platform = createPlatform()
  const loadLocale = async () => {
    const current = await platform.storage?.("opencode.global.dat").getItem("language")
    const legacy = current ? undefined : await platform.storage?.().getItem("language.v1")
    const raw = current ?? legacy
    if (!raw) return
    const locale = raw.match(/"locale"\s*:\s*"([^"]+)"/)?.[1]
    if (!locale) return
    const next = normalizeLocale(locale)
    if (next !== "en") await loadLocaleDict(next)
    return next satisfies Locale
  }

  const [windowCount] = createResource(() => window.api.getWindowCount())

  // Fetch sidecar credentials (available immediately, before health check)
  const [sidecar] = createResource(() => window.api.awaitInitialization())

  const [defaultServer] = createResource(() => platform.getDefaultServer?.())
  const [locale] = createResource(loadLocale)

  function handleClick(e: MouseEvent) {
    const link = (e.target as HTMLElement).closest("a.external-link") as HTMLAnchorElement | null
    if (link?.href) {
      e.preventDefault()
      platform.openLink(link.href)
    }
  }

  function Inner() {
    const cmd = useCommand()
    menuTrigger = (id) => cmd.trigger(id)

    const theme = useTheme()

    createEffect(() => {
      theme.mode()
      const bg = getComputedStyle(document.documentElement).getPropertyValue("--bg-base").trim()
      if (bg) {
        void window.api.setBackgroundColor(bg)
      }
    })

    return null
  }

  function App() {
    const wslServers = useWslServers()
    const [runtimeTools, setRuntimeTools] = createSignal<Record<string, WslToolAvailability> | null>(null)
    const webAuditRuntime = createMemo(() => {
      const data = initializationData(sidecar)
      if (!data) return null
      const availability = (runtimeTools() ?? data.tools)?.["argos-web"]
      return availability && !availability.available ? availability : null
    })
    const retryRuntime = async () => {
      const tools = await platform.refreshRuntimeTools?.().catch(() => null)
      if (tools) setRuntimeTools(tools)
    }
    const splash = (
      <div class="h-dvh w-screen flex flex-col items-center justify-center bg-background-base">
        <ThinkingOrb state="listening" size={64} />
      </div>
    )

    const ready = createMemo(
      () => !defaultServer.loading && !sidecar.loading && !windowCount.loading && !locale.loading,
    )
    const servers = createMemo(() => {
      const data = initializationData(sidecar)
      const list: ServerConnection.Any[] = []
      if (data) {
        list.push(primaryServerConnection(data))
      }
      if (list.length === 0 && import.meta.env.DEV) {
        list.push({
          displayName: "Dev Server",
          type: "http",
          http: {
            url: "http://127.0.0.1:4096",
          },
        })
      }
      list.push(...readyWslConnections(wslServers.data))
      return list
    })
    const effectiveDefaultServer = createMemo(() => {
      const serverKey = availableStartupServer(defaultServer.latest, wslServers.data)
      if (serverKey) return ServerConnection.Key.make(serverKey)
      const first = servers()[0]
      return first ? ServerConnection.key(first) : ServerConnection.Key.make("http://127.0.0.1:4096")
    })

    return (
      <Show when={ready()} fallback={splash}>
        <Show when={effectiveDefaultServer()} keyed>
          {(key) => (
            <AppInterface defaultServer={key} servers={servers()} router={MemoryRouter}>
              <Show when={webAuditRuntime()}>
                {(runtime) => (
                  <RuntimeCapabilityNotice
                    reason={runtime().reason ?? ""}
                    onRetry={platform.refreshRuntimeTools ? retryRuntime : undefined}
                    onRestart={platform.restart}
                  />
                )}
              </Show>
              <Inner />
            </AppInterface>
          )}
        </Show>
      </Show>
    )
  }

  onMount(() => {
    document.addEventListener("click", handleClick)
    onCleanup(() => {
      document.removeEventListener("click", handleClick)
    })
  })

  return (
    <PlatformProvider value={platform}>
      <AppBaseProviders locale={locale.latest}>
        <Show when={true}>{(_) => <App />}</Show>
      </AppBaseProviders>
    </PlatformProvider>
  )
}, root!)

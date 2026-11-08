import { AppIcon } from "@argos/ui/app-icon"
import { DropdownMenu } from "@argos/ui/dropdown-menu"
import { Icon } from "@argos/ui/icon"
import { IconButton } from "@argos/ui/icon-button"
import { showToast } from "@/utils/toast"
import { Tooltip } from "@argos/ui/tooltip"
import { createEffect, createMemo, For, Show } from "solid-js"
import { createStore } from "solid-js/store"
import { useLanguage } from "@/context/language"
import { usePlatform } from "@/context/platform"
import { useServer } from "@/context/server"
import { useSDK } from "@/context/sdk"
import { useSync } from "@/context/sync"
import { useTerminal } from "@/context/terminal"
import { focusTerminalById } from "@/pages/session/helpers"
import { useSessionLayout } from "@/pages/session/session-layout"
import { decode64 } from "@/utils/base64"
import { showRequestError } from "@/utils/request-error"
import { Persist, persisted } from "@/utils/persist"
import { sessionTitle } from "@/utils/session-title"
import { SessionContextUsage } from "@/components/session-context-usage"
import { AuthProfilesDialog } from "@/components/session/auth-profiles-dialog"
import { useDialog } from "@argos/ui/context/dialog"

const OPEN_APPS = [
  "vscode",
  "cursor",
  "zed",
  "textmate",
  "antigravity",
  "finder",
  "terminal",
  "iterm2",
  "ghostty",
  "warp",
  "xcode",
  "android-studio",
  "powershell",
  "sublime-text",
] as const

type OpenApp = (typeof OPEN_APPS)[number]
type OS = "macos" | "windows" | "linux" | "unknown"

const MAC_APPS = [
  { id: "vscode", label: "session.header.open.app.vscode", icon: "vscode", openWith: "Visual Studio Code" },
  { id: "cursor", label: "session.header.open.app.cursor", icon: "cursor", openWith: "Cursor" },
  { id: "zed", label: "session.header.open.app.zed", icon: "zed", openWith: "Zed" },
  { id: "textmate", label: "session.header.open.app.textmate", icon: "textmate", openWith: "TextMate" },
  { id: "antigravity", label: "session.header.open.app.antigravity", icon: "antigravity", openWith: "Antigravity" },
  { id: "terminal", label: "session.header.open.app.terminal", icon: "terminal", openWith: "Terminal" },
  { id: "iterm2", label: "session.header.open.app.iterm2", icon: "iterm2", openWith: "iTerm" },
  { id: "ghostty", label: "session.header.open.app.ghostty", icon: "ghostty", openWith: "Ghostty" },
  { id: "warp", label: "session.header.open.app.warp", icon: "warp", openWith: "Warp" },
  { id: "xcode", label: "session.header.open.app.xcode", icon: "xcode", openWith: "Xcode" },
  { id: "android-studio", label: "session.header.open.app.androidStudio", icon: "android-studio", openWith: "Android Studio" },
  { id: "sublime-text", label: "session.header.open.app.sublimeText", icon: "sublime-text", openWith: "Sublime Text" },
] as const

const WINDOWS_APPS = [
  { id: "vscode", label: "session.header.open.app.vscode", icon: "vscode", openWith: "code" },
  { id: "cursor", label: "session.header.open.app.cursor", icon: "cursor", openWith: "cursor" },
  { id: "zed", label: "session.header.open.app.zed", icon: "zed", openWith: "zed" },
  { id: "powershell", label: "session.header.open.app.powershell", icon: "powershell", openWith: "powershell" },
  { id: "sublime-text", label: "session.header.open.app.sublimeText", icon: "sublime-text", openWith: "Sublime Text" },
] as const

const LINUX_APPS = [
  { id: "vscode", label: "session.header.open.app.vscode", icon: "vscode", openWith: "code" },
  { id: "cursor", label: "session.header.open.app.cursor", icon: "cursor", openWith: "cursor" },
  { id: "zed", label: "session.header.open.app.zed", icon: "zed", openWith: "zed" },
  { id: "sublime-text", label: "session.header.open.app.sublimeText", icon: "sublime-text", openWith: "Sublime Text" },
] as const

const detectOS = (platform: ReturnType<typeof usePlatform>): OS => {
  if (platform.platform === "desktop" && platform.os) return platform.os
  if (typeof navigator !== "object") return "unknown"
  const value = navigator.platform || navigator.userAgent
  if (/Mac/i.test(value)) return "macos"
  if (/Win/i.test(value)) return "windows"
  if (/Linux/i.test(value)) return "linux"
  return "unknown"
}

export function SessionHeader() {
  const dialog = useDialog()
  const server = useServer()
  const platform = usePlatform()
  const language = useLanguage()
  const sync = useSync()
  const sdk = useSDK()
  const terminal = useTerminal()
  const { params, view } = useSessionLayout()

  const projectDirectory = createMemo(() => decode64(params.dir) ?? "")
  const os = createMemo(() => detectOS(platform))

  const currentSession = createMemo(() => (sync.data.session ?? []).find((s) => s.id === params.id))
  const title = createMemo(() => sessionTitle(currentSession()?.title) || language.t("session.untitled"))

  const [exists, setExists] = createStore<Partial<Record<OpenApp, boolean>>>({
    finder: true,
  })

  const apps = createMemo(() => {
    if (os() === "macos") return MAC_APPS
    if (os() === "windows") return WINDOWS_APPS
    return LINUX_APPS
  })

  const fileManager = createMemo(() => {
    if (os() === "macos") return { label: "session.header.open.finder", icon: "finder" as const }
    if (os() === "windows") return { label: "session.header.open.fileExplorer", icon: "file-explorer" as const }
    return { label: "session.header.open.fileManager", icon: "finder" as const }
  })

  createEffect(() => {
    if (platform.platform !== "desktop") return
    if (!platform.checkAppExists) return

    const list = apps()
    setExists(Object.fromEntries(list.map((app) => [app.id, undefined])) as Partial<Record<OpenApp, boolean>>)

    void Promise.all(
      list.map((app) =>
        Promise.resolve(platform.checkAppExists?.(app.openWith))
          .then((value) => Boolean(value))
          .catch(() => false)
          .then((ok) => [app.id, ok] as const),
      ),
    ).then((entries) => {
      setExists(Object.fromEntries(entries) as Partial<Record<OpenApp, boolean>>)
    })
  })

  const options = createMemo(() => {
    return [
      { id: "finder", label: language.t(fileManager().label), icon: fileManager().icon },
      ...apps()
        .filter((app) => exists[app.id])
        .map((app) => ({ ...app, label: language.t(app.label) })),
    ] as const
  })

  const toggleTerminal = () => {
    const next = !view().terminal.opened()
    view().terminal.toggle()
    if (!next) return

    const id = terminal.active()
    if (!id) return
    focusTerminalById(id)
  }

  const [prefs, setPrefs] = persisted(Persist.global("open.app"), createStore({ app: "finder" as OpenApp }))
  const [menu, setMenu] = createStore({ open: false })
  const [moreMenu, setMoreMenu] = createStore({ open: false })
  const [openRequest, setOpenRequest] = createStore({
    app: undefined as OpenApp | undefined,
  })

  const canOpen = createMemo(() => platform.platform === "desktop" && !!platform.openPath && server.isLocal())
  const current = createMemo(
    () =>
      options().find((o) => o.id === prefs.app) ??
      options()[0] ??
      ({ id: "finder", label: fileManager().label, icon: fileManager().icon } as const),
  )
  const opening = createMemo(() => openRequest.app !== undefined)

  const selectApp = (app: OpenApp) => {
    if (!options().some((item) => item.id === app)) return
    setPrefs("app", app)
  }

  const openDir = (app: OpenApp) => {
    if (opening() || !canOpen() || !platform.openPath) return
    const directory = projectDirectory()
    if (!directory) return

    const item = options().find((o) => o.id === app)
    const openWith = item && "openWith" in item ? item.openWith : undefined
    setOpenRequest("app", app)
    platform
      .openPath(directory, openWith)
      .catch((err: unknown) => showRequestError(language, err))
      .finally(() => {
        setOpenRequest("app", undefined)
      })
  }

  const copyPath = () => {
    const directory = projectDirectory()
    if (!directory) return
    navigator.clipboard
      .writeText(directory)
      .then(() => {
        showToast({
          icon: "circle-check",
          title: language.t("session.share.copy.copied"),
          description: directory,
        })
      })
      .catch((err: unknown) => showRequestError(language, err))
  }

  // Parada de emergencia del engagement: corta la ejecución en curso, marca la
  // sesión como abortada (las tools siguientes fallan rápido), mata los
  // subprocesos de los scanners y deja el evento en la cadena de auditoría.
  const emergencyStop = () => {
    const sessionID = params.id
    if (!sessionID) return
    void sdk
      .request(`/session/${sessionID}/emergency-stop`, { method: "POST" })
      .then(() =>
        showToast({
          icon: "circle-check",
          title: language.t("session.header.emergencyStop"),
          description: language.t("session.header.emergencyStop.done"),
        }),
      )
      .catch((err: unknown) => showRequestError(language, err))
  }

  const exportSession = () => {    const messages = params.id ? sync.data.message[params.id] ?? [] : []
    let text = `# ${title()}\n\n`
    for (const m of messages) {
      const parts = sync.data.part[m.id] ?? []
      for (const p of parts) {
        if (p.type === "text" && typeof (p as any).text === "string") {
          text += `${(p as any).text}\n\n`
        }
      }
    }
    const blob = new Blob([text], { type: "text/markdown" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = `${title().replace(/[^a-zA-Z0-9_-]/g, "_")}.md`
    a.click()
    URL.revokeObjectURL(url)
    showToast({
      icon: "circle-check",
      title: language.t("session.export.chat.success") ?? "Conversación exportada",
      description: a.download,
    })
  }

  return (
    <div class="h-10 px-3 flex items-center justify-between border-b border-border-weaker-base/70 bg-bg-surface shrink-0 min-w-0 select-none">
      {/* Left: Session Title */}
      <div class="flex items-center gap-2 min-w-0 flex-1 pr-2">
        <Icon name="folder" class="size-3.5 text-text-tertiary shrink-0" />
        <h1 class="m-0 text-13-medium tracking-tight text-text-primary truncate max-w-[280px] sm:max-w-[420px]" title={title()}>
          {title()}
        </h1>
      </div>

      {/* Right: Quick Action Controls + Context Usage */}
      <div class="flex items-center gap-2 shrink-0">
        <SessionContextUsage placement="bottom" />
        <div class="flex items-center gap-0.5">
          {/* 1. Scope / Folder Menu */}
        <DropdownMenu
          gutter={4}
          placement="bottom-end"
          open={menu.open}
          onOpenChange={(open) => setMenu("open", open)}
        >
          <Tooltip value={language.t("session.header.openIn") ?? "Abrir carpeta"}>
            <DropdownMenu.Trigger
              as={IconButton}
              icon="folder"
              variant="ghost"
              size="large"
              class="!size-7 text-text-tertiary hover:text-text-primary"
              aria-label={language.t("session.header.openWorkdir")}
            />
          </Tooltip>
          <DropdownMenu.Portal>
            <DropdownMenu.Content class="min-w-[180px] p-1">
              <DropdownMenu.Group>
                <DropdownMenu.GroupLabel class="px-2 py-1 text-xs text-text-tertiary font-medium">
                  {language.t("session.header.openIn")}
                </DropdownMenu.GroupLabel>
                <DropdownMenu.RadioGroup
                  value={current().id}
                  onChange={(value) => {
                    if (!OPEN_APPS.includes(value as OpenApp)) return
                    selectApp(value as OpenApp)
                  }}
                >
                  <For each={options()}>
                    {(o) => (
                      <DropdownMenu.RadioItem
                        value={o.id}
                        disabled={opening()}
                        onSelect={() => {
                          setMenu("open", false)
                          openDir(o.id)
                        }}
                        class="flex items-center gap-2 px-2 py-1.5 text-xs rounded hover:bg-surface-base-hover cursor-pointer"
                      >
                        <div class="flex size-4 shrink-0 items-center justify-center [&_[data-component=app-icon]]:size-4">
                          <AppIcon id={o.icon} />
                        </div>
                        <DropdownMenu.ItemLabel class="truncate">{o.label}</DropdownMenu.ItemLabel>
                      </DropdownMenu.RadioItem>
                    )}
                  </For>
                </DropdownMenu.RadioGroup>
              </DropdownMenu.Group>
              <DropdownMenu.Separator class="my-1 border-b border-border-weaker-base" />
              <DropdownMenu.Item
                onSelect={() => {
                  setMenu("open", false)
                  copyPath()
                }}
                class="flex items-center gap-2 px-2 py-1.5 text-xs rounded hover:bg-surface-base-hover cursor-pointer"
              >
                <Icon name="copy" class="size-3.5 text-text-tertiary" />
                <DropdownMenu.ItemLabel>{language.t("session.header.open.copyPath")}</DropdownMenu.ItemLabel>
              </DropdownMenu.Item>
            </DropdownMenu.Content>
          </DropdownMenu.Portal>
        </DropdownMenu>

        {/* 2. Terminal Toggle */}
        <Tooltip value={language.t("command.terminal.toggle") ?? "Alternar Terminal"}>
          <IconButton
            icon="terminal"
            variant="ghost"
            size="large"
            onClick={toggleTerminal}
            class="!size-7 text-text-tertiary hover:text-text-primary"
            classList={{
              "bg-surface-base text-text-primary": view().terminal.opened(),
            }}
            aria-label={language.t("command.terminal.toggle") ?? "Terminal"}
          />
        </Tooltip>

        {/* 3. Export Conversation / Chat */}
        <Tooltip value={language.t("session.export.chat") ?? "Exportar conversación"}>
          <IconButton
            icon="download"
            variant="ghost"
            size="large"
            onClick={exportSession}
            class="!size-7 text-text-tertiary hover:text-text-primary"
            aria-label={language.t("session.export.chat") ?? "Exportar conversación"}
          />
        </Tooltip>

        {/* 3.1 Emergency stop: corta la auditoría en curso */}
        <Tooltip value={language.t("session.header.emergencyStop")}>
          <IconButton
            icon="stop"
            variant="ghost"
            size="large"
            onClick={emergencyStop}
            class="!size-7 text-severity-fg-critical hover:text-severity-fg-critical"
            aria-label={language.t("session.header.emergencyStop")}
          />
        </Tooltip>

        {/* 4. Target Web / Browser */}
        <Tooltip value="Alcance Web">
          <IconButton
            icon="globe"
            variant="ghost"
            size="large"
            onClick={() => platform.openLink("https://github.com/iwiels/argos-auditor")}
            class="!size-7 text-text-tertiary hover:text-text-primary"
            aria-label={language.t("session.header.web")}
          />
        </Tooltip>

        {/* 5. Right Side Panel Toggle (Hallazgos, Cumplimiento, Contexto) */}
        <Tooltip value={view().reviewPanel.opened() ? (language.t("session.panel.hide") ?? "Ocultar panel lateral") : (language.t("session.panel.show") ?? "Mostrar panel lateral")}>
          <IconButton
            icon={
              <svg
                viewBox="0 0 16 16"
                width="15"
                height="15"
                fill="none"
                stroke="currentColor"
                stroke-width="1.2"
                stroke-linecap="round"
                stroke-linejoin="round"
                aria-hidden="true"
              >
                <rect x="2" y="2.5" width="12" height="11" rx="1.5" />
                <line x1="10" y1="2.5" x2="10" y2="13.5" />
              </svg>
            }
            variant="ghost"
            size="large"
            onClick={() => view().reviewPanel.toggle()}
            class="!size-7 text-text-tertiary hover:text-text-primary"
            classList={{
              "bg-surface-base text-text-primary": view().reviewPanel.opened(),
            }}
            aria-label={view().reviewPanel.opened() ? (language.t("session.panel.hide") ?? "Ocultar panel lateral") : (language.t("session.panel.show") ?? "Mostrar panel lateral")}
          />
        </Tooltip>

        {/* 5. More Options */}
        <DropdownMenu
          gutter={4}
          placement="bottom-end"
          open={moreMenu.open}
          onOpenChange={(open) => setMoreMenu("open", open)}
        >
          <Tooltip value="Más opciones">
            <DropdownMenu.Trigger
              as={IconButton}
              icon="outline-dots"
              variant="ghost"
              size="large"
              class="!size-7 text-text-tertiary hover:text-text-primary"
              aria-label={language.t("session.header.options")}
            />
          </Tooltip>
          <DropdownMenu.Portal>
            <DropdownMenu.Content class="min-w-[160px] p-1">
              <DropdownMenu.Item
                onSelect={() => {
                  setMoreMenu("open", false)
                  copyPath()
                }}
                class="flex items-center gap-2 px-2 py-1.5 text-xs rounded hover:bg-surface-base-hover cursor-pointer"
              >
                <Icon name="copy" class="size-3.5 text-text-tertiary" />
                <span>Copiar ruta del alcance</span>
              </DropdownMenu.Item>
              <Show when={params.id}>
                <Show when={platform.platform === "desktop" && window.api?.authProfiles}>
                  <DropdownMenu.Item
                    onSelect={() => {
                      setMoreMenu("open", false)
                      const sessionID = params.id
                      if (!sessionID) return
                      void dialog.show(() => <AuthProfilesDialog sessionID={sessionID} />)
                    }}
                    class="flex items-center gap-2 px-2 py-1.5 text-xs rounded hover:bg-surface-base-hover cursor-pointer"
                  >
                    <Icon name="shield" class="size-3.5 text-text-tertiary" />
                    <span>{language.t("session.authProfiles.menu")}</span>
                  </DropdownMenu.Item>
                </Show>
                <DropdownMenu.Item
                  onSelect={() => {
                    setMoreMenu("open", false)
                    if (params.id) {
                      void navigator.clipboard.writeText(params.id).then(() =>
                        showToast({
                          icon: "circle-check",
                          title: "ID de sesión copiado",
                          description: params.id,
                        }),
                      )
                    }
                  }}
                  class="flex items-center gap-2 px-2 py-1.5 text-xs rounded hover:bg-surface-base-hover cursor-pointer"
                >
                  <Icon name="checklist" class="size-3.5 text-text-tertiary" />
                  <span>Copiar ID de sesión</span>
                </DropdownMenu.Item>
              </Show>
            </DropdownMenu.Content>
          </DropdownMenu.Portal>
        </DropdownMenu>
      </div>
    </div>
  </div>
  )
}




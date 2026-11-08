import {
  createEffect,
  createMemo,
  Show,
  untrack,
} from "solid-js"
import { createStore } from "solid-js/store"
import { useLocation, useNavigate } from "@solidjs/router"
import { IconButton } from "@argos/ui/icon-button"
import { Icon } from "@argos/ui/icon"
import { useTheme } from "@argos/ui/theme/context"

import { useLayout } from "@/context/layout"
import { usePlatform } from "@/context/platform"
import { useCommand } from "@/context/command"
import { useLanguage } from "@/context/language"
import { WindowsAppMenu } from "./windows-app-menu"
import { applyPath, backPath, forwardPath } from "./titlebar-history"

type TauriDesktopWindow = {
  startDragging?: () => Promise<void>
  toggleMaximize?: () => Promise<void>
}

type TauriThemeWindow = {
  setTheme?: (theme?: "light" | "dark" | null) => Promise<void>
}

type TauriApi = {
  window?: {
    getCurrentWindow?: () => TauriDesktopWindow
  }
  webviewWindow?: {
    getCurrentWebviewWindow?: () => TauriThemeWindow
  }
}

const tauriApi = () => (window as unknown as { __TAURI__?: TauriApi }).__TAURI__
const currentDesktopWindow = () => tauriApi()?.window?.getCurrentWindow?.()
const currentThemeWindow = () => tauriApi()?.webviewWindow?.getCurrentWebviewWindow?.()
const titlebarHeight = 36
const minTitlebarZoom = 0.25
const windowsControlsBaseWidth = 138 // 3 native Windows caption buttons at 46px each.

export type TitlebarUpdate = {
  version: () => string | undefined
  installing: () => boolean
  install: () => void
}

export function Titlebar(props: { update?: TitlebarUpdate }) {
  const platform = usePlatform()
  const command = useCommand()
  const language = useLanguage()
  const theme = useTheme()
  const layout = useLayout()
  const navigate = useNavigate()
  const location = useLocation()
  const mac = createMemo(() => platform.platform === "desktop" && platform.os === "macos")
  const windows = createMemo(() => platform.platform === "desktop" && platform.os === "windows")
  const electronWindows = createMemo(() => windows() && !tauriApi())
  const linux = createMemo(() => platform.platform === "desktop" && platform.os === "linux")
  const zoom = () => platform.webviewZoom?.() ?? 1
  const titlebarZoom = () => (windows() ? Math.max(zoom(), minTitlebarZoom) : zoom())
  const minHeight = () => {
    if (mac()) return `${titlebarHeight / zoom()}px`
    if (windows()) return `${titlebarHeight / Math.min(titlebarZoom(), 1)}px`
    return undefined
  }
  const windowsControlsWidth = () => `${windowsControlsBaseWidth / Math.max(titlebarZoom(), 1)}px`

  const [history, setHistory] = createStore({
    stack: [] as string[],
    index: 0,
    action: undefined as "back" | "forward" | undefined,
  })

  const path = () => `${location.pathname}${location.search}${location.hash}`

  createEffect(() => {
    const current = path()

    untrack(() => {
      const next = applyPath(history, current)
      if (next === history) return
      setHistory(next)
    })
  })

  const updateState = createMemo<TitlebarUpdatePillState>(() => {
    const installing = props.update?.installing() ?? false
    const version = props.update?.version()
    return {
      visible: version !== undefined || installing,
      installing,
      label: language.t("titlebar.update.label"),
      ariaLabel: language.t("toast.update.action.installRestart"),
      title: version ? language.t("titlebar.update.titleWithVersion", { version }) : undefined,
      onInstall: () => props.update?.install(),
    }
  })
  const v2RightState = createMemo<TitlebarV2RightState>(() => ({
    update: updateState(),
  }))

  const back = () => {
    const next = backPath(history)
    if (!next) return
    setHistory(next.state)
    navigate(next.to)
  }

  const forward = () => {
    const next = forwardPath(history)
    if (!next) return
    setHistory(next.state)
    navigate(next.to)
  }

  command.register(() => [
    {
      id: "common.goBack",
      title: language.t("common.goBack"),
      category: language.t("command.category.view"),
      keybind: "mod+[",
      onSelect: back,
    },
    {
      id: "common.goForward",
      title: language.t("common.goForward"),
      category: language.t("command.category.view"),
      keybind: "mod+]",
      onSelect: forward,
    },
  ])

  const getWin = () => {
    if (platform.platform !== "desktop") return
    return currentDesktopWindow()
  }

  createEffect(() => {
    if (platform.platform !== "desktop") return

    const scheme = theme.colorScheme()
    const value = scheme === "system" ? null : scheme

    const win = currentThemeWindow()
    if (!win?.setTheme) return

    void win.setTheme(value).catch(() => undefined)
  })

  const interactive = (target: EventTarget | null) => {
    if (!(target instanceof Element)) return false

    const selector =
      "button, a, input, textarea, select, option, [role='button'], [role='menuitem'], [contenteditable='true'], [contenteditable='']"

    return !!target.closest(selector)
  }

  const drag = (e: MouseEvent) => {
    if (platform.platform !== "desktop") return
    if (e.buttons !== 1) return
    if (interactive(e.target)) return

    const win = getWin()
    if (!win?.startDragging) return

    e.preventDefault()
    void win.startDragging().catch(() => undefined)
  }

  const maximize = (e: MouseEvent) => {
    if (platform.platform !== "desktop") return
    if (interactive(e.target)) return

    const win = getWin()
    if (!win?.toggleMaximize) return

    e.preventDefault()
    void win.toggleMaximize().catch(() => undefined)
  }

  return (
    <header
      class="shrink-0 relative flex flex-row h-9 bg-bg-base overflow-visible"
      style={{
        "min-height": minHeight(),
        "padding-left": mac() ? `${84 / zoom()}px` : 0,
        width: electronWindows() ? `env(titlebar-area-width, calc(100vw - ${windowsControlsWidth()}))` : undefined,
        "max-width": electronWindows()
          ? `env(titlebar-area-width, calc(100vw - ${windowsControlsWidth()}))`
          : undefined,
        "align-self": electronWindows() ? "flex-start" : undefined,
      }}
      data-window-drag-region
      onMouseDown={drag}
      onDblClick={maximize}
    >
      <div
        class="h-full flex-1 overflow-hidden flex flex-row items-center gap-0.5 pr-3 pt-2"
        classList={{
          "pl-2": mac(),
          "pl-3": !mac(),
        }}
      >
        <Show when={windows() || linux()}>
          <WindowsAppMenu command={command} platform={platform} />
        </Show>

        {/* Sidebar Toggle (Claude Code style) */}
        <IconButton
          variant="ghost-muted"
          size="large"
          onClick={() => layout.sidebar.toggle()}
          class="shrink-0"
          icon={
            <svg
              viewBox="0 0 16 16"
              width="16"
              height="16"
              fill="none"
              stroke="currentColor"
              stroke-width="1.2"
              stroke-linecap="round"
              stroke-linejoin="round"
              aria-hidden="true"
            >
              <rect x="2" y="2.5" width="12" height="11" rx="1.5" />
              <line x1="6" y1="2.5" x2="6" y2="13.5" />
            </svg>
          }
          aria-label={
            layout.sidebar.opened()
              ? language.t("sidebar.hide")
              : language.t("sidebar.show")
          }
          data-sidebar-toggle
          state={layout.sidebar.opened() ? "pressed" : undefined}
        />

        {/* Quick Search / Command Palette */}
        <IconButton
          variant="ghost-muted"
          size="large"
          onClick={() => command.show()}
          class="shrink-0"
          icon={<Icon name="magnifying-glass" />}
          aria-label={language.t("command.palette")}
        />

        {/* History Back */}
        <IconButton
          variant="ghost-muted"
          size="large"
          onClick={back}
          disabled={history.index <= 0}
          class="shrink-0"
          icon={<Icon name="arrow-left" />}
          aria-label={language.t("common.goBack")}
        />

        {/* History Forward */}
        <IconButton
          variant="ghost-muted"
          size="large"
          onClick={forward}
          disabled={history.index >= history.stack.length - 1}
          class="shrink-0"
          icon={<Icon name="arrow-right" />}
          aria-label={language.t("common.goForward")}
        />

        <div class="flex-1" />
        <TitlebarV2Right state={v2RightState()} />
      </div>
    </header>
  )
}

type TitlebarUpdatePillState = {
  visible: boolean
  installing: boolean
  label: string
  ariaLabel: string
  title?: string
  onInstall: () => void
}

type TitlebarV2RightState = {
  update: TitlebarUpdatePillState
}

function TitlebarV2Right(props: { state: TitlebarV2RightState }) {
  return (
    <div class="relative z-20 flex shrink-0 items-center justify-end gap-0 overflow-visible">
      <Show when={props.state.update.visible}>
        <TitlebarUpdateIconButton state={props.state.update} />
      </Show>
    </div>
  )
}

function TitlebarUpdateIconButton(props: { state: TitlebarUpdatePillState }) {
  const language = useLanguage()
  return (
    <div class="relative isolate mr-3 size-5 shrink-0">
      <button
        type="button"
        class="group absolute right-0 top-0 z-10 flex h-5 w-5 items-center justify-end overflow-hidden rounded-full bg-icon-icon-accent/20 text-icon-icon-accent transition-[width,background-color] duration-150 ease-out hover:z-30 hover:w-17 hover:bg-[color-mix(in_srgb,var(--icon-icon-accent)_20%,var(--bg-base))] focus-visible:z-30 focus-visible:w-17 focus-visible:bg-[color-mix(in_srgb,var(--icon-icon-accent)_20%,var(--bg-base))] focus-visible:outline-none disabled:opacity-60 motion-reduce:transition-none"
        onClick={props.state.onInstall}
        disabled={props.state.installing}
        aria-busy={props.state.installing}
        aria-label={props.state.ariaLabel}
      >
        <span class="shrink-0 ml-2 mr-px text-xs text-text-accent font-medium opacity-0 translate-x-2 motion-safe:transition-all duration-150 ease-out group-hover:opacity-100 group-hover:translate-x-0 group-focus-visible:opacity-100 group-focus-visible:translate-x-0 motion-reduce:translate-x-0">
          {language.t("titlebar.update.label")}
        </span>
        <span class="flex size-5 shrink-0 items-center justify-center">
          <Show
            when={!props.state.installing}
            fallback={<span data-slot="titlebar-update-loader" aria-hidden="true" />}
          >
            <Icon name="arrow-down" size="small" />
          </Show>
        </span>
      </button>
    </div>
  )
}

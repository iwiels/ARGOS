import { For, Show, createEffect, createMemo, createSignal, on, onCleanup, onMount } from "solid-js"
import { createStore } from "solid-js/store"
import { makeEventListener } from "@solid-primitives/event-listener"
import { Tabs } from "@argos/ui/tabs"
import { ResizeHandle } from "@argos/ui/resize-handle"
import { IconButton } from "@argos/ui/icon-button"
import { Icon } from "@argos/ui/icon"
import { Tooltip } from "@argos/ui/tooltip"
import { DragDropProvider, DragDropSensors, DragOverlay, SortableProvider, closestCenter } from "@thisbeyond/solid-dnd"
import type { DragEvent } from "@thisbeyond/solid-dnd"
import { ConstrainDragYAxis, getDraggableId } from "@/utils/solid-dnd"

import { SortableTerminalTab } from "@/components/session"
import { Terminal } from "@/components/terminal"
import { useLanguage } from "@/context/language"
import { useLayout } from "@/context/layout"
import { useTerminal } from "@/context/terminal"
import { terminalTabLabel } from "@/pages/session/terminal-label"
import { createSizing, focusTerminalById } from "@/pages/session/helpers"
import { onConnectFailure } from "@/pages/session/terminal-recovery"
import { getTerminalHandoff, setTerminalHandoff } from "@/pages/session/handoff"
import { useSessionLayout } from "@/pages/session/session-layout"

export function TerminalPanel() {
  const delays = [120, 240]
  const layout = useLayout()
  const terminal = useTerminal()
  const language = useLanguage()
  const { params, workspaceKey, view } = useSessionLayout()

  const opened = createMemo(() => view().terminal.opened())
  const size = createSizing()
  const height = createMemo(() => layout.terminal.height())
  const close = () => view().terminal.close()
  let root: HTMLDivElement | undefined

  const [store, setStore] = createStore({
    autoCreated: false,
    activeDraggable: undefined as string | undefined,
    recovered: {} as Record<string, boolean>,
    recoveryStreak: 0,
    view: typeof window === "undefined" ? 1000 : (window.visualViewport?.height ?? window.innerHeight),
  })

  const max = () => store.view * 0.6
  const pane = () => Math.min(height(), max())

  onMount(() => {
    if (typeof window === "undefined") return

    const sync = () => setStore("view", window.visualViewport?.height ?? window.innerHeight)
    const port = window.visualViewport

    sync()
    makeEventListener(window, "resize", sync)
    if (port) makeEventListener(port, "resize", sync)
  })

  createEffect(() => {
    if (!opened()) {
      setStore("autoCreated", false)
      return
    }

    if (!terminal.ready() || terminal.all().length !== 0 || store.autoCreated) return
    setStore("autoCreated", true)
    // Si la creación falla, liberar el pestillo: de lo contrario el panel se
    // queda con el estado vacío para siempre y ni siquiera reintenta al
    // reabrirlo.
    void Promise.resolve(terminal.new()).catch(() => setStore("autoCreated", false))
  })

  createEffect(
    on(
      () => terminal.all().length,
      (count, prevCount) => {
        if (prevCount === undefined || prevCount <= 0 || count !== 0) return
        if (!opened()) return
        close()
      },
    ),
  )

  const focus = (id: string) => {
    focusTerminalById(id)

    const frame = requestAnimationFrame(() => {
      if (!opened()) return
      if (terminal.active() !== id) return
      focusTerminalById(id)
    })

    const timers = delays.map((ms) =>
      window.setTimeout(() => {
        if (!opened()) return
        if (terminal.active() !== id) return
        focusTerminalById(id)
      }, ms),
    )

    return () => {
      cancelAnimationFrame(frame)
      for (const timer of timers) clearTimeout(timer)
    }
  }

  createEffect(
    on(
      () => [opened(), terminal.active()] as const,
      ([next, id]) => {
        if (!next || !id) return
        const stop = focus(id)
        onCleanup(stop)
      },
    ),
  )

  createEffect(() => {
    if (opened()) return
    const active = document.activeElement
    if (!(active instanceof HTMLElement)) return
    if (!root?.contains(active)) return
    active.blur()
  })

  createEffect(() => {
    const dir = params.dir
    if (!dir) return
    if (!terminal.ready()) return
    language.locale()

    setTerminalHandoff(
      workspaceKey(),
      terminal.all().map((pty) =>
        terminalTabLabel({
          title: pty.title,
          titleNumber: pty.titleNumber,
          t: language.t as (key: string, vars?: Record<string, string | number | boolean>) => string,
        }),
      ),
    )
  })

  const handoff = createMemo(() => {
    const dir = params.dir
    if (!dir) return []
    return getTerminalHandoff(workspaceKey()) ?? []
  })

  const all = terminal.all
  const ids = createMemo(() => all().map((pty) => pty.id))

  // Keep-mounted terminals: once a tab has been activated its Terminal stays
  // mounted (hidden via CSS when inactive), so switching tabs no longer pays
  // a WASM rebuild + WS reconnect + serialize round-trip per click.
  const [activatedIds, setActivatedIds] = createSignal<Set<string>>(new Set())
  createEffect(
    on(terminal.active, (id) => {
      if (!id) return
      setActivatedIds((prev) => (prev.has(id) ? prev : new Set(prev).add(id)))
    }),
  )
  const mountedTerminals = createMemo(() => {
    void activatedIds()
    return all().filter((pty) => activatedIds().has(pty.id))
  })

  const recoverTerminal = (id: string, gone: boolean, clone: (id: string) => Promise<void>) => {
    const outcome = onConnectFailure({ attempted: store.recovered, streak: store.recoveryStreak }, id, gone)
    if (outcome.action === "give-up") return
    if (outcome.action === "drop") {
      terminal.drop(id)
      return
    }
    setStore("recovered", outcome.next.attemptedID, true)
    setStore("recoveryStreak", outcome.next.streak)
    void clone(id)
  }

  const markTerminalConnected = (id: string, trim: (id: string) => void) => {
    // Una conexión exitosa demuestra que el fallo era transitorio: se limpia la
    // racha para que futuras caídas puedan volver a recuperarse.
    setStore("recoveryStreak", 0)
    setStore("recovered", id, false)
    trim(id)
  }

  const handleTerminalDragStart = (event: unknown) => {
    const id = getDraggableId(event)
    if (!id) return
    setStore("activeDraggable", id)
  }

  const handleTerminalDragOver = (event: DragEvent) => {
    const { draggable, droppable } = event
    if (!draggable || !droppable) return

    const terminals = terminal.all()
    const fromIndex = terminals.findIndex((t) => t.id === draggable.id.toString())
    const toIndex = terminals.findIndex((t) => t.id === droppable.id.toString())
    if (fromIndex !== -1 && toIndex !== -1 && fromIndex !== toIndex) {
      terminal.move(draggable.id.toString(), toIndex)
    }
  }

  const handleTerminalDragEnd = () => {
    setStore("activeDraggable", undefined)

    const activeId = terminal.active()
    if (!activeId) return
    requestAnimationFrame(() => {
      if (terminal.active() !== activeId) return
      focusTerminalById(activeId)
    })
  }

  return (
    <div
      ref={root}
      id="terminal-panel"
      role="region"
      aria-label={language.t("terminal.title")}
      aria-hidden={!opened()}
      inert={!opened()}
      class="relative w-full shrink-0 overflow-hidden rounded-xl border border-border-weaker-base/80 bg-bg-surface shadow-xs transition-[height] duration-200 ease-[cubic-bezier(0.22,1,0.36,1)]"
      classList={{
        "border-0 shadow-none !h-0 !p-0 !m-0 hidden": !opened(),
        "motion-reduce:transition-none": !size.active(),
      }}
      style={{ height: opened() ? `${pane()}px` : "0px" }}
    >
      <div
        class="absolute inset-x-0 top-0 flex flex-col"
        classList={{
          "pointer-events-none": !opened(),
        }}
        style={{ height: `${pane()}px` }}
      >
        <div class="hidden md:block" onPointerDown={() => size.start()}>
          <ResizeHandle
            direction="vertical"
            size={pane()}
            min={100}
            max={max()}
            collapseThreshold={50}
            onResize={(next) => {
              size.touch()
              layout.terminal.resize(next)
            }}
            onCollapse={close}
          />
        </div>
        <Show
          when={terminal.ready()}
          fallback={
            <div class="flex flex-col h-full pointer-events-none">
              <div class="h-9 flex items-center gap-2 px-3 border-b border-border-weaker-base overflow-hidden bg-bg-surface/90">
                <For each={handoff()}>
                  {(title) => (
                    <div class="px-2 py-1 rounded-md bg-bg-surface text-13-regular text-text-weak truncate max-w-40">
                      {title}
                    </div>
                  )}
                </For>
                <div class="flex-1" />
                <div class="text-xs text-text-weak pr-2">
                  {language.t("common.loading")}
                  {language.t("common.loading.ellipsis")}
                </div>
              </div>
              <div class="flex-1 flex items-center justify-center text-xs text-text-weak">{language.t("terminal.loading")}</div>
            </div>
          }
        >
          <DragDropProvider
            onDragStart={handleTerminalDragStart}
            onDragEnd={handleTerminalDragEnd}
            onDragOver={handleTerminalDragOver}
            collisionDetector={closestCenter}
          >
            <DragDropSensors />
            <ConstrainDragYAxis />
            <div class="flex flex-col h-full">
              <Tabs
                value={terminal.active()}
                onChange={(id) => terminal.open(id)}
                class="!h-auto !flex-none"
              >
                <Tabs.List class="h-9 border-b border-border-weaker-base/70 bg-bg-surface/90 px-3 flex items-center justify-between select-none">
                  {/* Left: Terminal Shell Indicator & Tabs */}
                  <div class="flex items-center gap-2 overflow-x-auto min-w-0">
                    <div class="flex items-center gap-1.5 px-2 py-0.5 rounded-md bg-surface-base border border-border-weaker-base text-text-secondary text-xs font-medium shrink-0">
                      <Icon name="terminal" class="size-3.5 text-text-tertiary" />
                      <span>{language.t("terminal.title")}</span>
                    </div>

                    <div class="h-3.5 w-px bg-border-weaker-base shrink-0 mx-0.5" />

                    <SortableProvider ids={ids()}>
                      <For each={all()}>{(pty) => <SortableTerminalTab terminal={pty} onClose={close} />}</For>
                    </SortableProvider>

                    <Tooltip value={language.t("command.terminal.new")} placement="bottom">
                      <IconButton
                        icon="plus-small"
                        variant="ghost"
                        size="small"
                        class="size-6 text-text-tertiary hover:text-text-primary hover:bg-surface-base-hover rounded"
                        onClick={() => void Promise.resolve(terminal.new()).catch(() => {})}
                        aria-label={language.t("command.terminal.new")}
                      />
                    </Tooltip>
                  </div>

                  {/* Right: Quick Terminal Actions */}
                  <div class="flex items-center gap-1 shrink-0 ml-auto pl-2">
                    <Tooltip value={language.t("common.close")} placement="bottom">
                      <IconButton
                        icon="xmark-small"
                        variant="ghost"
                        size="small"
                        class="size-6 text-text-tertiary hover:text-text-primary hover:bg-surface-base-hover rounded"
                        onClick={close}
                        aria-label={language.t("common.close")}
                      />
                    </Tooltip>
                  </div>
                </Tabs.List>
              </Tabs>
              <div class="flex-1 min-h-0 relative bg-bg-surface">
                <Show
                  when={all().length > 0 && terminal.active()}
                  fallback={
                    <div class="flex flex-col items-center justify-center h-full p-6 text-center select-none bg-bg-surface">
                      <div class="flex size-10 items-center justify-center rounded-xl bg-surface-base border border-border-weaker-base text-text-secondary mb-2.5 shadow-xs">
                        <Icon name="terminal" class="size-5" />
                      </div>
                      <p class="text-xs font-semibold text-text-primary mb-1">
                        {language.t("terminal.title")}
                      </p>
                      <button
                        type="button"
                        onClick={() => void Promise.resolve(terminal.new()).catch(() => {})}
                        class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface-base-hover border border-border-weak-base text-text-primary text-xs font-medium hover:bg-surface-raised-hover transition-colors cursor-pointer shadow-xs"
                      >
                        <Icon name="plus-small" class="size-4" />
                        <span>{language.t("command.terminal.new")}</span>
                      </button>
                    </div>
                  }
                >
                  <Show when={terminal.active()} keyed>
                    {(id) => {
                      void id
                      return (
                        <For each={mountedTerminals()}>
                          {(pty) => {
                            const ops = terminal.bind()
                            return (
                              <div
                                id={`terminal-wrapper-${pty.id}`}
                                class="absolute inset-0 p-2 bg-bg-surface"
                                classList={{ hidden: pty.id !== terminal.active() }}
                              >
                                <Terminal
                                  pty={pty}
                                  autoFocus={opened() && pty.id === terminal.active()}
                                  onConnect={() => markTerminalConnected(pty.id, ops.trim)}
                                  onCleanup={ops.update}
                                  onConnectError={(_err, info) => recoverTerminal(pty.id, info.gone, ops.clone)}
                                />
                              </div>
                            )
                          }}
                        </For>
                      )
                    }}
                  </Show>
                </Show>
              </div>
            </div>
            <DragOverlay>
              <Show when={store.activeDraggable} keyed>
                {(id) => (
                  <Show when={all().find((pty) => pty.id === id)}>
                    {(t) => (
                      <div class="relative p-1 h-9 flex items-center bg-bg-elevated text-13-regular rounded-md shadow-md">
                        {terminalTabLabel({
                          title: t().title,
                          titleNumber: t().titleNumber,
                          t: language.t as (key: string, vars?: Record<string, string | number | boolean>) => string,
                        })}
                      </div>
                    )}
                  </Show>
                )}
              </Show>
            </DragOverlay>
          </DragDropProvider>
        </Show>
      </div>
    </div>
  )
}



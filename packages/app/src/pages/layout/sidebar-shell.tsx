import { createMemo, createSignal, For, Show, type Accessor, type JSX } from "solid-js"
import { type LocalProject } from "@/context/layout"
import { Icon as IconV2 } from "@argos/ui/icon"
import { Button } from "@argos/ui/button"
import { IconButton } from "@argos/ui/icon-button"
import { DropdownMenu } from "@argos/ui/dropdown-menu"
import { ArgosIcon } from "@argos/ui/argos-logo"
import { A, useLocation } from "@solidjs/router"
import { useLanguage } from "@/context/language"
import { useServerSync } from "@/context/server-sync"
import { sessionTitle } from "@/utils/session-title"
import { sortedRootSessions } from "./helpers"
import { focusSessionTitleEditor, transitionSessionInteraction, type SessionInteraction } from "./sidebar-session-state"
import type { Session } from "@argos/sdk/client"

export const SidebarContent = (props: {
  mobile?: boolean
  opened: Accessor<boolean>
  projects: Accessor<LocalProject[]>
  openProjectLabel: JSX.Element
  onOpenProject: () => void
  onNewSession: (directory: string) => void
  navigateToProject: (directory: string) => void
  onEditProject?: (project: LocalProject) => void
  sectionsCollapsed?: Accessor<Record<string, boolean>>
  onToggleSection?: (key: string) => void
  onNavigateToSession?: (directory: string, id: string) => void
  onArchiveSession?: (session: Session) => void
  onRenameSession?: (session: Session, title: string) => void
  onPinSession?: (session: Session, pinned: boolean) => void
  onDeleteSession?: (session: Session) => void
  settingsLabel: Accessor<string>
  onOpenSettings: () => void
  helpLabel: Accessor<string>
  onOpenHelp: () => void
}): JSX.Element => {
  const location = useLocation()
  const language = useLanguage()
  const serverSync = useServerSync()
  const [sessionInteraction, setSessionInteraction] = createSignal<SessionInteraction>({ type: "idle" })
  const [draftTitle, setDraftTitle] = createSignal("")
  const [commitActiveRename, setCommitActiveRename] = createSignal<(() => void) | undefined>()
  const auditBase = createMemo(() => {
    const segments = location.pathname.split("/").filter(Boolean)
    if (segments[0] === "auditorias" && segments[1]) return "/auditorias/" + segments[1]
    return "/auditorias"
  })
  const auditOpen = createMemo(() => location.pathname.startsWith("/auditorias/"))
  const collapsed = (key: string) => props.sectionsCollapsed?.()?.[key] ?? false
  const toggle = (key: string) => props.onToggleSection?.(key)

  const sectionHeader = (key: string, label: string, action?: JSX.Element) => (
    <button
      type="button"
      class="group/section flex w-full items-center gap-1.5 px-1 pb-2 pt-1 text-left text-10-mono font-medium uppercase tracking-widest text-text-tertiary transition-colors hover:text-text-secondary"
      aria-expanded={!collapsed(key)}
      aria-label={`${label} — ${collapsed(key) ? language.t("sidebar.sections.expand") : language.t("sidebar.sections.collapse")}`}
      onClick={() => toggle(key)}
    >
      <IconV2
        name="chevron-right"
        class={`size-3 shrink-0 transition-transform duration-150 ${collapsed(key) ? "" : "rotate-90"}`}
      />
      <span class="truncate">{label}</span>
      {action}
    </button>
  )

  return (
    <nav
      data-component="app-sidebar"
      aria-label={language.t("sidebar.nav.projectsAndSessions")}
      aria-hidden={!props.opened()}
      inert={!props.opened()}
      class="flex flex-col overflow-hidden bg-bg-surface relative z-20 no-drag transition-[width,margin,opacity] duration-200 ease-[cubic-bezier(0.22,1,0.36,1)]"
      classList={{
        "w-[var(--w-sidebar)] m-2 mr-0 rounded-[4px] border border-border-weaker-base/80 shadow-xs opacity-100": props.opened(),
        "w-0 m-0 border-0 opacity-0 pointer-events-none": !props.opened(),
      }}
    >
      {/* Tactical Cockpit Dossier Header */}
      <div class="h-13 px-3 flex items-center border-b border-border-weaker-base/80 shrink-0 select-none bg-bg-surface">
        <a
          href="https://github.com/iwiels/argos-auditor"
          target="_blank"
          rel="noopener noreferrer"
          class="flex items-center gap-2.5 min-w-0 group/brand"
          title="Argos"
        >
          <ArgosIcon size={26} class="shrink-0 transition-transform duration-150 group-hover/brand:scale-105" />
          <span class="text-13-medium font-bold tracking-wider text-text-primary leading-none group-hover/brand:text-accent transition-colors font-display uppercase">
            Argos
          </span>
        </a>
      </div>

      <div class="flex flex-col gap-2 px-3 pt-3 pb-2">
        {/* audit-allow: el botón es rounded-sm (no pill); el rounded-full pertenece al span hijo que dibuja la barra de acento en hover, y border al borde del propio botón — la regla ve ambos en la misma ventana y los confunde */}
        <button
          type="button"
          onClick={props.onOpenProject}
          class="group relative flex w-full items-center justify-between rounded-sm border border-border-weaker-base bg-bg-elevated/70 px-3 py-2 text-text-primary transition-all hover:border-accent hover:bg-bg-elevated hover:shadow-xs cursor-pointer"
        >
          <span class="absolute inset-y-1 left-0 w-0.5 rounded-full bg-accent opacity-0 transition-opacity group-hover:opacity-100" />
          <span class="flex items-center gap-2">
            <IconV2 name="plus" class="size-3.5 text-accent transition-transform duration-150 group-hover:scale-110" />
            <span class="text-12-medium font-semibold text-text-primary">{language.t("audit.new")}</span>
          </span>
        </button>
      </div>

      <div class="flex flex-col gap-0.5 border-b border-border-weaker-base/60 px-3 pb-2 pt-0.5">
        <NavItem icon="shield" label={language.t("nav.audits")} href="/auditorias" />
      </div>

      <Show when={auditOpen()}>
        <div class="mt-2.5 flex flex-col px-3">
          {sectionHeader("audit", language.t("sidebar.audit.active"))}
          <Show when={!collapsed("audit")}>
            <div class="flex flex-col gap-0.5 pt-0.5 pl-2 border-l border-border-weaker-base/60 ml-2">
              <NavItem icon="chat" label={language.t("audit.nav.conversation")} href={auditBase()} exact />
              <NavItem icon="shield" label={language.t("audit.nav.findings")} href={auditBase() + "/hallazgos"} />
              <NavItem icon="checklist" label={language.t("audit.nav.report")} href={auditBase() + "/reporte"} />
              <NavItem icon="server" label={language.t("audit.nav.topology")} href={auditBase() + "/topologia"} />
            </div>
          </Show>
        </div>
      </Show>

      <div class="mt-2.5 flex min-h-0 flex-1 flex-col px-3">
        {sectionHeader("scopes", language.t("sidebar.scopes.active"))}

        <Show
          when={!collapsed("scopes")}
        >
          <div
            classList={{
                  "flex flex-col gap-0.5 overflow-y-auto no-scrollbar": true,
                  "flex-1 justify-center": props.projects().length === 0,
                }}
              >
                <Show
                  when={props.projects().length > 0}
                  fallback={
                    <div class="flex flex-col items-center gap-1.5 rounded-sm border border-dashed border-border-weaker-base px-3 py-6 text-center">
                      <span class="text-xs text-text-secondary">{language.t("sidebar.scopes.empty.title")}</span>
                      <span class="text-11-regular text-text-tertiary">
                        {language.t("sidebar.scopes.empty.description")}
                      </span>
                      <Button
                        variant="secondary"
                        size="small"
                        icon="plus"
                        onClick={props.onOpenProject}
                        class="mt-1"
                      >
                        {language.t("audit.new")}
                      </Button>
                    </div>
                  }
                >
                  <For each={props.projects()}>
                    {(project) => {
                      const name = project.worktree.split(/[\\/]/).pop() || language.t("sidebar.project.local")
                      const [store] = serverSync.child(project.worktree, { bootstrap: false })
                      const sessions = createMemo(() => sortedRootSessions(store, Date.now()))

                      return (
                        <div class="flex flex-col gap-0.5 mb-2.5">
                          {/* Workspace Header Row */}
                          <div class="group flex items-center justify-between px-2 py-1.5 rounded-sm border border-border-weaker-base/60 bg-bg-surface hover:bg-bg-elevated/80 hover:border-border-default transition-all mb-1">
                            <button
                              type="button"
                              class="flex items-center gap-1.5 min-w-0 text-left cursor-pointer focus:outline-none"
                              onClick={() => props.navigateToProject(project.worktree)}
                            >
                              <IconV2 name="folder-add-left" class="size-3.5 shrink-0 text-text-tertiary group-hover:text-accent transition-colors" />
                              <span class="truncate font-mono text-11-mono text-text-secondary group-hover:text-text-primary transition-colors font-medium">
                                {name}
                              </span>
                            </button>
                            <div
                              class="flex items-center gap-0.5 opacity-0 transition-opacity group-hover:opacity-100 focus-within:opacity-100"
                            >
                              <Show when={props.onEditProject}>
                                <IconButton
                                  icon={<IconV2 name="settings-gear" class="size-3.5" />}
                                  size="small"
                                  variant="ghost-muted"
                                  title={language.t("dialog.project.edit.title")}
                                  aria-label={language.t("dialog.project.edit.title")}
                                  onClick={(e) => {
                                    e.stopPropagation()
                                    props.onEditProject?.(project)
                                  }}
                                />
                              </Show>
                              <IconButton
                                icon={<IconV2 name="plus" class="size-3.5" />}
                                size="small"
                                variant="ghost-muted"
                                title={language.t("sidebar.project.newSessionScope")}
                                aria-label={language.t("sidebar.project.newSessionScope")}
                                onClick={(e) => {
                                  e.stopPropagation()
                                  props.onNewSession(project.worktree)
                                }}
                              />
                            </div>
                          </div>

                          {/* Sessions list under this workspace */}
                          <div class="flex flex-col gap-0.5 pl-2 border-l border-border-weaker-base/50 ml-2">
                            <For each={sessions().slice(0, 15)}>
                              {(session) => {
                                const isSessionActive = createMemo(() => location.pathname.includes(session.id))
                                const title = () => sessionTitle(session.title) || language.t("session.untitled")
                                const pinned = createMemo(() => !!(session.metadata as Record<string, unknown> | undefined)?.pinned)
                                const isRenaming = createMemo(() => {
                                  const current = sessionInteraction()
                                  return current.type === "rename" && current.sessionID === session.id
                                })
                                const menuOpen = createMemo(() => {
                                  const current = sessionInteraction()
                                  return current.type === "menu" && current.sessionID === session.id
                                })
                                const commitRename = () => {
                                  if (!isRenaming()) return
                                  const next = draftTitle().trim()
                                  setSessionInteraction((current) =>
                                    transitionSessionInteraction(current, { type: "finish-rename", sessionID: session.id }),
                                  )
                                  setCommitActiveRename(undefined)
                                  if (next && next !== title()) props.onRenameSession?.(session, next)
                                }
                                const cancelRename = () => {
                                  setSessionInteraction((current) =>
                                    transitionSessionInteraction(current, { type: "finish-rename", sessionID: session.id }),
                                  )
                                  setCommitActiveRename(undefined)
                                }
                                return (
                                  <div
                                    class={`group/session-row flex w-full items-center gap-2 rounded-sm pl-2 pr-1 text-xs transition-colors ${
                                      isSessionActive()
                                        ? "bg-bg-elevated text-text-primary font-medium border-l-2 border-accent shadow-xs"
                                        : "text-text-secondary hover:bg-bg-elevated/60 hover:text-text-primary"
                                    }`}
                                  >
                                    <Show
                                      when={!isRenaming()}
                                      fallback={
                                        <input
                                          type="text"
                                          value={draftTitle()}
                                          ref={(element) => queueMicrotask(() => focusSessionTitleEditor(element))}
                                          onInput={(e) => setDraftTitle((e.target as HTMLInputElement).value)}
                                          onBlur={commitRename}
                                          onKeyDown={(e) => {
                                            if (e.key === "Enter") {
                                              e.preventDefault()
                                              e.stopPropagation()
                                              commitRename()
                                            }
                                            if (e.key === "Escape") {
                                              e.preventDefault()
                                              e.stopPropagation()
                                              cancelRename()
                                            }
                                          }}
                                          class="min-w-0 flex-1 rounded-sm border border-accent bg-bg-surface px-1.5 py-0.5 text-12-regular text-text-primary outline-none"
                                          aria-label={language.t("sidebar.session.rename")}
                                        />
                                      }
                                    >
                                      <button
                                        type="button"
                                        onClick={() =>
                                          props.onNavigateToSession
                                            ? props.onNavigateToSession(project.worktree, session.id)
                                            : props.navigateToProject(project.worktree)
                                        }
                                        class="flex min-w-0 flex-1 items-center gap-2 py-1 text-left cursor-pointer"
                                      >
                                        <span
                                          class={`size-1.5 shrink-0 ${
                                            pinned()
                                              ? "bg-accent"
                                              : isSessionActive()
                                                ? "bg-accent"
                                                : "rounded-full bg-text-tertiary group-hover/session-row:bg-text-secondary"
                                          }`}
                                        />
                                        <span class="truncate text-12-regular leading-tight">{title()}</span>
                                      </button>
                                    </Show>
                                    <Show when={!isRenaming()}>
                                      <div
                                        class="shrink-0 opacity-0 transition-opacity group-hover/session-row:opacity-100 focus-within:opacity-100"
                                      >
                                        <DropdownMenu
                                          gutter={4}
                                          placement="bottom-end"
                                          modal={false}
                                          open={menuOpen()}
                                          onOpenChange={(open) => {
                                            if (open) {
                                              if (sessionInteraction().type === "rename") commitActiveRename()?.()
                                              setSessionInteraction((current) =>
                                                transitionSessionInteraction(current, { type: "open-menu", sessionID: session.id }),
                                              )
                                              return
                                            }
                                            setSessionInteraction((current) =>
                                              transitionSessionInteraction(current, { type: "close-menu", sessionID: session.id }),
                                            )
                                          }}
                                        >
                                          <DropdownMenu.Trigger
                                            as={IconButton}
                                            icon={<IconV2 name="dots" class="size-3.5" />}
                                            size="small"
                                            variant="ghost-muted"
                                            aria-label={language.t("sidebar.session.menu")}
                                          />
                                          <DropdownMenu.Portal>
                                            <DropdownMenu.Content class="min-w-[160px] p-1 shadow-popover">
                                              <DropdownMenu.Item
                                                onSelect={() => {
                                                  setDraftTitle(title())
                                                  setSessionInteraction((current) =>
                                                    transitionSessionInteraction(current, {
                                                      type: "start-rename",
                                                      sessionID: session.id,
                                                    }),
                                                  )
                                                  setCommitActiveRename(() => commitRename)
                                                }}
                                              >
                                                <DropdownMenu.ItemLabel>{language.t("sidebar.session.rename")}</DropdownMenu.ItemLabel>
                                              </DropdownMenu.Item>
                                              <DropdownMenu.Item onSelect={() => props.onPinSession?.(session, !pinned())}>
                                                <DropdownMenu.ItemLabel>
                                                  {pinned() ? language.t("sidebar.session.unpin") : language.t("sidebar.session.pin")}
                                                </DropdownMenu.ItemLabel>
                                              </DropdownMenu.Item>
                                              <DropdownMenu.Separator />
                                              <DropdownMenu.Item onSelect={() => props.onArchiveSession?.(session)}>
                                                <DropdownMenu.ItemLabel>{language.t("common.archive")}</DropdownMenu.ItemLabel>
                                              </DropdownMenu.Item>
                                              <DropdownMenu.Item
                                                class="text-severity-fg-high"
                                                onSelect={() => props.onDeleteSession?.(session)}
                                              >
                                                <DropdownMenu.ItemLabel>{language.t("common.delete")}</DropdownMenu.ItemLabel>
                                              </DropdownMenu.Item>
                                            </DropdownMenu.Content>
                                          </DropdownMenu.Portal>
                                        </DropdownMenu>
                                      </div>
                                    </Show>
                                  </div>
                                )
                              }}
                            </For>
                          </div>
                        </div>
                      )
                    }}
                  </For>
                </Show>
          </div>
        </Show>
      </div>

      <div class="mt-auto flex items-center gap-1 border-t border-border-weaker-base/80 bg-bg-surface p-2 shrink-0">
        <button
          type="button"
          class="flex min-w-0 flex-1 items-center gap-2 rounded-sm px-2 py-1 text-left text-text-secondary transition-colors hover:bg-bg-elevated hover:text-text-primary cursor-pointer"
          onClick={props.onOpenSettings}
          aria-label={props.settingsLabel()}
        >
          <IconV2 name="settings-gear" class="size-3.5 shrink-0 text-text-tertiary group-hover:text-text-primary" />
          <span class="truncate text-11-medium">{props.settingsLabel()}</span>
        </button>
        <button
          type="button"
          class="flex size-7 shrink-0 items-center justify-center rounded-sm text-text-secondary transition-colors hover:bg-bg-elevated hover:text-text-primary cursor-pointer"
          onClick={props.onOpenHelp}
          aria-label={props.helpLabel()}
          title={props.helpLabel()}
        >
          <IconV2 name="help" class="size-3.5 text-text-tertiary hover:text-text-primary" />
        </button>
      </div>
    </nav>
  )
}

export function relativeTime(at: number, language: ReturnType<typeof useLanguage>) {
  const diff = Math.max(0, Date.now() - at)
  const minutes = Math.floor(diff / 60_000)
  if (minutes < 1) return language.t("common.time.justNow")
  if (minutes < 60) return language.t("common.time.minutesAgo.short", { count: minutes })
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return language.t("common.time.hoursAgo.short", { count: hours })
  return language.t("common.time.daysAgo.short", { count: Math.floor(hours / 24) })
}

function NavItem(props: { icon: string; label: string; href: string; exact?: boolean }) {
  const location = useLocation()
  const isActive = createMemo(() => {
    if (props.exact) return location.pathname === props.href
    if (props.href === "/auditorias") return location.pathname.startsWith("/auditorias")
    return location.pathname.includes(props.href)
  })
  return (
    <A
      href={props.href}
      end={props.exact}
      class={`group relative flex items-center justify-between rounded-sm px-2.5 py-1.5 transition-colors cursor-pointer ${
        isActive()
          ? "border-l-2 border-accent bg-bg-elevated pl-2 text-text-primary font-medium shadow-xs"
          : "text-text-secondary hover:bg-bg-elevated/50 hover:text-text-primary"
      }`}
      aria-current={isActive() ? "page" : undefined}
    >
      <div class="flex items-center gap-2 min-w-0">
        <IconV2
          name={props.icon}
          class={`size-3.5 shrink-0 transition-colors ${isActive() ? "text-accent" : "text-text-tertiary group-hover:text-text-primary"}`}
        />
        <span class="text-12-medium truncate">{props.label}</span>
      </div>
      <Show when={isActive()}>
        <span class="size-1.5 rounded-full bg-accent shrink-0" aria-hidden="true" />
      </Show>
    </A>
  )
}

import { createMemo, For, Show } from "solid-js"
import { useServerSync } from "@/context/server-sync"
import { useLayout } from "@/context/layout"
import { useServer } from "@/context/server"
import { useLanguage } from "@/context/language"
import { usePlatform } from "@/context/platform"
import { useDialog } from "@argos/ui/context/dialog"
import { Button } from "@argos/ui/button"
import { PageHeader } from "@/components/audit-ui"
import { PixelIcon } from "@argos/ui/pixel-icon"
import { ArgosIcon } from "@argos/ui/argos-logo"
import { sortedRootSessions } from "@/pages/layout/helpers"
import { homeRuntimeMessage } from "./runtime-label"
import type { Session } from "@argos/sdk/client"

export function ScopeBriefing(props: { worktree?: string }) {
  const sync = useServerSync()
  const layout = useLayout()
  const server = useServer()
  const language = useLanguage()
  const dialog = useDialog()
  const platform = usePlatform()
  const runtimeLabel = createMemo(() => {
    const message = homeRuntimeMessage(server.current, platform, server.isLocal())
    return language.t(message.key, message.params)
  })

  const activeWorktree = createMemo(() => {
    if (props.worktree) return props.worktree
    const projects = layout.projects.list()
    return projects[0]?.worktree
  })

  const currentProject = createMemo(() => {
    const wt = activeWorktree()
    if (!wt) return undefined
    return layout.projects.list().find((p) => p.worktree === wt)
  })

  const scope = createMemo(() => currentProject()?.scope)
  const hasScope = createMemo(() => {
    const s = scope()
    if (!s) return false
    return (
      (s.domains && s.domains.length > 0) ||
      (s.cidrs && s.cidrs.length > 0)
    )
  })
  const displayDomains = createMemo(() => (scope()?.domains ?? []).slice(0, 3))

  const openScopeDialog = () => {
    const proj = currentProject()
    const conn = server.current
    if (proj && conn) {
      void import("@/components/dialog-edit-project").then((x) => {
        void dialog.show(() => <x.DialogEditProject server={conn} project={proj} />)
      })
    }
  }

  // Load sessions for active worktree
  const sessions = createMemo<Session[]>(() => {
    const wt = activeWorktree()
    if (!wt) return []
    try {
      const [store] = sync.child(wt, { bootstrap: false })
      return sortedRootSessions(store, Date.now())
    } catch {
      return []
    }
  })

  const lastActivity = createMemo(() => {
    const sList = sessions()
    if (sList.length === 0) return language.t("home.activity.none")
    const latest = sList[0]
    const ts = latest.time.updated ?? latest.time.created
    const seconds = Math.round((ts - Date.now()) / 1000)
    const relative = new Intl.RelativeTimeFormat(language.intl(), { numeric: "auto" })
    if (Math.abs(seconds) < 60) return relative.format(0, "second")
    const minutes = Math.round(seconds / 60)
    if (Math.abs(minutes) < 60) return relative.format(minutes, "minute")
    const hours = Math.round(minutes / 60)
    if (Math.abs(hours) < 24) return relative.format(hours, "hour")
    return relative.format(Math.round(hours / 24), "day")
  })

  return (
    <div class="flex flex-col items-center w-full max-w-2xl gap-5">
      <PageHeader
        variant="dossier"
        size="hero"
        title={
          <span class="inline-flex items-center gap-3">
            <span class="flex size-10 shrink-0 items-center justify-center rounded-lg border border-accent/25 bg-bg-surface shadow-xs">
              <ArgosIcon size={26} />
            </span>
            <span>{language.t("home.title")}</span>
          </span>
        }
      />

      <section
        aria-label={language.t("home.title")}
        class="w-full flex flex-col gap-4 rounded-[4px] border border-border-weaker-base bg-bg-surface p-5 shadow-xs"
      >
          <div class="grid grid-cols-2 gap-4 border-b border-border-weaker-base pb-4">
            <div class="flex flex-col gap-1.5">
              <span class="text-[10px] text-text-tertiary font-medium uppercase tracking-widest">{language.t("nav.audits")}</span>
              <span class="font-display text-2xl font-bold tabular-nums leading-none text-text-primary">{sessions().length}</span>
            </div>
            <div class="flex flex-col gap-1.5">
              <span class="text-[10px] text-text-tertiary font-medium uppercase tracking-widest">{language.t("home.recent.title")}</span>
              <span class="text-xs font-medium font-mono tabular-nums text-text-secondary">{lastActivity()}</span>
            </div>
          </div>

          <div class="flex flex-col gap-3">
            <Show
              when={hasScope()}
              fallback={
                <div class="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-3 p-3 rounded-[4px] border border-state-fg-warning/25 bg-state-fg-warning/5">
                  <div class="flex items-center gap-2.5">
                    <PixelIcon name="radar" size={18} class="text-state-fg-warning shrink-0" />
                    <div class="flex flex-col gap-0.5">
                      <span class="text-xs font-mono font-bold text-text-primary uppercase tracking-wide">
                        {language.t("home.scope.unconfigured.title")}
                      </span>
                      <span class="text-[11px] text-text-secondary leading-tight">
                        {language.t("home.scope.unconfigured.desc")}
                      </span>
                    </div>
                  </div>
                  <Show
                    when={currentProject()}
                    fallback={
                      <span class="shrink-0 font-mono text-[10px] text-text-tertiary">
                        {language.t("home.scope.projectRequired")}
                      </span>
                    }
                  >
                    <Button
                      type="button"
                      variant="contrast"
                      size="small"
                      onClick={openScopeDialog}
                      class="shrink-0 font-mono text-xs"
                    >
                      {language.t("home.scope.configure")}
                    </Button>
                  </Show>
                </div>
              }
            >
              <div class="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-3 p-3 rounded-[4px] border border-accent/25 bg-accent/5">
                <div class="flex flex-col gap-1.5 min-w-0">
                  <div class="flex items-center gap-2 flex-wrap">
                    <span class="size-2 rounded-full bg-severity-fg-low shrink-0" />
                    <span class="text-xs font-mono font-bold text-text-primary uppercase tracking-wide">
                      {language.t("home.scope.configured.title")}
                    </span>
                    <span class="px-1.5 py-0.2 rounded-[3px] text-[10px] font-mono uppercase bg-accent/15 text-accent border border-accent/25 font-semibold">
                      {scope()?.modality ?? "black-box"}
                    </span>
                    <span class="text-[10px] font-mono text-text-tertiary">
                      {scope()?.maxRPS ? `${scope()?.maxRPS} RPS` : "∞ RPS"}
                    </span>
                    <Show when={scope()?.safeMode}>
                      <span class="text-[10px] font-mono text-severity-fg-low bg-severity-bg-low/10 px-1 rounded">
                        {language.t("dialog.project.edit.traffic.safeModeBadge")}
                      </span>
                    </Show>
                  </div>
                  <div class="flex flex-wrap items-center gap-1.5">
                    <For each={displayDomains()}>
                      {(dom) => (
                        <span class="px-1.5 py-0.5 rounded-[3px] bg-bg-surface-elevated border border-border-base text-text-secondary font-mono text-[10px]">
                          {dom}
                        </span>
                      )}
                    </For>
                    <Show when={(scope()?.domains?.length ?? 0) > 3}>
                      <span class="text-[10px] font-mono text-text-tertiary">
                        {language.t("home.scope.more", { count: (scope()?.domains?.length ?? 0) - 3 })}
                      </span>
                    </Show>
                    <Show when={(scope()?.cidrs?.length ?? 0) > 0}>
                      <span class="px-1.5 py-0.5 rounded-[3px] bg-bg-surface-elevated border border-border-base text-accent font-mono text-[10px]">
                        {scope()?.cidrs?.[0]}
                      </span>
                    </Show>
                  </div>
                </div>
                <Button
                  type="button"
                  variant="secondary"
                  size="small"
                  onClick={openScopeDialog}
                  class="shrink-0 font-mono text-xs"
                >
                  {language.t("home.scope.edit")}
                </Button>
              </div>
            </Show>

            <div class="flex items-center gap-2 border-t border-border-weaker-base pt-3 text-xs">
              <div class="flex items-center gap-2 min-w-0">
                <span class="text-[10px] font-mono text-text-tertiary uppercase tracking-wider">
                  {language.t("home.runtime.title")}
                </span>
                <span class="text-text-tertiary">/</span>
                <div data-testid="runtime-status" class="flex items-center gap-1.5">
                  <span class="size-1.5 rounded-full bg-text-tertiary shrink-0" />
                  <span class="font-mono text-11-medium text-text-secondary">{runtimeLabel()}</span>
                </div>
              </div>
            </div>
          </div>
      </section>
    </div>
  )
}

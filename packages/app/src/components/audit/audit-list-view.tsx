import { For, Show, createMemo } from "solid-js"
import { DateTime } from "luxon"
import { useNavigate } from "@solidjs/router"
import { Icon } from "@argos/ui/icon"
import { PixelIcon } from "@argos/ui/pixel-icon"
import { DossierFolder, DossierFolderSheet, FolderTab } from "@argos/ui/folder-tab"
import type { Session } from "@argos/sdk/v2"
import { useLanguage } from "@/context/language"
import { groupSessions, type AuditSession, type HomeSessionRecord } from "@/components/home"
import { EmptyState, PageHeader } from "@/components/audit-ui"

function auditTypeBadge(session: AuditSession): { label: string } | undefined {
  const rawType = (session.type || "").toLowerCase()

  if (rawType === "web") {
    return { label: "WEB" }
  }
  if (rawType === "red" || rawType === "net" || rawType === "network") {
    return { label: "NET" }
  }
  if (rawType === "recon" || rawType === "osint") {
    return { label: "OSINT" }
  }
  if (rawType === "full" || rawType === "360") {
    return { label: "360°" }
  }
  return undefined
}

export function displayTitle(record: HomeSessionRecord, t?: (key: string, params?: Record<string, string>) => string | undefined) {
  const title = record.session.title
  if (!title || title.startsWith("New session -")) {
    const defaultTarget = t?.("home.audit.defaultTarget") ?? "Objetivo Local"
    const target = record.projectName || record.session.directory.split(/[\\/]/).pop() || defaultTarget
    return t?.("home.audit.titleTemplate", { target }) ?? `Auditoría de seguridad sobre ${target}`
  }
  return title
}

// Skeleton nombrado para listas de auditorías (extiende el patrón de
// SessionSkeleton en sidebar-items: Spinner = acción en curso, skeleton =
// lista cargando; nunca `animate-spin` sobre Icon para este estado).
function AuditRowSkeleton(props: { count?: number }) {
  const rows = () => Array.from({ length: props.count ?? 3 }, (_, index) => index)
  return (
    <div class="flex flex-col gap-4" role="status" aria-busy="true">
      <For each={rows()}>
        {(i) => (
          <div
            class="h-16 rounded-lg bg-bg-base opacity-60 animate-pulse"
            style={{ "animation-delay": `${i * 150}ms` }}
          />
        )}
      </For>
    </div>
  )
}

export function AuditListView(props: {
  records: HomeSessionRecord[]
  isLoading: boolean
  search: string
  onSearch: (value: string) => void
  onOpenSession: (session: Session) => void
}) {
  const language = useLanguage()
  const navigate = useNavigate()

  const filteredRecords = createMemo(() => {
    const q = props.search.trim().toLowerCase()
    if (!q) return props.records
    return props.records.filter((r) => {
      const target = r.projectName || r.session.directory.split(/[\\/]/).pop() || ""
      const title = r.session.title || ""
      return (
        target.toLowerCase().includes(q) ||
        title.toLowerCase().includes(q) ||
        r.session.directory.toLowerCase().includes(q)
      )
    })
  })

  const groups = createMemo(() => groupSessions(filteredRecords(), language.t))

  return (
    <div class="mx-auto w-full h-full max-w-275 px-8 py-8 flex flex-col min-h-0 min-w-0 gap-6">
      <DossierFolder class="flex flex-col items-start">
        <div class="translate-y-[1px] z-10">
          <FolderTab
            label="AUDITORÍAS"
            color="var(--accent)"
            textColor="var(--black-900)"
            active={true}
          />
        </div>
        <DossierFolderSheet class="w-full rounded-[4px] rounded-tl-none border border-border-weaker-base bg-bg-surface px-5 py-4 shadow-[0_-1px_8px_rgba(0,0,0,0.25)]">
          <PageHeader
            variant="dossier"
            title={<>{language.t("audit.list.title")}</>}
            description={language.t("audit.list.subtitle")}
          />
        </DossierFolderSheet>
      </DossierFolder>

      <div class="relative">
        <label class="relative z-10 flex h-11 w-full items-center gap-2 rounded-[4px] border border-border-weaker-base bg-bg-base py-1 pl-3 pr-3 transition-all duration-120 ease-in-out focus-within:border-accent focus-within:bg-bg-base focus-within:shadow-[0_0_0_2px_var(--border-interactive-base)]">
          <input
            value={props.search}
            onInput={(e) => props.onSearch((e.target as HTMLInputElement).value)}
            class="min-w-0 flex-1 border-0 bg-transparent text-text-primary outline-0 font-mono text-sm placeholder:text-text-tertiary"
            placeholder={language.t("audit.list.searchPlaceholder")}
            aria-label={language.t("audit.list.searchAriaLabel")}
          />
        </label>
      </div>

      <Show
        when={!props.isLoading}
        fallback={
          <div class="flex flex-col gap-4">
            <div class="flex items-center gap-2 px-1 mb-2 border-b border-border-weaker-base pb-2">
              <span class="text-xs font-mono uppercase tracking-wider text-text-tertiary">{language.t("audit.list.loading")}</span>
            </div>
            <AuditRowSkeleton count={3} />
          </div>
        }
      >
        <div class="scroll-view mt-2 min-h-0 flex-1">
          <div class="scroll-view__viewport" tabindex="0" role="region" aria-label={language.t("audit.list.scrollableContent")}>
            <Show
              when={groups().length > 0}
              fallback={
                <EmptyState
                  class="h-full"
                  icon={<PixelIcon name="folder" size={28} />}
                  title={language.t("audit.list.empty")}
                  description={language.t("audit.list.empty.description")}
                >
                  <button
                    type="button"
                    onClick={() => navigate("/")}
                    class="mt-1 inline-flex cursor-pointer items-center gap-1.5 rounded-md border border-border-weaker-base bg-bg-surface px-2.5 py-1 text-xs font-medium text-accent transition-colors hover:border-border-strong hover:bg-surface-base-hover"
                  >
                    <Icon name="plus" class="size-3.5" />
                    {language.t("audit.new")}
                  </button>
                </EmptyState>
              }
            >
              <div class="flex flex-col gap-8">
                <For each={groups()}>
                  {(group) => (
                    <div class="flex min-w-0 flex-col gap-2">
                      <div class="flex items-center gap-2 px-1 mb-2 border-b border-border-weaker-base pb-2">
                        <span class="font-display text-sm font-bold uppercase tracking-wider text-text-tertiary">{group.title}</span>
                        <span class="text-xs font-mono text-text-tertiary">({group.sessions.length})</span>
                      </div>
                      <For each={group.sessions}>
                        {(record) => {
                          const badge = auditTypeBadge(record.session)
                          const target = record.projectName || record.session.directory.split(/[\\/]/).pop() || "unknown"
                          const titleText = displayTitle(record, language.t)
                          const dateLocale = language.locale() === "br" ? "pt" : language.locale()
                          return (
                            <button
                              type="button"
                              onClick={() => props.onOpenSession(record.session)}
                              class="group w-full flex items-center gap-4 rounded-[4px] border border-border-weaker-base bg-bg-surface p-3 transition-all duration-150 hover:border-accent hover:bg-bg-elevated text-left cursor-pointer"
                            >
                              <div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-[4px] border border-border-weaker-base bg-bg-base text-text-secondary transition-colors group-hover:text-accent">
                                <PixelIcon name="folder" size={28} />
                              </div>
                              <Show when={badge}>
                                {(b) => (
                                  <div class="shrink-0 flex h-6 px-2 items-center justify-center rounded-[3px] border border-border-weaker-base bg-bg-elevated font-mono text-10-mono text-text-secondary">
                                    {b().label}
                                  </div>
                                )}
                              </Show>
                              <div class="flex min-w-0 flex-1 flex-col gap-0.5">
                                <span class="font-display text-lg font-bold uppercase leading-none text-text-primary truncate">{target}</span>
                                <span class="text-xs text-text-secondary truncate">{titleText}</span>
                              </div>
                              <span class="shrink-0 text-xs font-mono text-text-tertiary tabular-nums">
                                {DateTime.fromMillis(record.session.time.updated ?? record.session.time.created).toRelative({ locale: dateLocale })}
                              </span>
                            </button>
                          )
                        }}
                      </For>
                    </div>
                  )}
                </For>
              </div>
            </Show>
          </div>
        </div>
      </Show>
    </div>
  )
}

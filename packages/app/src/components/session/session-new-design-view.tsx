import type { JSX } from "solid-js"
import { createMemo, For, Show } from "solid-js"
import { ScopeBriefing } from "@/components/home/scope-briefing"
import { Icon } from "@argos/ui/icon"
import { DropdownMenu } from "@argos/ui/dropdown-menu"
import { useLayout } from "@/context/layout"
import { useNavigate } from "@solidjs/router"
import { base64Encode } from "@/core/encode"
import { useDirectoryPicker } from "@/components/directory-picker"
import { useServer } from "@/context/server"
import { useLanguage } from "@/context/language"

export function NewSessionDesignView(props: {
  children?: JSX.Element
  worktree?: string
}) {
  const layout = useLayout()
  const navigate = useNavigate()
  const server = useServer()
  const pickDirectory = useDirectoryPicker()
  const language = useLanguage()

  const projects = () => layout.projects.list()
  const currentWorktree = () => props.worktree || projects()[0]?.worktree

  const openNewDirectory = () => {
    const conn = server.current
    if (!conn) return
    pickDirectory({
      server: conn,
      title: language.t("command.project.open"),
      onSelect: (result) => {
        const dir = Array.isArray(result) ? result[0] : result
        if (dir) {
          layout.projects.open(dir)
          server.projects.touch(dir)
          navigate(`/${base64Encode(dir)}/session`)
        }
      },
    })
  }

  return (
    <div
      data-component="session-new-design"
      data-scroll-main
      class="relative size-full overflow-y-auto bg-bg-base flex flex-col justify-between items-center px-4 sm:px-6 py-6 sm:py-8"
    >
      {/* Center Scope Briefing Hub */}
      <div class="flex-1 flex flex-col items-center justify-center w-full max-w-2xl my-auto py-4">
        <ScopeBriefing worktree={currentWorktree()} />
      </div>

      {/* Bottom Dock Container: Context Pills + Prompt Composer */}
      <div class="w-full max-w-2xl flex flex-col gap-2 shrink-0 mt-2">
        {/* Context Pills above prompt */}
        <div class="flex items-center gap-1.5 px-1">
          {/* Interactive Workspace / Scope Selector Pill */}
          <DropdownMenu gutter={4} placement="top-start">
            <DropdownMenu.Trigger
              as="button"
              type="button"
              class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md bg-bg-surface border border-border-weaker-base text-[11px] font-mono text-text-secondary hover:text-text-primary hover:border-border-strong transition-colors cursor-pointer max-w-[240px]"
            >
              <Icon name="folder" size="small" class="text-text-tertiary shrink-0" />
              <span class="truncate">
                {currentWorktree() ? (currentWorktree()?.split(/[\\/]/).pop() || currentWorktree()) : "Abrir carpeta..."}
              </span>
              <Icon name="chevron-down" size="small" class="size-2.5 text-text-tertiary ml-0.5" />
            </DropdownMenu.Trigger>
            <DropdownMenu.Portal>
              <DropdownMenu.Content class="min-w-[180px] p-1 shadow-popover">
                <div class="px-2 py-1 text-[10px] font-mono uppercase tracking-wider text-text-tertiary">
                  Reciente
                </div>
                <For each={projects()}>
                  {(project) => {
                    const name = project.worktree.split(/[\\/]/).pop() || project.worktree
                    const isSelected = createMemo(() => project.worktree === currentWorktree())
                    return (
                      <DropdownMenu.Item
                        onSelect={() => navigate(`/${base64Encode(project.worktree)}/session`)}
                        class="flex items-center justify-between text-xs py-1.5"
                      >
                        <DropdownMenu.ItemLabel class="truncate font-mono">
                          {name}
                        </DropdownMenu.ItemLabel>
                        <Show when={isSelected()}>
                          <Icon name="check" size="small" class="size-3 text-accent" />
                        </Show>
                      </DropdownMenu.Item>
                    )
                  }}
                </For>
                <DropdownMenu.Separator />
                <DropdownMenu.Item onSelect={openNewDirectory} class="text-xs py-1.5">
                  <DropdownMenu.ItemLabel class="font-mono">
                    Abrir carpeta...
                  </DropdownMenu.ItemLabel>
                </DropdownMenu.Item>
              </DropdownMenu.Content>
            </DropdownMenu.Portal>
          </DropdownMenu>
        </div>

        {/* Main Prompt Input Box */}
        <div class="w-full rounded-xl bg-bg-surface border border-border-weaker-base shadow-sm">
          {props.children}
        </div>
      </div>
    </div>
  )
}

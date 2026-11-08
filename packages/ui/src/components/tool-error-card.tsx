import { type ComponentProps, createMemo, Show, splitProps, For } from "solid-js"
import { createStore } from "solid-js/store"
import { Collapsible } from "./collapsible"
import { Icon } from "./icon"
import { useI18n } from "../context/i18n"
import { useCopyToClipboard } from "../hooks/use-copy-to-clipboard"

export interface ToolErrorCardProps extends ComponentProps<"div"> {
  tool: string
  error: string
  title?: string
  defaultOpen?: boolean
  open?: boolean
  onOpenChange?: (open: boolean) => void
  subtitle?: string
  href?: string
}

export function ToolErrorCard(props: ToolErrorCardProps) {
  const i18n = useI18n()
  const [state, setState] = createStore({
    open: props.defaultOpen ?? false,
  })
  const open = () => props.open ?? state.open
  const { copied, copy: copyToClipboard } = useCopyToClipboard()
  const [split, rest] = splitProps(props, [
    "tool",
    "error",
    "title",
    "defaultOpen",
    "open",
    "onOpenChange",
    "subtitle",
    "href",
    "class"
  ])
  const setOpen = (value: boolean) => {
    if (props.open === undefined) setState("open", value)
    props.onOpenChange?.(value)
  }
  const name = createMemo(() => {
    if (split.title) return split.title
    const map: Record<string, string> = {
      read: "ui.tool.read",
      list: "ui.tool.list",
      glob: "ui.tool.glob",
      grep: "ui.tool.grep",
      task: "ui.tool.task",
      webfetch: "ui.tool.webfetch",
      websearch: "ui.tool.websearch",
      bash: "ui.tool.shell",
      apply_patch: "ui.tool.patch",
      question: "ui.tool.questions",
    }
    const key = map[split.tool]
    if (!key) return split.tool
    if (!key.includes(".")) return key
    return i18n.t(key)
  })

  const getToolIcon = (tool: string): string => {
    if (tool === "bash") return "console"
    if (tool === "read" || tool === "list" || tool === "glob" || tool === "grep") return "folder"
    if (tool === "websearch" || tool === "webfetch") return "globe"
    if (tool === "apply_patch") return "edit"
    return "mcp"
  }

  const cleaned = createMemo(() => split.error.replace(/^Error:\s*/, "").trim())
  const tail = createMemo(() => {
    const value = cleaned()
    const prefix = `${split.tool} `
    if (value.startsWith(prefix)) return value.slice(prefix.length)
    return value
  })

  const errorLines = createMemo(() => {
    const parts = tail().split("\n").filter((l) => l.trim().length > 0)
    return parts.length > 0 ? parts : [tail()]
  })

  const copy = (text: string) => copyToClipboard(text)

  return (
    <div class={`flex flex-col w-full max-w-full ${split.class || ""}`} {...rest}>
      <Collapsible
        class="group flex flex-col overflow-hidden rounded-lg border border-border-weaker-base bg-bg-surface transition-colors hover:border-border-strong focus-within:border-border-strong"
        open={open()} 
        onOpenChange={setOpen}
      >
        <Collapsible.Trigger 
          as="button" 
          class="w-full flex items-center justify-between px-3 py-0 text-left outline-none transition-colors hover:bg-surface-base-hover h-9 min-h-[36px] max-h-[36px]"
        >
          <div class="flex items-center gap-2 min-w-0 flex-1 overflow-hidden flex-nowrap">
            <Icon name={getToolIcon(split.tool) as any} class="shrink-0 size-4" />
            
            <span class="shrink-0 font-medium text-13 text-text-primary">{name()}</span>
            
            <Show when={errorLines().length > 1}>
              <span class="shrink-0 text-12 text-text-secondary font-mono">
                ×{errorLines().length}
              </span>
            </Show>
            
            <Show when={split.subtitle}>
              <span class="min-w-0 truncate text-13 font-normal text-text-secondary" title={split.subtitle}>
                {split.subtitle}
              </span>
            </Show>
          </div>
          
          <Collapsible.Arrow class="shrink-0 ml-auto" />
        </Collapsible.Trigger>

        <Collapsible.Content>
          <div class="flex flex-col w-full border-t border-border-weaker-base/60 bg-bg-surface p-2.5 gap-2">
            <For each={errorLines()}>
              {(line) => (
                <div class="flex items-center justify-between gap-3 p-2.5 rounded-md border border-state-border-danger/40 bg-state-bg-danger/10 text-12-regular text-text-primary">
                  <div class="flex items-center gap-2.5 min-w-0">
                    <Icon name="circle-ban-sign" class="size-4 shrink-0 text-state-fg-danger" />
                    <div class="flex flex-col gap-0.5 min-w-0">
                      <span class="text-12-medium leading-tight text-state-fg-danger">
                        {i18n.t("ui.toolErrorCard.failed") || "Falló"}
                      </span>
                      <span class="break-words text-left text-11-mono text-text-secondary line-clamp-3">
                        {line}
                      </span>
                    </div>
                  </div>

                  <button
                    onClick={(e) => {
                      e.stopPropagation()
                      void copy(line)
                    }}
                    class="flex items-center gap-1.5 p-1.5 rounded-md hover:bg-bg-surface text-text-tertiary hover:text-text-primary shrink-0 transition-colors"
                    title={copied() ? i18n.t("ui.message.copied") || "Copied" : i18n.t("ui.message.copy") || "Copy"}
                  >
                    <Show when={copied()}>
                      <span class="text-10-regular font-medium text-text-tertiary">
                        {i18n.t("ui.message.copied") || "Copied"}
                      </span>
                    </Show>
                    <Icon name={copied() ? "check" : "copy"} class="size-3.5 shrink-0" />
                  </button>
                </div>
              )}
            </For>
          </div>
        </Collapsible.Content>
      </Collapsible>
    </div>
  )
}


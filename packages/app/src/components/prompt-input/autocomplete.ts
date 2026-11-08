import { useFilteredList } from "@argos/ui/hooks"
import { createEffect, createMemo } from "solid-js"
import { useCommand } from "@/context/command"
import { useFile } from "@/context/file"
import { DEFAULT_PROMPT, usePrompt, type ContentPart, type ImageAttachmentPart } from "@/context/prompt"
import { useSync } from "@/context/sync"
import type { AtOption, SlashCommand } from "./slash-popover"

type PromptAutocompleteInput = {
  recent: () => string[]
  imageAttachments: () => ImageAttachmentPart[]
  closePopover: () => void
  addPart: (part: ContentPart) => boolean
  clearEditor: () => void
  setEditorText: (text: string) => void
  focusEditorEnd: () => void
}

/**
 * Wires the `@` mention and `/` slash-command popovers: source lists,
 * filtering/keyboard navigation (via `useFilteredList`), and selection
 * handling. Kept independent of the editor DOM mechanics in `editor-sync.ts`
 * — it only reaches into the editor through the callbacks passed in, so
 * neither module needs to import the other.
 */
export function createPromptAutocomplete(input: PromptAutocompleteInput) {
  const sync = useSync()
  const files = useFile()
  const command = useCommand()
  const prompt = usePrompt()

  let slashPopoverRef: HTMLDivElement | undefined
  const setSlashPopoverRef = (el: HTMLDivElement) => {
    slashPopoverRef = el
  }

  const agentList = createMemo(() =>
    sync.data.agent
      .filter((agent) => !agent.hidden && agent.mode !== "primary")
      .map((agent): AtOption => ({ type: "agent", name: agent.name, display: agent.name })),
  )

  const handleAtSelect = (option: AtOption | undefined) => {
    if (!option) return
    if (option.type === "agent") {
      input.addPart({ type: "agent", name: option.name, content: "@" + option.name, start: 0, end: 0 })
    } else {
      input.addPart({ type: "file", path: option.path, content: "@" + option.path, start: 0, end: 0 })
    }
  }

  const atKey = (x: AtOption | undefined) => {
    if (!x) return ""
    return x.type === "agent" ? `agent:${x.name}` : `file:${x.path}`
  }

  const {
    flat: atFlat,
    active: atActive,
    setActive: setAtActive,
    onInput: atOnInput,
    onKeyDown: atOnKeyDown,
  } = useFilteredList<AtOption>({
    items: async (query) => {
      const agents = agentList()
      const open = input.recent()
      const seen = new Set(open)
      const pinned: AtOption[] = open.map((path) => ({ type: "file", path, display: path, recent: true }))
      if (!query.trim()) return [...agents, ...pinned]
      const paths = await files.searchFilesAndDirectories(query)
      const fileOptions: AtOption[] = paths
        .filter((path) => !seen.has(path))
        .map((path) => ({ type: "file", path, display: path }))
      return [...agents, ...pinned, ...fileOptions]
    },
    key: atKey,
    filterKeys: ["display"],
    groupBy: (item) => {
      if (item.type === "agent") return "agent"
      if (item.recent) return "recent"
      return "file"
    },
    sortGroupsBy: (a, b) => {
      const rank = (category: string) => {
        if (category === "agent") return 0
        if (category === "recent") return 1
        return 2
      }
      return rank(a.category) - rank(b.category)
    },
    onSelect: handleAtSelect,
  })

  const slashCommands = createMemo<SlashCommand[]>(() => {
    const builtin = command.options
      .filter((opt) => !opt.disabled && !opt.id.startsWith("suggested.") && opt.slash)
      .map((opt) => ({
        id: opt.id,
        trigger: opt.slash!,
        title: opt.title,
        description: opt.description,
        type: "builtin" as const,
      }))

    const custom = sync.data.command.map((cmd) => ({
      id: `custom.${cmd.name}`,
      trigger: cmd.name,
      title: cmd.name,
      description: cmd.description,
      type: "custom" as const,
      source: cmd.source,
    }))

    return [...custom, ...builtin]
  })

  const handleSlashSelect = (cmd: SlashCommand | undefined) => {
    if (!cmd) return
    input.closePopover()
    const images = input.imageAttachments()

    if (cmd.type === "custom") {
      const text = `/${cmd.trigger} `
      input.setEditorText(text)
      prompt.set([{ type: "text", content: text, start: 0, end: text.length }, ...images], text.length)
      input.focusEditorEnd()
      return
    }

    input.clearEditor()
    prompt.set([...DEFAULT_PROMPT, ...images], 0)
    command.trigger(cmd.id, "slash")
  }

  const {
    flat: slashFlat,
    active: slashActive,
    setActive: setSlashActive,
    onInput: slashOnInput,
    onKeyDown: slashOnKeyDown,
  } = useFilteredList<SlashCommand>({
    items: slashCommands,
    key: (x) => x?.id,
    filterKeys: ["trigger", "title"],
    onSelect: handleSlashSelect,
  })

  // Auto-scroll active command into view when navigating with keyboard
  createEffect(() => {
    const activeId = slashActive()
    if (!activeId || !slashPopoverRef) return

    requestAnimationFrame(() => {
      const element = slashPopoverRef?.querySelector(`[data-slash-id="${activeId}"]`)
      element?.scrollIntoView({ block: "nearest", behavior: "smooth" })
    })
  })

  return {
    atFlat,
    atActive,
    setAtActive,
    atOnInput,
    atOnKeyDown,
    atKey,
    handleAtSelect,
    slashFlat,
    slashActive,
    setSlashActive,
    slashOnInput,
    slashOnKeyDown,
    handleSlashSelect,
    setSlashPopoverRef,
  }
}

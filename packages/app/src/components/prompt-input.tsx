import { useSpring } from "@argos/ui/motion-spring"
import {
  createEffect,
  on,
  Component,
  Show,
  onCleanup,
  createMemo,
  createSignal,
  createResource,
} from "solid-js"
import { createStore } from "solid-js/store"
import { useLocal } from "@/context/local"
import { selectionFromLines, type SelectedLineRange, useFile } from "@/context/file"
import { ContentPart, DEFAULT_PROMPT, Prompt, usePrompt, ImageAttachmentPart } from "@/context/prompt"
import { useLayout } from "@/context/layout"
import { useNavigate } from "@solidjs/router"
import { useSDK } from "@/context/sdk"
import { useServer } from "@/context/server"
import { useSync } from "@/context/sync"
import { useComments } from "@/context/comments"
import { DockShellForm } from "@argos/ui/dock-surface"
import { Icon } from "@argos/ui/icon"
import { Tooltip } from "@argos/ui/tooltip"
import { IconButton } from "@argos/ui/icon-button"
import { Select } from "@argos/ui/select"
import { useDialog } from "@argos/ui/context/dialog"
import { useProviders } from "@/hooks/use-providers"
import { useCommand } from "@/context/command"
import { Persist, persisted } from "@/utils/persist"
import { usePermission } from "@/context/permission"
import { useLanguage } from "@/context/language"
import { usePlatform } from "@/context/platform"
import { useSettings } from "@/context/settings"
import { serverAttachmentFile } from "./prompt-input/server-attachment"
import { useSessionLayout } from "@/pages/session/session-layout"
import { createSessionTabs } from "@/pages/session/helpers"
import { createTextFragment, getCursorPosition, setCursorPosition, setRangeEdge } from "./prompt-input/editor-dom"
import { createPromptEditor } from "./prompt-input/editor-sync"
import { createPromptAutocomplete } from "./prompt-input/autocomplete"
import { createPromptAttachments } from "./prompt-input/attachments"
import { ACCEPTED_FILE_TYPES, pickAttachmentFiles } from "./prompt-input/files"
import {
  canNavigateHistoryAtCursor,
  navigatePromptHistory,
  prependHistoryEntry,
  type PromptHistoryComment,
  type PromptHistoryEntry,
  type PromptHistoryStoredEntry,
  promptLength,
} from "./prompt-input/history"
import { createPromptSubmit, sendFollowupDraft, type FollowupDraft } from "./prompt-input/submit"
import { buildReportPrompt } from "@/components/session/report-request"
import { useAuditFindings } from "@/hooks/use-audit-findings"
import { useServerSync } from "@/context/server-sync"
import { createReportMetaStore } from "@/utils/report-meta"
import { PromptPopover } from "./prompt-input/slash-popover"
import { PromptContextItems } from "./prompt-input/context-items"
import { PromptImageAttachments } from "./prompt-input/image-attachments"
import { PromptDragOverlay } from "./prompt-input/drag-overlay"
import { promptPlaceholder } from "./prompt-input/placeholder"
import {
  ComposerAgentControl,
  ComposerModelControl,
  ComposerPickerTrigger,
  type ComposerAgentControlState,
  type ComposerModelControlState,
  type ComposerPickerTriggerState,
} from "./prompt-input/composer-controls"
import { useDirectoryPicker } from "./directory-picker"
import { showToast } from "@/utils/toast"
import { ImagePreview } from "@argos/ui/image-preview"
import { useQueries } from "@tanstack/solid-query"
import { useQueryOptions } from "@/context/server-sync"
import { pathKey } from "@/utils/path-key"
import { base64Encode } from "@/core/encode"

interface PromptInputProps {
  class?: string
  variant?: "dock" | "new-session"
  ref?: (el: HTMLDivElement) => void
  newSessionWorktree?: string
  onNewSessionWorktreeReset?: () => void
  edit?: { id: string; prompt: Prompt; context: FollowupDraft["context"] }
  onEditLoaded?: () => void
  shouldQueue?: () => boolean
  onQueue?: (draft: FollowupDraft) => void
  onAbort?: () => void
  onSubmit?: () => void
}

const EXAMPLES = [
  "prompt.example.1",
  "prompt.example.2",
  "prompt.example.3",
  "prompt.example.4",
  "prompt.example.5",
  "prompt.example.6",
  "prompt.example.7",
  "prompt.example.8",
  "prompt.example.9",
  "prompt.example.10",
  "prompt.example.11",
  "prompt.example.12",
  "prompt.example.13",
  "prompt.example.14",
  "prompt.example.15",
  "prompt.example.16",
  "prompt.example.17",
  "prompt.example.18",
  "prompt.example.19",
  "prompt.example.20",
  "prompt.example.21",
  "prompt.example.22",
  "prompt.example.23",
  "prompt.example.24",
  "prompt.example.25",
] as const

export const PromptInput: Component<PromptInputProps> = (props) => {
  const sdk = useSDK()
  const navigate = useNavigate()
  const queryOptions = useQueryOptions()

  const sync = useSync()
  const local = useLocal()
  const files = useFile()
  const prompt = usePrompt()
  const layout = useLayout()
  const server = useServer()
  const comments = useComments()
  const dialog = useDialog()
  const providers = useProviders()
  const command = useCommand()
  const permission = usePermission()
  const language = useLanguage()
  const platform = usePlatform()
  const pickDirectory = useDirectoryPicker()
  const settings = useSettings()
  const { params, tabs, view } = useSessionLayout()
  let editorRef!: HTMLDivElement
  let fileInputRef: HTMLInputElement | undefined
  let scrollRef!: HTMLDivElement

  const {
    clearEditor,
    setEditorText,
    focusEditorEnd,
    createPill,
    parseFromDOM,
    reconcile,
    markMirrored,
    queueScroll,
    restoreFocus,
  } = createPromptEditor({
    editor: () => editorRef,
    scroll: () => scrollRef,
  })

  const activeFileTab = createSessionTabs({
    tabs,
    pathFromTab: files.pathFromTab,
    normalizeTab: (tab) => (tab.startsWith("file://") ? files.tab(tab) : tab),
  }).activeFileTab

  const commentInReview = (path: string) => {
    const sessionID = params.id
    if (!sessionID) return false

    const diffs = sync.data.session_diff[sessionID]
    if (!diffs) return false
    return diffs.some((diff) => diff.file === path)
  }

  const openComment = (item: { path: string; commentID?: string; commentOrigin?: "review" | "file" }) => {
    if (!item.commentID) return

    const focus = { file: item.path, id: item.commentID }
    comments.setActive(focus)

    const queueCommentFocus = (attempts = 6) => {
      const schedule = (left: number) => {
        requestAnimationFrame(() => {
          comments.setFocus({ ...focus })
          if (left <= 0) return
          requestAnimationFrame(() => {
            const current = comments.focus()
            if (!current) return
            if (current.file !== focus.file || current.id !== focus.id) return
            schedule(left - 1)
          })
        })
      }

      schedule(attempts)
    }

    const wantsReview = item.commentOrigin === "review" || (item.commentOrigin !== "file" && commentInReview(item.path))
    if (wantsReview) {
      if (!view().reviewPanel.opened()) view().reviewPanel.open()
      layout.fileTree.setTab("changes")
      tabs().setActive("review")
      queueCommentFocus()
      return
    }

    if (!view().reviewPanel.opened()) view().reviewPanel.open()
    layout.fileTree.setTab("all")
    const tab = files.tab(item.path)
    void tabs().open(tab)
    tabs().setActive(tab)
    void Promise.resolve(files.load(item.path)).finally(() => queueCommentFocus())
  }

  const recent = createMemo(() => {
    const all = tabs().all()
    const active = activeFileTab()
    const order = active ? [active, ...all.filter((x) => x !== active)] : all
    const seen = new Set<string>()
    const paths: string[] = []

    for (const tab of order) {
      const path = files.pathFromTab(tab)
      if (!path) continue
      if (seen.has(path)) continue
      seen.add(path)
      paths.push(path)
    }

    return paths
  })
  const info = createMemo(() => (params.id ? sync.session.get(params.id) : undefined))
  const working = createMemo(() => sync.data.session_working(params.id ?? ""))

  /**
   * Acción "Generar informe": vive en la barra del compositor porque es una
   * acción sobre la conversación entera, no sobre un hallazgo suelto. Redactar
   * el informe completo es caro, así que se dispara explícitamente y no en cada
   * turno. Sólo aparece cuando la sesión ya tiene hallazgos que reportar.
   */
  const serverSync = useServerSync()
  const { findings: reportFindings, counts: reportCounts } = useAuditFindings({
    dir: () => sdk.directory,
    sessionID: () => params.id,
  })
  const { meta: reportMeta } = createReportMetaStore(sdk.directory || "local")
  const [reportSending, setReportSending] = createSignal(false)

  const canGenerateReport = createMemo(() => !!params.id && reportFindings().length > 0)

  const generateReportRequest = async () => {
    const sessionID = params.id
    const model = local.model.current()
    const agent = local.agent.current()
    if (!sessionID || !model || !agent) return

    const missing = [
      reportMeta.leadAuditor.trim() ? undefined : language.t("report.meta.leadAuditor"),
      reportMeta.legalName.trim() ? undefined : language.t("report.meta.legalName"),
      reportMeta.classification.trim() ? undefined : language.t("report.meta.classification"),
    ].filter((label): label is string => !!label)

    const text = buildReportPrompt(
      {
        missing,
        findingsCount: reportFindings().length,
        criticalCount: reportCounts().critical,
        highCount: reportCounts().high,
      },
      language.t,
    )

    setReportSending(true)
    try {
      await sendFollowupDraft({
        client: sdk.client,
        sync,
        serverSync,
        draft: {
          sessionID,
          sessionDirectory: sdk.directory,
          prompt: [{ type: "text", content: text, start: 0, end: text.length }],
          context: [],
          agent: agent.name,
          model: { modelID: model.id, providerID: model.provider.id },
          variant: local.model.variant.current(),
        },
        optimisticBusy: true,
      })
      showToast({
        title: language.t("report.generate.running"),
        description: language.t("report.generate.hint"),
      })
    } catch {
      showToast({ title: language.t("report.generate.failed") })
    } finally {
      setReportSending(false)
    }
  }
  const imageAttachments = createMemo(() =>
    prompt.current().filter((part): part is ImageAttachmentPart => part.type === "image"),
  )

  const [store, setStore] = createStore<{
    popover: "at" | "slash" | null
    historyIndex: number
    savedPrompt: PromptHistoryEntry | null
    placeholder: number
    draggingType: "image" | "@mention" | null
    mode: "normal" | "shell"
    applyingHistory: boolean
    variantOpen: boolean
  }>({
    popover: null,
    historyIndex: -1,
    savedPrompt: null as PromptHistoryEntry | null,
    placeholder: Math.floor(Math.random() * EXAMPLES.length),
    draggingType: null,
    mode: "normal",
    applyingHistory: false,
    variantOpen: false,
  })

  const buttonsSpring = useSpring(() => (store.mode === "normal" ? 1 : 0), { visualDuration: 0.2, bounce: 0 })
  const motion = (value: number) => ({
    opacity: value,
    transform: `scale(${0.98 + value * 0.02})`,
    filter: `blur(${(1 - value) * 2}px)`,
    "pointer-events": value > 0.5 ? ("auto" as const) : ("none" as const),
  })
  const buttons = createMemo(() => motion(buttonsSpring()))
  const control = createMemo(() => ({ height: "28px", ...buttons() }))

  const commentCount = createMemo(() => {
    if (store.mode === "shell") return 0
    return prompt.context.items().filter((item) => !!item.comment?.trim()).length
  })
  const blank = createMemo(() => {
    const text = prompt
      .current()
      .map((part) => ("content" in part ? part.content : ""))
      .join("")
    return text.trim().length === 0 && imageAttachments().length === 0 && commentCount() === 0
  })
  const stopping = createMemo(() => working() && blank())
  const tip = () => {
    if (stopping()) {
      return (
        <div class="flex items-center gap-2">
          <span>{language.t("prompt.action.stop")}</span>
          <span class="text-icon-base text-12-medium text-xs!">{language.t("common.key.esc")}</span>
        </div>
      )
    }

    return (
      <div class="flex items-center gap-2">
        <span>{language.t("prompt.action.send")}</span>
        <Icon name="enter" size="normal" class="size-4 text-icon-base" />
      </div>
    )
  }

  const contextItems = createMemo(() => {
    const items = prompt.context.items()
    if (store.mode !== "shell") return items
    return items.filter((item) => !item.comment?.trim())
  })

  const hasUserPrompt = createMemo(() => {
    const sessionID = params.id
    if (!sessionID) return false
    const messages = sync.data.message[sessionID]
    if (!messages) return false
    return messages.some((m) => m.role === "user")
  })

  const [history, setHistory] = persisted(
    Persist.global("prompt-history", ["prompt-history.v1"]),
    createStore<{
      entries: PromptHistoryStoredEntry[]
    }>({
      entries: [],
    }),
  )
  const [shellHistory, setShellHistory] = persisted(
    Persist.global("prompt-history-shell", ["prompt-history-shell.v1"]),
    createStore<{
      entries: PromptHistoryStoredEntry[]
    }>({
      entries: [],
    }),
  )

  const suggest = createMemo(() => !hasUserPrompt())

  const placeholder = createMemo(() =>
    promptPlaceholder({
      mode: store.mode,
      commentCount: commentCount(),
      example: suggest() ? (store.mode === "shell" ? "git status" : language.t(EXAMPLES[store.placeholder])) : "",
      suggest: suggest(),
      t: (key, params) => language.t(key as Parameters<typeof language.t>[0], params as never),
    }),
  )

  const historyComments = () => {
    const byID = new Map(comments.all().map((item) => [`${item.file}\n${item.id}`, item] as const))
    return prompt.context.items().flatMap((item) => {
      if (item.type !== "file") return []
      const comment = item.comment?.trim()
      if (!comment) return []

      const selection = item.commentID ? byID.get(`${item.path}\n${item.commentID}`)?.selection : undefined
      const nextSelection =
        selection ??
        (item.selection
          ? ({
              start: item.selection.startLine,
              end: item.selection.endLine,
            } satisfies SelectedLineRange)
          : undefined)
      if (!nextSelection) return []

      return [
        {
          id: item.commentID ?? item.key,
          path: item.path,
          selection: { ...nextSelection },
          comment,
          time: item.commentID ? (byID.get(`${item.path}\n${item.commentID}`)?.time ?? Date.now()) : Date.now(),
          origin: item.commentOrigin,
          preview: item.preview,
        } satisfies PromptHistoryComment,
      ]
    })
  }

  const applyHistoryComments = (items: PromptHistoryComment[]) => {
    comments.replace(
      items.map((item) => ({
        id: item.id,
        file: item.path,
        selection: { ...item.selection },
        comment: item.comment,
        time: item.time,
      })),
    )
    prompt.context.replaceComments(
      items.map((item) => ({
        type: "file" as const,
        path: item.path,
        selection: selectionFromLines(item.selection),
        comment: item.comment,
        commentID: item.id,
        commentOrigin: item.origin,
        preview: item.preview,
      })),
    )
  }

  const applyHistoryPrompt = (entry: PromptHistoryEntry, position: "start" | "end") => {
    const p = entry.prompt
    const length = position === "start" ? 0 : promptLength(p)
    setStore("applyingHistory", true)
    applyHistoryComments(entry.comments)
    prompt.set(p, length)
    requestAnimationFrame(() => {
      editorRef.focus()
      setCursorPosition(editorRef, length)
      setStore("applyingHistory", false)
      queueScroll()
    })
  }

  const getCaretState = () => {
    const selection = window.getSelection()
    const textLength = promptLength(prompt.current())
    if (!selection || selection.rangeCount === 0) {
      return { collapsed: false, cursorPosition: 0, textLength }
    }
    const anchorNode = selection.anchorNode
    if (!anchorNode || !editorRef.contains(anchorNode)) {
      return { collapsed: false, cursorPosition: 0, textLength }
    }
    return {
      collapsed: selection.isCollapsed,
      cursorPosition: getCursorPosition(editorRef),
      textLength,
    }
  }

  const escBlur = () => platform.platform === "desktop" && platform.os === "macos"

  const pick = () => {
    if (server.isLocal()) {
      pickAttachmentFiles({
        picker: platform.openAttachmentPickerDialog,
        directory: () => sdk.directory,
        fallback: () => fileInputRef?.click(),
        onFile: addAttachment,
        onError: (error) =>
          showToast({
            title: language.t("common.requestFailed"),
            description: error instanceof Error ? error.message : String(error),
          }),
      })
      return
    }
    void import("@/components/dialog-select-file").then((module) =>
      dialog.show(() => (
        <module.DialogSelectFile
          mode="files"
          onSelectFile={(path) => {
            void sdk.client.v2.fs
              .read({ path })
              .then((response) => response.data?.data)
              .then((data) => data && addAttachments([serverAttachmentFile(path, data)]))
          }}
        />
      )),
    )
  }

  const setMode = (mode: "normal" | "shell") => {
    setStore("mode", mode)
    setStore("popover", null)
    requestAnimationFrame(() => editorRef?.focus())
  }

  const shellModeKey = "mod+shift+x"
  const normalModeKey = "mod+shift+e"

  command.register("prompt-input", () => [
    {
      id: "file.attach",
      title: language.t("prompt.action.attachFile"),
      category: language.t("command.category.file"),
      keybind: "mod+u",
      disabled: store.mode !== "normal",
      onSelect: pick,
    },
    {
      id: "prompt.mode.shell",
      title: language.t("command.prompt.mode.shell"),
      category: language.t("command.category.session"),
      keybind: shellModeKey,
      disabled: store.mode === "shell",
      onSelect: () => setMode("shell"),
    },
    {
      id: "prompt.mode.normal",
      title: language.t("command.prompt.mode.normal"),
      category: language.t("command.category.session"),
      keybind: normalModeKey,
      disabled: store.mode === "normal",
      onSelect: () => setMode("normal"),
    },
  ])

  const closePopover = () => setStore("popover", null)

  const resetHistoryNavigation = (force = false) => {
    if (!force && (store.historyIndex < 0 || store.applyingHistory)) return
    setStore("historyIndex", -1)
    setStore("savedPrompt", null)
  }

  createEffect(() => {
    params.id
    if (params.id) return
    if (!suggest()) return
    const interval = setInterval(() => {
      setStore("placeholder", (prev) => (prev + 1) % EXAMPLES.length)
    }, 6500)
    onCleanup(() => clearInterval(interval))
  })

  const [composing, setComposing] = createSignal(false)
  const isImeComposing = (event: KeyboardEvent) => event.isComposing || composing() || event.keyCode === 229

  const handleBlur = () => {
    closePopover()
    setComposing(false)
  }

  const handleCompositionStart = () => {
    setComposing(true)
  }

  const handleCompositionEnd = () => {
    setComposing(false)
    requestAnimationFrame(() => {
      if (composing()) return
      reconcile(prompt.current().filter((part) => part.type !== "image"))
    })
  }

  const agentNames = createMemo(() => local.agent.list().map((agent) => agent.name))

  const autocomplete = createPromptAutocomplete({
    recent,
    imageAttachments,
    closePopover,
    addPart: (part) => addPart(part),
    clearEditor,
    setEditorText,
    focusEditorEnd,
  })

  const selectPopoverActive = () => {
    if (store.popover === "at") {
      const items = autocomplete.atFlat()
      if (items.length === 0) return
      const active = autocomplete.atActive()
      const item = items.find((entry) => autocomplete.atKey(entry) === active) ?? items[0]
      autocomplete.handleAtSelect(item)
      return
    }

    if (store.popover === "slash") {
      const items = autocomplete.slashFlat()
      if (items.length === 0) return
      const active = autocomplete.slashActive()
      const item = items.find((entry) => entry.id === active) ?? items[0]
      autocomplete.handleSlashSelect(item)
    }
  }

  createEffect(
    on(
      () => prompt.current(),
      (parts) => {
        if (composing()) return
        reconcile(parts.filter((part) => part.type !== "image"))
      },
    ),
  )

  const handleInput = () => {
    const rawParts = parseFromDOM()
    const images = imageAttachments()
    const cursorPosition = getCursorPosition(editorRef)
    const rawText =
      rawParts.length === 1 && rawParts[0]?.type === "text"
        ? rawParts[0].content
        : rawParts.map((p) => ("content" in p ? p.content : "")).join("")
    const hasNonText = rawParts.some((part) => part.type !== "text")
    const textContent = (editorRef.textContent ?? "").replace(/\u200B/g, "")
    const shouldReset =
      textContent.length === 0 && rawText.replace(/\n/g, "").length === 0 && !hasNonText && images.length === 0

    if (shouldReset) {
      closePopover()
      resetHistoryNavigation()
      if (prompt.dirty()) {
        markMirrored()
        prompt.set(DEFAULT_PROMPT, 0)
      }
      queueScroll()
      return
    }

    const shellMode = store.mode === "shell"

    if (!shellMode) {
      const atMatch = rawText.substring(0, cursorPosition).match(/@(\S*)$/)
      const slashMatch = rawText.match(/^\/(\S*)$/)

      if (atMatch) {
        autocomplete.atOnInput(atMatch[1])
        setStore("popover", "at")
      } else if (slashMatch) {
        autocomplete.slashOnInput(slashMatch[1])
        setStore("popover", "slash")
      } else {
        closePopover()
      }
    } else {
      closePopover()
    }

    resetHistoryNavigation()

    markMirrored()
    prompt.set([...rawParts, ...images], cursorPosition)
    queueScroll()
  }

  const addPart = (part: ContentPart) => {
    if (part.type === "image") return false

    const selection = window.getSelection()
    if (!selection) return false

    if (selection.rangeCount === 0 || !editorRef.contains(selection.anchorNode)) {
      editorRef.focus()
      const cursor = prompt.cursor() ?? promptLength(prompt.current())
      setCursorPosition(editorRef, cursor)
    }

    if (selection.rangeCount === 0) return false
    const range = selection.getRangeAt(0)
    if (!editorRef.contains(range.startContainer)) return false

    if (part.type === "file" || part.type === "agent") {
      const cursorPosition = getCursorPosition(editorRef)
      const rawText = prompt
        .current()
        .map((p) => ("content" in p ? p.content : ""))
        .join("")
      const textBeforeCursor = rawText.substring(0, cursorPosition)
      const atMatch = textBeforeCursor.match(/@(\S*)$/)
      const pill = createPill(part)
      const gap = document.createTextNode(" ")

      if (atMatch) {
        const start = atMatch.index ?? cursorPosition - atMatch[0].length
        setRangeEdge(editorRef, range, "start", start)
        setRangeEdge(editorRef, range, "end", cursorPosition)
      }

      range.deleteContents()
      range.insertNode(gap)
      range.insertNode(pill)
      range.setStartAfter(gap)
      range.collapse(true)
      selection.removeAllRanges()
      selection.addRange(range)
    }

    if (part.type === "text") {
      const fragment = createTextFragment(part.content)
      const last = fragment.lastChild
      range.deleteContents()
      range.insertNode(fragment)
      if (last) {
        if (last.nodeType === Node.TEXT_NODE) {
          const text = last.textContent ?? ""
          if (text === "\u200B") {
            range.setStart(last, 0)
          }
          if (text !== "\u200B") {
            range.setStart(last, text.length)
          }
        }
        if (last.nodeType !== Node.TEXT_NODE) {
          const isBreak = last.nodeType === Node.ELEMENT_NODE && (last as HTMLElement).tagName === "BR"
          const next = last.nextSibling
          const emptyText = next?.nodeType === Node.TEXT_NODE && (next.textContent ?? "") === ""
          if (isBreak && (!next || emptyText)) {
            const placeholder = next && emptyText ? next : document.createTextNode("\u200B")
            if (!next) last.parentNode?.insertBefore(placeholder, null)
            placeholder.textContent = "\u200B"
            range.setStart(placeholder, 0)
          } else {
            range.setStartAfter(last)
          }
        }
      }
      range.collapse(true)
      selection.removeAllRanges()
      selection.addRange(range)
    }

    handleInput()
    closePopover()
    return true
  }

  const addToHistory = (prompt: Prompt, mode: "normal" | "shell") => {
    const currentHistory = mode === "shell" ? shellHistory : history
    const setCurrentHistory = mode === "shell" ? setShellHistory : setHistory
    const next = prependHistoryEntry(currentHistory.entries, prompt, mode === "shell" ? [] : historyComments())
    if (next === currentHistory.entries) return
    setCurrentHistory("entries", next)
  }

  createEffect(
    on(
      () => props.edit?.id,
      (id) => {
        const edit = props.edit
        if (!id || !edit) return

        for (const item of prompt.context.items()) {
          prompt.context.remove(item.key)
        }

        for (const item of edit.context) {
          prompt.context.add({
            type: item.type,
            path: item.path,
            selection: item.selection,
            comment: item.comment,
            commentID: item.commentID,
            commentOrigin: item.commentOrigin,
            preview: item.preview,
          })
        }

        setStore("mode", "normal")
        setStore("popover", null)
        setStore("historyIndex", -1)
        setStore("savedPrompt", null)
        prompt.set(edit.prompt, promptLength(edit.prompt))
        requestAnimationFrame(() => {
          editorRef.focus()
          setCursorPosition(editorRef, promptLength(edit.prompt))
          queueScroll()
        })
        props.onEditLoaded?.()
      },
      { defer: true },
    ),
  )

  const navigateHistory = (direction: "up" | "down") => {
    const result = navigatePromptHistory({
      direction,
      entries: store.mode === "shell" ? shellHistory.entries : history.entries,
      historyIndex: store.historyIndex,
      currentPrompt: prompt.current(),
      currentComments: historyComments(),
      savedPrompt: store.savedPrompt,
    })
    if (!result.handled) return false
    setStore("historyIndex", result.historyIndex)
    setStore("savedPrompt", result.savedPrompt)
    applyHistoryPrompt(result.entry, result.cursor)
    return true
  }

  const { addAttachment, addAttachments, removeAttachment, handlePaste } = createPromptAttachments({
    editor: () => editorRef,
    isDialogActive: () => !!dialog.active,
    setDraggingType: (type) => setStore("draggingType", type),
    focusEditor: () => {
      editorRef.focus()
      setCursorPosition(editorRef, promptLength(prompt.current()))
    },
    addPart,
    readClipboardImage: platform.readClipboardImage,
  })

  const fileAttachmentInput = () => (
    <input
      ref={(el) => (fileInputRef = el)}
      id="prompt-attachment-input"
      name="prompt-attachment-input"
      type="file"
      multiple
      accept={ACCEPTED_FILE_TYPES.join(",")}
      class="hidden"
      onChange={(e) => {
        const list = e.currentTarget.files
        if (list) void addAttachments(Array.from(list))
        e.currentTarget.value = ""
      }}
    />
  )

  const variants = createMemo(() => ["default", ...local.model.variant.list()])
  // Check provider variants directly: `variants` also includes the UI-only default option.
  const showVariantControl = createMemo(() => local.model.variant.list().length > 0)
  const accepting = createMemo(() => {
    const id = params.id
    if (!id) return permission.isAutoAcceptingDirectory(sdk.directory)
    return permission.isAutoAccepting(id, sdk.directory)
  })

  const { abort, handleSubmit } = createPromptSubmit({
    info,
    imageAttachments,
    commentCount,
    autoAccept: () => accepting(),
    mode: () => store.mode,
    working,
    editor: () => editorRef,
    queueScroll,
    promptLength,
    addToHistory,
    resetHistoryNavigation: () => {
      resetHistoryNavigation(true)
    },
    setMode: (mode) => setStore("mode", mode),
    setPopover: (popover) => setStore("popover", popover),
    newSessionWorktree: () => props.newSessionWorktree,
    onNewSessionWorktreeReset: props.onNewSessionWorktreeReset,
    shouldQueue: props.shouldQueue,
    onQueue: props.onQueue,
    onAbort: props.onAbort,
    onSubmit: props.onSubmit,
  })

  const handleKeyDown = (event: KeyboardEvent) => {
    if ((event.metaKey || event.ctrlKey) && !event.altKey && !event.shiftKey && event.key.toLowerCase() === "u") {
      event.preventDefault()
      if (store.mode !== "normal") return
      pick()
      return
    }

    if (event.key === "Backspace") {
      const selection = window.getSelection()
      if (selection && selection.isCollapsed) {
        const node = selection.anchorNode
        const offset = selection.anchorOffset
        if (node && node.nodeType === Node.TEXT_NODE) {
          const text = node.textContent ?? ""
          if (/^\u200B+$/.test(text) && offset > 0) {
            const range = document.createRange()
            range.setStart(node, 0)
            range.collapse(true)
            selection.removeAllRanges()
            selection.addRange(range)
          }
        }
      }
    }

    if (event.key === "!" && store.mode === "normal") {
      const cursorPosition = getCursorPosition(editorRef)
      if (cursorPosition === 0) {
        setStore("mode", "shell")
        setStore("popover", null)
        event.preventDefault()
        return
      }
    }

    if (event.key === "Escape") {
      if (store.popover) {
        closePopover()
        event.preventDefault()
        event.stopPropagation()
        return
      }

      if (store.mode === "shell") {
        setStore("mode", "normal")
        event.preventDefault()
        event.stopPropagation()
        return
      }

      if (working()) {
        void abort()
        event.preventDefault()
        event.stopPropagation()
        return
      }

      if (escBlur()) {
        editorRef.blur()
        event.preventDefault()
        event.stopPropagation()
        return
      }
    }

    if (store.mode === "shell") {
      const { collapsed, cursorPosition, textLength } = getCaretState()
      if (event.key === "Backspace" && collapsed && cursorPosition === 0 && textLength === 0) {
        setStore("mode", "normal")
        event.preventDefault()
        return
      }
    }

    // Handle Shift+Enter BEFORE IME check - Shift+Enter is never used for IME input
    // and should always insert a newline regardless of composition state
    if (event.key === "Enter" && event.shiftKey) {
      addPart({ type: "text", content: "\n", start: 0, end: 0 })
      event.preventDefault()
      return
    }

    if (event.key === "Enter" && isImeComposing(event)) {
      return
    }

    const ctrl = event.ctrlKey && !event.metaKey && !event.altKey && !event.shiftKey

    if (store.popover) {
      if (event.key === "Tab") {
        selectPopoverActive()
        event.preventDefault()
        return
      }
      const nav = event.key === "ArrowUp" || event.key === "ArrowDown" || event.key === "Enter"
      const ctrlNav = ctrl && (event.key === "n" || event.key === "p")
      if (nav || ctrlNav) {
        if (store.popover === "at") {
          autocomplete.atOnKeyDown(event)
          event.preventDefault()
          return
        }
        if (store.popover === "slash") {
          autocomplete.slashOnKeyDown(event)
        }
        event.preventDefault()
        return
      }
    }

    if (ctrl && event.code === "KeyG") {
      if (store.popover) {
        closePopover()
        event.preventDefault()
        return
      }
      if (working()) {
        void abort()
        event.preventDefault()
      }
      return
    }

    if (event.key === "ArrowUp" || event.key === "ArrowDown") {
      if (event.altKey || event.ctrlKey || event.metaKey) return
      const { collapsed } = getCaretState()
      if (!collapsed) return

      const cursorPosition = getCursorPosition(editorRef)
      const textContent = prompt
        .current()
        .map((part) => ("content" in part ? part.content : ""))
        .join("")
      const direction = event.key === "ArrowUp" ? "up" : "down"
      if (!canNavigateHistoryAtCursor(direction, textContent, cursorPosition, store.historyIndex >= 0)) return
      if (navigateHistory(direction)) {
        event.preventDefault()
      }
      return
    }

    // Note: Shift+Enter is handled earlier, before IME check
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault()
      if (event.repeat) return
      if (
        working() &&
        prompt
          .current()
          .map((part) => ("content" in part ? part.content : ""))
          .join("")
          .trim().length === 0 &&
        imageAttachments().length === 0 &&
        commentCount() === 0
      ) {
        return
      }
      void handleSubmit(event)
    }
  }

  const [agentsQuery, globalProvidersQuery, providersQuery] = useQueries(() => ({
    queries: [
      queryOptions.agents(pathKey(sdk.directory)),
      queryOptions.providers(null),
      queryOptions.providers(pathKey(sdk.directory)),
    ],
  }))

  const agentsLoading = () => agentsQuery.isLoading
  const providersLoading = () => agentsLoading() || providersQuery.isLoading || globalProvidersQuery.isLoading

  const [promptReady] = createResource(
    () => prompt.ready().promise,
    (p) => p,
  )

  const designPlaceholder = () => {
    if (store.mode === "shell") return placeholder()
    return language.t("prompt.placeholder.design")
  }

  const modelControlState = createMemo<ComposerModelControlState>(() => ({
    loading: providersLoading(),
    paid: providers.paid().length > 0,
    title: language.t("command.model.choose"),
    keybind: command.keybind("model.choose"),
    model: local.model,
    providerID: local.model.current()?.provider?.id,
    modelName: local.model.current()?.name ?? language.t("dialog.model.select.title"),
    style: control(),
    onClose: restoreFocus,
    onUnpaidClick: () => {
      void import("@/components/dialog-select-model-unpaid").then((x) => {
        void dialog.show(() => <x.DialogSelectModelUnpaid model={local.model} />)
      })
    },
  }))

  const newSession = () => props.variant === "new-session"
  const projects = createMemo(() => layout.projects.list())
  const projectForDirectory = (directory: string | undefined) => {
    if (!directory) return
    const key = pathKey(directory)
    return projects().find(
      (project) => pathKey(project.worktree) === key || project.sandboxes?.some((sandbox) => pathKey(sandbox) === key),
    )
  }
  const selectedProject = createMemo(() => projectForDirectory(sdk.directory))
  const showAgentControl = createMemo(() => settings.general.showCustomAgents() && agentNames().length > 0)
  const selectProject = (worktree: string) => {
    if (pathKey(worktree) === pathKey(selectedProject()?.worktree ?? "")) {
      restoreFocus()
      return
    }
    layout.projects.open(worktree)
    server.projects.touch(worktree)
    navigate(`/${base64Encode(worktree)}/session`)
  }
  const addProject = () => {
    const conn = server.current
    if (!conn) return
    const select = (result: string | string[] | null) => {
      const directory = Array.isArray(result) ? result[0] : result
      if (!directory) return
      selectProject(directory)
    }
    pickDirectory({
      server: conn,
      title: language.t("command.project.open"),
      onSelect: select,
    })
  }

  const agentControlState = createMemo<ComposerAgentControlState>(() => ({
    title: language.t("command.agent.cycle"),
    keybind: command.keybind("agent.cycle"),
    options: agentNames(),
    current: local.agent.current()?.name ?? "",
    style: control(),
    onSelect: (value) => {
      local.agent.set(value ?? undefined)
      restoreFocus()
    },
  }))
  const newProjectTriggerState = createMemo<ComposerPickerTriggerState>(() => ({
    action: "prompt-project",
    icon: "folder-add-left",
    label: language.t("session.new.project.new"),
    class: "max-w-40",
    style: control(),
    onPress: () => addProject(),
  }))

  const activeDescendant = () => {
    const popover = store.popover
    if (!popover) return undefined
    const key = popover === "at" ? autocomplete.atActive() : autocomplete.slashActive()
    if (!key) return undefined
    return `oc-prompt-opt-${key.replace(/[^a-zA-Z0-9_-]/g, "_")}`
  }

  return (
    <div class="relative size-full flex flex-col gap-0">
      {(promptReady(), null)}
      <PromptPopover
        popover={store.popover}
        placement={newSession() ? "bottom" : "top"}
        setSlashPopoverRef={autocomplete.setSlashPopoverRef}
        atFlat={autocomplete.atFlat()}
        atActive={autocomplete.atActive() ?? undefined}
        atKey={autocomplete.atKey}
        setAtActive={autocomplete.setAtActive}
        onAtSelect={autocomplete.handleAtSelect}
        slashFlat={autocomplete.slashFlat()}
        slashActive={autocomplete.slashActive() ?? undefined}
        setSlashActive={autocomplete.setSlashActive}
        onSlashSelect={autocomplete.handleSlashSelect}
        t={(key) => language.t(key as Parameters<typeof language.t>[0])}
      />
      <div class="flex flex-col gap-3">
            <DockShellForm
              data-component={newSession() ? "session-new-composer" : "session-composer"}
              onSubmit={handleSubmit}
              classList={{
                "group/prompt-input min-h-24 w-full rounded-lg bg-bg-surface": true,
                "border-icon-info-active border-dashed": store.draggingType !== null,
                [props.class ?? ""]: !!props.class,
              }}
            >
              <PromptDragOverlay
                type={store.draggingType}
                label={language.t(
                  store.draggingType === "@mention" ? "prompt.dropzone.file.label" : "prompt.dropzone.label",
                )}
              />
              <PromptContextItems
                items={contextItems()}
                active={(item) => {
                  const active = comments.active()
                  return !!item.commentID && item.commentID === active?.id && item.path === active?.file
                }}
                openComment={openComment}
                remove={(item) => {
                  if (item.commentID) comments.remove(item.path, item.commentID)
                  prompt.context.remove(item.key)
                }}
                t={(key) => language.t(key as Parameters<typeof language.t>[0])}
              />
              <PromptImageAttachments
                attachments={imageAttachments()}
                onOpen={(attachment) =>
                  dialog.show(() => <ImagePreview src={attachment.dataUrl} alt={attachment.filename} />)
                }
                onRemove={removeAttachment}
                removeLabel={language.t("prompt.attachment.remove")}
              />
              <div
                class="relative min-h-13"
                onMouseDown={(e) => {
                  const target = e.target
                  if (!(target instanceof HTMLElement)) return
                  if (target.closest('[data-action^="prompt-"]')) return
                  editorRef?.focus()
                }}
              >
                <div class="relative max-h-45 overflow-y-auto no-scrollbar" ref={(el) => (scrollRef = el)}>
                  <div
                    data-component="prompt-input"
                    ref={(el) => {
                      editorRef = el
                      props.ref?.(el)
                    }}
                    role="textbox"
                    aria-multiline="true"
                    aria-label={designPlaceholder()}
                    aria-controls={store.popover === null ? undefined : "oc-prompt-popover"}
                    aria-activedescendant={activeDescendant()}
                    data-placeholder={designPlaceholder()}
                    contenteditable="true"
                    autocapitalize="off"
                    autocorrect="off"
                    spellcheck={false}
                    inputMode="text"
                    // @ts-expect-error
                    autocomplete="off"
                    onInput={handleInput}
                    onPaste={handlePaste}
                    onCompositionStart={handleCompositionStart}
                    onCompositionEnd={handleCompositionEnd}
                    onBlur={handleBlur}
                    onKeyDown={handleKeyDown}
                    classList={{
                      "select-text": true,
                      "min-h-13 w-full px-4 pt-4 pb-2 focus:outline-none whitespace-pre-wrap leading-5 text-base font-normal text-text-primary": true,
                      "empty:before:content-[attr(data-placeholder)] empty:before:text-text-tertiary empty:before:pointer-events-none": true,
                      "[&_[data-type=file]]:text-syntax-property": true,
                      "[&_[data-type=agent]]:text-syntax-type": true,
                      "font-mono!": store.mode === "shell",
                    }}
                  />

                </div>
              </div>
              <div class="flex h-11 items-center px-2">
                <div class="flex min-w-0 flex-1 items-center gap-0">
                  {fileAttachmentInput()}
                  <Tooltip
                    placement="top"
                    value={language.t("prompt.action.attachFile")}
                    
                  >
                    <IconButton
                      data-action="prompt-attach"
                      type="button"
                      icon="plus"
                      variant="ghost"
                      class="size-7 rounded-md p-1.5 text-icon-muted"
                      style={buttons()}
                      onClick={pick}
                      disabled={store.mode !== "normal"}
                      tabIndex={store.mode === "normal" ? undefined : -1}
                      aria-label={language.t("prompt.action.attachFile")}
                    />
                  </Tooltip>
                  <Show when={canGenerateReport()}>
                    <Tooltip placement="top" value={language.t("report.generate.button")}>
                      <IconButton
                        data-action="prompt-report"
                        type="button"
                        icon={reportSending() ? "refresh" : "report-sparkle"}
                        variant="ghost"
                        class={`size-7 rounded-md p-1.5 text-icon-muted ${reportSending() ? "animate-spin" : ""}`}
                        style={buttons()}
                        onClick={() => void generateReportRequest()}
                        disabled={reportSending() || store.mode !== "normal"}
                        tabIndex={store.mode === "normal" ? undefined : -1}
                        aria-label={language.t("report.generate.button")}
                      />
                    </Tooltip>
                  </Show>
                  <Show when={showAgentControl()}>
                    <ComposerAgentControl state={agentControlState()} />
                  </Show>
                  <Show when={newSession() && !selectedProject()}>
                    <ComposerPickerTrigger state={newProjectTriggerState()} />
                  </Show>
                  <ComposerModelControl state={modelControlState()} />
                  <Show when={store.mode !== "shell" && showVariantControl()}>
                    <div
                      data-component="prompt-variant-control"
                      classList={{
                        "hidden group-hover/prompt-input:block group-focus-within/prompt-input:block":
                          !local.model.variant.current() && !store.variantOpen,
                      }}
                    >
                      <Tooltip
                        placement="top"
                        gutter={4}
                        value={language.t("command.model.variant.cycle")}
                        
                      >
                  <Select
                    options={variants()}
                    current={local.model.variant.current() ?? "default"}
                    label={(x) => (x === "default" ? language.t("common.default") : x)}
                    onOpenChange={(open) => setStore("variantOpen", open)}
                    onSelect={(value) => {
                      local.model.variant.set(value === "default" ? undefined : (value ?? undefined))
                      restoreFocus()
                    }}
                    class="capitalize max-w-40 justify-start text-text-secondary"
                    valueClass="truncate text-base font-normal leading-5 text-text-secondary"
                  />
                      </Tooltip>
                    </div>
                  </Show>
                </div>

                <Tooltip placement="top" inactive={!working() && blank()} value={tip()}>
                  <IconButton
                    data-action="prompt-submit"
                    type="submit"
                    disabled={!working() && blank()}
                    aria-disabled={!working() && blank()}
                    tabIndex={store.mode === "normal" ? undefined : -1}
                    icon={stopping() ? "stop" : store.mode === "shell" ? "arrow-undo-down" : "arrow-up"}
                    variant="contrast-elevated"
                    class="rounded-md shadow-popover transition-transform duration-150 will-change-transform hover:scale-105 active:scale-95 aria-disabled:hover:scale-100"
                    size="large"
                    aria-label={stopping() ? language.t("prompt.action.stop") : language.t("prompt.action.send")}
                  />
                </Tooltip>
              </div>
            </DockShellForm>
          </div>
    </div>
  )
}


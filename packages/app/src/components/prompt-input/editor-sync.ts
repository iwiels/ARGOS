import {
  DEFAULT_PROMPT,
  isPromptEqual,
  usePrompt,
  type AgentPart,
  type FileAttachmentPart,
  type Prompt,
} from "@/context/prompt"
import { createTextFragment, getCursorPosition, setCursorPosition } from "./editor-dom"
import { promptLength } from "./history"

/**
 * Distance (px) reserved at the bottom of the scroll container so the caret
 * never sits flush against the fade/actions overlay. Shared between the
 * scroll-into-view calculation here and the composer's own bottom padding.
 */
export const PROMPT_EDITOR_SCROLL_INSET = 56

type PromptEditorInput = {
  editor: () => HTMLDivElement
  scroll: () => HTMLDivElement | undefined
}

/**
 * Owns the contenteditable <-> Prompt reconciliation for the prompt editor:
 * rendering a `Prompt` into DOM nodes, parsing DOM back into a `Prompt`, and
 * keeping the two in sync without fighting the browser's native editing.
 */
export function createPromptEditor(input: PromptEditorInput) {
  const prompt = usePrompt()

  // Set right before a locally-driven `prompt.set()` so the next reconcile
  // knows the DOM is already correct and can skip a full re-render.
  const mirror = { input: false }

  const clearEditor = () => {
    input.editor().innerHTML = ""
  }

  const setEditorText = (text: string) => {
    clearEditor()
    input.editor().textContent = text
  }

  const focusEditorEnd = () => {
    requestAnimationFrame(() => {
      const editor = input.editor()
      editor.focus()
      const range = document.createRange()
      const selection = window.getSelection()
      range.selectNodeContents(editor)
      range.collapse(false)
      selection?.removeAllRanges()
      selection?.addRange(range)
    })
  }

  const currentCursor = () => {
    const editor = input.editor()
    const selection = window.getSelection()
    if (!selection || selection.rangeCount === 0 || !editor.contains(selection.anchorNode)) return null
    return getCursorPosition(editor)
  }

  const createPill = (part: FileAttachmentPart | AgentPart) => {
    const pill = document.createElement("span")
    pill.textContent = part.content
    pill.setAttribute("data-type", part.type)
    if (part.type === "file") pill.setAttribute("data-path", part.path)
    if (part.type === "agent") pill.setAttribute("data-name", part.name)
    pill.setAttribute("contenteditable", "false")
    pill.style.userSelect = "text"
    pill.style.cursor = "default"
    return pill
  }

  const isNormalizedEditor = () =>
    Array.from(input.editor().childNodes).every((node) => {
      if (node.nodeType === Node.TEXT_NODE) {
        const text = node.textContent ?? ""
        if (!text.includes("\u200B")) return true
        if (text !== "\u200B") return false

        const prev = node.previousSibling
        const next = node.nextSibling
        const prevIsBr = prev?.nodeType === Node.ELEMENT_NODE && (prev as HTMLElement).tagName === "BR"
        return prevIsBr && !next
      }
      if (node.nodeType !== Node.ELEMENT_NODE) return false
      const el = node as HTMLElement
      if (el.dataset.type === "file") return true
      if (el.dataset.type === "agent") return true
      return el.tagName === "BR"
    })

  const renderEditor = (parts: Prompt) => {
    const editor = input.editor()
    clearEditor()
    for (const part of parts) {
      if (part.type === "text") {
        editor.appendChild(createTextFragment(part.content))
        continue
      }
      if (part.type === "file" || part.type === "agent") {
        editor.appendChild(createPill(part))
      }
    }

    const last = editor.lastChild
    if (last?.nodeType === Node.ELEMENT_NODE && (last as HTMLElement).tagName === "BR") {
      editor.appendChild(document.createTextNode("\u200B"))
    }
  }

  const renderEditorWithCursor = (parts: Prompt) => {
    const cursor = currentCursor()
    renderEditor(parts)
    if (cursor !== null) setCursorPosition(input.editor(), cursor)
  }

  const parseFromDOM = (): Prompt => {
    const editor = input.editor()
    const parts: Prompt = []
    let position = 0
    let buffer = ""

    const flushText = () => {
      let content = buffer
      if (content.includes("\r")) content = content.replace(/\r\n?/g, "\n")
      if (content.includes("\u200B")) content = content.replace(/\u200B/g, "")
      buffer = ""
      if (!content) return
      parts.push({ type: "text", content, start: position, end: position + content.length })
      position += content.length
    }

    const pushFile = (file: HTMLElement) => {
      const content = file.textContent ?? ""
      parts.push({
        type: "file",
        path: file.dataset.path!,
        content,
        start: position,
        end: position + content.length,
      })
      position += content.length
    }

    const pushAgent = (agent: HTMLElement) => {
      const content = agent.textContent ?? ""
      parts.push({
        type: "agent",
        name: agent.dataset.name!,
        content,
        start: position,
        end: position + content.length,
      })
      position += content.length
    }

    const visit = (node: Node) => {
      if (node.nodeType === Node.TEXT_NODE) {
        buffer += node.textContent ?? ""
        return
      }
      if (node.nodeType !== Node.ELEMENT_NODE) return

      const el = node as HTMLElement
      if (el.dataset.type === "file") {
        flushText()
        pushFile(el)
        return
      }
      if (el.dataset.type === "agent") {
        flushText()
        pushAgent(el)
        return
      }
      if (el.tagName === "BR") {
        buffer += "\n"
        return
      }

      for (const child of Array.from(el.childNodes)) {
        visit(child)
      }
    }

    const children = Array.from(editor.childNodes)
    children.forEach((child, index) => {
      const isBlock = child.nodeType === Node.ELEMENT_NODE && ["DIV", "P"].includes((child as HTMLElement).tagName)
      visit(child)
      if (isBlock && index < children.length - 1) {
        buffer += "\n"
      }
    })

    flushText()

    if (parts.length === 0) parts.push(...DEFAULT_PROMPT)
    return parts
  }

  const reconcile = (parts: Prompt) => {
    if (mirror.input) {
      mirror.input = false
      if (isNormalizedEditor()) return

      renderEditorWithCursor(parts)
      return
    }

    const dom = parseFromDOM()
    if (isNormalizedEditor() && isPromptEqual(parts, dom)) return

    renderEditorWithCursor(parts)
  }

  const markMirrored = () => {
    mirror.input = true
  }

  const scrollCursorIntoView = () => {
    const container = input.scroll()
    const editor = input.editor()
    const selection = window.getSelection()
    if (!container || !selection || selection.rangeCount === 0) return

    const range = selection.getRangeAt(0)
    if (!editor.contains(range.startContainer)) return

    const cursor = getCursorPosition(editor)
    const length = promptLength(prompt.current().filter((part) => part.type !== "image"))
    if (cursor >= length) {
      container.scrollTop = container.scrollHeight
      return
    }

    const rect = range.getClientRects().item(0) ?? range.getBoundingClientRect()
    if (!rect.height) return

    const containerRect = container.getBoundingClientRect()
    const top = rect.top - containerRect.top + container.scrollTop
    const bottom = rect.bottom - containerRect.top + container.scrollTop
    const padding = 12

    if (top < container.scrollTop + padding) {
      container.scrollTop = Math.max(0, top - padding)
      return
    }

    if (bottom > container.scrollTop + container.clientHeight - PROMPT_EDITOR_SCROLL_INSET) {
      container.scrollTop = bottom - container.clientHeight + PROMPT_EDITOR_SCROLL_INSET
    }
  }

  const queueScroll = (count = 2) => {
    requestAnimationFrame(() => {
      scrollCursorIntoView()
      if (count > 1) queueScroll(count - 1)
    })
  }

  const restoreFocus = () => {
    requestAnimationFrame(() => {
      const editor = input.editor()
      const cursor = prompt.cursor() ?? promptLength(prompt.current())
      editor.focus()
      setCursorPosition(editor, cursor)
      queueScroll()
    })
  }

  return {
    clearEditor,
    setEditorText,
    focusEditorEnd,
    createPill,
    parseFromDOM,
    reconcile,
    markMirrored,
    queueScroll,
    restoreFocus,
  }
}

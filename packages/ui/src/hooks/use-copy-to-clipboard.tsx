import { createSignal, onCleanup } from "solid-js"

export async function writeClipboard(text: string): Promise<boolean> {
  const body = typeof document === "undefined" ? undefined : document.body
  if (body) {
    const textarea = document.createElement("textarea")
    textarea.value = text
    textarea.setAttribute("readonly", "")
    textarea.style.position = "fixed"
    textarea.style.opacity = "0"
    textarea.style.pointerEvents = "none"
    body.appendChild(textarea)
    textarea.select()
    const copied = document.execCommand("copy")
    body.removeChild(textarea)
    if (copied) return true
  }

  const clipboard = typeof navigator === "undefined" ? undefined : navigator.clipboard
  if (!clipboard?.writeText) return false
  return clipboard.writeText(text).then(
    () => true,
    () => false,
  )
}

export function useCopyToClipboard(revertMs = 2000) {
  const [copied, setCopied] = createSignal(false)
  let timer: ReturnType<typeof setTimeout> | undefined

  onCleanup(() => {
    if (timer) clearTimeout(timer)
  })

  const copy = async (text: string) => {
    if (!text) return false
    const ok = await writeClipboard(text)
    if (ok) {
      if (timer) clearTimeout(timer)
      setCopied(true)
      timer = setTimeout(() => setCopied(false), revertMs)
    }
    return ok
  }

  return { copied, copy }
}

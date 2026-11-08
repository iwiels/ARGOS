import { createEffect, createSignal, on, onCleanup, type Accessor } from "solid-js"
import type { VirtualizerHandle } from "virtua/solid"
import { normalizeWheelDelta } from "./message-gesture"
import { markBoundaryGesture, writeTimelineCache } from "./message-timeline-cache"

export function useTimelineScroller(input: {
  sessionKey: Accessor<string>
  timelineRowKeys: Accessor<string[]>
  messageRowIndex: Accessor<Map<string, number>>
  activeAssistantContentVersion: Accessor<string>
  sessionStatusType: Accessor<string>
  working: Accessor<boolean>
  shouldAnchorBottom: () => boolean
  setRevealMessage?: (fn: (id: string) => void) => void
  setScrollRef: (el: HTMLDivElement | undefined) => void
  setContentRef: (el: HTMLDivElement) => void
  onScheduleScrollState: (el: HTMLDivElement) => void
  onHistoryScroll: () => void
  hasScrollGesture: () => boolean
  onUserScroll: () => void
  onAutoScrollHandleScroll: () => void
  onMarkScrollGesture: (target?: EventTarget | null) => void
}) {
  let touchGesture: number | undefined
  let virtualizer: VirtualizerHandle | undefined

  let cacheSessionKey = input.sessionKey()
  let cacheRowKeys = input.timelineRowKeys()
  let virtualizerSessionKey = cacheSessionKey
  let virtualizerRowKeys = cacheRowKeys
  let bottomAnchorSessionKey = ""

  const maybeAnchorBottom = () => {
    const key = input.sessionKey()
    if (bottomAnchorSessionKey === key) return
    if (!virtualizer) return
    const keys = input.timelineRowKeys()
    if (keys.length === 0) return
    bottomAnchorSessionKey = key
    if (!input.shouldAnchorBottom()) return
    virtualizer.scrollToIndex(keys.length - 1, { align: "end" })
  }

  createEffect(
    on(
      () => [input.timelineRowKeys(), input.activeAssistantContentVersion(), input.sessionStatusType()] as const,
      () => {
        if (!virtualizer) return
        if (!input.shouldAnchorBottom() && !measuredBottomAnchored) return
        const keys = input.timelineRowKeys()
        if (keys.length === 0) return
        virtualizer.scrollToIndex(keys.length - 1, { align: "end" })
        scheduleMeasuredBottomAnchor()
      },
      { defer: true },
    ),
  )

  createEffect(() => {
    input.setRevealMessage?.((id) => {
      const index = input.messageRowIndex().get(id)
      if (index === undefined) return
      virtualizer?.scrollToIndex(index, { align: "center" })
    })
  })

  createEffect(
    on(
      () => [input.sessionKey(), input.timelineRowKeys()] as const,
      (next, prev) => {
        if (prev && prev[0] !== next[0]) writeTimelineCache(prev[0], prev[1], virtualizer)
        cacheSessionKey = next[0]
        cacheRowKeys = next[1]
        if (virtualizer) {
          virtualizerSessionKey = cacheSessionKey
          virtualizerRowKeys = cacheRowKeys
          maybeAnchorBottom()
        }
      },
      { defer: true },
    ),
  )

  onCleanup(() => {
    writeTimelineCache(virtualizerSessionKey, virtualizerRowKeys, virtualizer)
    input.setRevealMessage?.(() => {})
    indexObserver?.disconnect()
  })

  let listRoot: HTMLDivElement | undefined
  let indexObserver: MutationObserver | undefined
  let listFrame: number | undefined
  let contentFrame: number | undefined
  let bottomAnchorFrame: number | undefined
  let bottomAnchorFrames = 0
  let measuredBottomAnchored = true
  const [scrollRoot, setScrollRoot] = createSignal<HTMLDivElement>()

  const isMeasuredBottom = (root: HTMLDivElement) => root.scrollHeight - root.clientHeight - root.scrollTop <= 4

  const measureTimeline = () => {
    
    anchorMeasuredBottom()
  }

  function anchorMeasuredBottom() {
    if (!listRoot) return false
    if (!measuredBottomAnchored) return false
    listRoot.scrollTop = listRoot.scrollHeight
    return true
  }

  function scheduleMeasuredBottomAnchor() {
    // Workaround for virtua issue #301: virtua does not expose a synchronous item-resize hook for
    // "stay at bottom if already at bottom". Tool rows can briefly outgrow the measured virtual
    // height, so keep the scroll container bottom-locked for a few frames while measurement settles.
    bottomAnchorFrames = 90
    if (bottomAnchorFrame !== undefined) return

    const tick = () => {
      bottomAnchorFrame = undefined
      if (!anchorMeasuredBottom()) {
        bottomAnchorFrames = 0
        return
      }

      bottomAnchorFrames = input.working() ? 12 : bottomAnchorFrames - 1
      if (bottomAnchorFrames <= 0) return
      bottomAnchorFrame = requestAnimationFrame(tick)
    }

    bottomAnchorFrame = requestAnimationFrame(tick)
  }

  const bindContentRoot = (root: HTMLDivElement) => {
    const child = root.firstElementChild
    input.setContentRef(child instanceof HTMLDivElement ? child : root)
  }

  const scheduleContentRoot = (root: HTMLDivElement) => {
    if (contentFrame !== undefined) cancelAnimationFrame(contentFrame)
    contentFrame = requestAnimationFrame(() => {
      contentFrame = undefined
      if (listRoot !== root) return
      bindContentRoot(root)
    })
  }

  const connectListRoot = (root: HTMLDivElement) => {
    if (listRoot !== root) return
    if (!root.isConnected || !root.ownerDocument.defaultView) {
      listFrame = requestAnimationFrame(() => {
        listFrame = undefined
        connectListRoot(root)
      })
      return
    }

    input.setScrollRef(root)
    measuredBottomAnchored = isMeasuredBottom(root)
    setScrollRoot(root)
    scheduleContentRoot(root)
  }

  const bindListRoot = (root: HTMLDivElement) => {
    if (root === listRoot) return

    if (listFrame !== undefined) cancelAnimationFrame(listFrame)
    if (contentFrame !== undefined) cancelAnimationFrame(contentFrame)
    listRoot = root
    setScrollRoot(undefined)
    connectListRoot(root)
  }

  const handleListWheel = (event: WheelEvent & { currentTarget: HTMLDivElement }) => {
    const root = event.currentTarget
    const delta = normalizeWheelDelta({
      deltaY: event.deltaY,
      deltaMode: event.deltaMode,
      rootHeight: root.clientHeight,
    })
    if (!delta) return
    markBoundaryGesture({ root, target: event.target, delta, onMarkScrollGesture: input.onMarkScrollGesture })
  }

  const handleListTouchStart = (event: TouchEvent) => {
    touchGesture = event.touches[0]?.clientY
  }

  const handleListTouchMove = (event: TouchEvent & { currentTarget: HTMLDivElement }) => {
    const next = event.touches[0]?.clientY
    const prev = touchGesture
    touchGesture = next
    if (next === undefined || prev === undefined) return

    const delta = prev - next
    if (!delta) return

    markBoundaryGesture({
      root: event.currentTarget,
      target: event.target,
      delta,
      onMarkScrollGesture: input.onMarkScrollGesture,
    })
  }

  const handleListTouchEnd = () => {
    touchGesture = undefined
  }

  const handleListPointerDown = (event: PointerEvent & { currentTarget: HTMLDivElement }) => {
    if (event.target !== event.currentTarget) return
    input.onMarkScrollGesture(event.currentTarget)
  }

  const handleListScroll = (event: Event & { currentTarget: HTMLDivElement }) => {
    measuredBottomAnchored = isMeasuredBottom(event.currentTarget)
    input.onScheduleScrollState(event.currentTarget)
    input.onHistoryScroll()
    if (!input.hasScrollGesture()) return
    input.onUserScroll()
    input.onAutoScrollHandleScroll()
    input.onMarkScrollGesture(event.currentTarget)
  }

  const connectVirtualizer = (handle: VirtualizerHandle | undefined, rootEl: HTMLDivElement) => {
    if (!handle) {
      indexObserver?.disconnect()
      indexObserver = undefined
      writeTimelineCache(virtualizerSessionKey, virtualizerRowKeys, virtualizer)
      virtualizer = undefined
      return
    }
    virtualizer = handle
    virtualizerSessionKey = cacheSessionKey
    virtualizerRowKeys = cacheRowKeys
    maybeAnchorBottom()
    scheduleContentRoot(rootEl)
    if (!indexObserver) {
      indexObserver = new MutationObserver((mutations) => {
        for (const mutation of mutations) {
          for (const node of mutation.addedNodes) {
            if (node instanceof Element) node.removeAttribute("index")
          }
        }
      })
      indexObserver.observe(rootEl, { childList: true, subtree: true })
    }
  }

  onCleanup(() => {
    if (listFrame !== undefined) cancelAnimationFrame(listFrame)
    if (contentFrame !== undefined) cancelAnimationFrame(contentFrame)
    if (bottomAnchorFrame !== undefined) cancelAnimationFrame(bottomAnchorFrame)
    setScrollRoot(undefined)
    input.setScrollRef(undefined)
  })

  return {
    scrollRoot,
    measureTimeline,
    bindListRoot,
    connectVirtualizer,
    handleListWheel,
    handleListTouchStart,
    handleListTouchMove,
    handleListTouchEnd,
    handleListPointerDown,
    handleListScroll,
  }
}

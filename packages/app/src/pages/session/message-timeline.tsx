import { createEffect, createMemo, createSignal, on, Show, mapArray, type Accessor } from "solid-js"
import { createStore, produce } from "solid-js/store"
import { useNavigate } from "@solidjs/router"
import { useMutation } from "@tanstack/solid-query"
import { Virtualizer } from "virtua/solid"
import { Button } from "@argos/ui/button"
import { Icon } from "@argos/ui/icon"
import { Dialog } from "@argos/ui/dialog"
import { SessionRetry } from "@argos/ui/session-retry"
import { ScrollView } from "@argos/ui/scroll-view"
import type { AssistantMessage, Message as MessageType, Part as PartType, UserMessage } from "@argos/sdk/client"
import type { UserActions } from "@argos/ui/message-part"
import { showToast } from "@/utils/toast"
import { Binary } from "@/core/binary"
import { useDialog } from "@argos/ui/context/dialog"
import { createResizeObserver } from "@solid-primitives/resize-observer"
import { useLanguage } from "@/context/language"
import { useSessionKey } from "@/pages/session/session-layout"
import { useServerSDK } from "@/context/server-sdk"
import { useServerSync } from "@/context/server-sync"
import { usePlatform } from "@/context/platform"
import { useSettings } from "@/context/settings"
import { useSDK } from "@/context/sdk"
import { useSync } from "@/context/sync"
import { notifySessionTabsRemoved } from "@/components/titlebar-session-events"
import { messageAgentColor } from "@/utils/agent"
import { sessionTitle } from "@/utils/session-title"
import { makeTimer } from "@solid-primitives/timer"
import { Timeline, TimelineRow } from "./message-timeline.data"
import {
  pace,
  readTimelineCache,
  sameKeys,
  timelineFallbackItemSize,
  reuseTimelineRows,
  taskDescription,
} from "./message-timeline-cache"
import { TimelineDiffSummaryRow, TimelineThinkingRow, TurnLabel } from "./message-timeline-rows"
import { StreamErrorCard } from "./stream-error-card"
import { useTimelineRetry } from "./use-timeline-retry"
import { useTimelineScroller } from "./use-timeline-scroller"
import {
  TimelineAssistantPartGroup,
  TimelineCommentStrip,
  TimelineRowByTag,
  TimelineRowFrame,
  TimelineToolRun,
  TimelineTurnDivider,
  TimelineUserMessage,
} from "./message-timeline-parts"

const emptyMessages: MessageType[] = []
const emptyParts: PartType[] = []
const emptyAssistantMessages: AssistantMessage[] = []
const idle = { type: "idle" as const }


export function MessageTimeline(props: {
  actions?: UserActions
  scroll: { overflow: boolean; bottom: boolean; jump: boolean }
  onResumeScroll: () => void
  setScrollRef: (el: HTMLDivElement | undefined) => void
  onScheduleScrollState: (el: HTMLDivElement) => void
  onAutoScrollHandleScroll: () => void
  onMarkScrollGesture: (target?: EventTarget | null) => void
  hasScrollGesture: () => boolean
  onUserScroll: () => void
  onHistoryScroll: () => void
  onAutoScrollInteraction: (event: MouseEvent) => void
  shouldAnchorBottom: () => boolean
  centered: boolean
  setContentRef: (el: HTMLDivElement) => void
  historyShift: boolean
  userMessages: UserMessage[]
  anchor: (id: string) => string
  setRevealMessage?: (fn: (id: string) => void) => void
}) {
  const navigate = useNavigate()
  const serverSDK = useServerSDK()
  const serverSync = useServerSync()
  const sdk = useSDK()
  const sync = useSync()
  const settings = useSettings()
  const dialog = useDialog()
  const language = useLanguage()
  const { params, sessionKey } = useSessionKey()
  const platform = usePlatform()

  const sessionID = createMemo(() => params.id)
  const sessionMessages = createMemo(() => {
    const id = sessionID()
    if (!id) return emptyMessages
    const raw = sync.data.message[id] ?? emptyMessages
    const seen = new Set<string>()
    const result: typeof raw = []
    for (const msg of raw) {
      if (seen.has(msg.id)) continue
      seen.add(msg.id)
      result.push(msg)
    }
    return result
  })
  const messageByID = createMemo(() => new Map(sessionMessages().map((message) => [message.id, message] as const)))
  const assistantMessagesByParent = createMemo(() => {
    const result = new Map<string, AssistantMessage[]>()
    for (const message of sessionMessages()) {
      if (message.role !== "assistant") continue
      const messages = result.get(message.parentID)
      if (messages) {
        messages.push(message)
        continue
      }
      result.set(message.parentID, [message])
    }
    return result
  })
  const pending = createMemo(() =>
    sessionMessages().findLast(
      (item): item is AssistantMessage => item.role === "assistant" && typeof item.time.completed !== "number",
    ),
  )
  const sessionStatus = createMemo(() => {
    const id = sessionID()
    if (!id) return idle
    return sync.data.session_status[id] ?? idle
  })
  const working = createMemo(() => sessionStatus().type !== "idle")
  const tint = createMemo(() => messageAgentColor(sessionMessages(), sync.data.agent))

  const [timeoutDone, setTimeoutDone] = createSignal(true)

  const workingStatus = createMemo<"hidden" | "showing" | "hiding">((prev) => {
    if (working()) return "showing"
    if (prev === "showing" || !timeoutDone()) return "hiding"
    return "hidden"
  })

  createEffect(() => {
    if (workingStatus() !== "hiding") return

    setTimeoutDone(false)
    makeTimer(() => setTimeoutDone(true), 260, setTimeout)
  })

  const activeMessageID = createMemo(() => {
    const parentID = pending()?.parentID
    if (parentID) {
      const messages = sessionMessages()
      const result = Binary.search(messages, parentID, (message) => message.id)
      const message = result.found ? messages[result.index] : messages.find((item) => item.id === parentID)
      if (message && message.role === "user") return message.id
    }

    const status = sessionStatus()
    if (status.type !== "idle") {
      const messages = sessionMessages()
      for (let i = messages.length - 1; i >= 0; i--) {
        if (messages[i].role === "user") return messages[i].id
      }
    }

    return undefined
  })
  const info = createMemo(() => {
    const id = sessionID()
    if (!id) return
    return sync.session.get(id)
  })
  const titleValue = createMemo(() => info()?.title)
  const titleLabel = createMemo(() => sessionTitle(titleValue()))
  const shareUrl = createMemo(() => info()?.share?.url)
  const shareEnabled = createMemo(() => sync.data.config.share !== "disabled")
  const parentID = createMemo(() => info()?.parentID)
  const parent = createMemo(() => {
    const id = parentID()
    if (!id) return
    return sync.session.get(id)
  })
  const parentMessages = createMemo(() => {
    const id = parentID()
    if (!id) return emptyMessages
    return sync.data.message[id] ?? emptyMessages
  })
  const parentTitle = createMemo(() => sessionTitle(parent()?.title) ?? language.t("command.session.new"))
  const getMsgParts = (msgId: string) => sync.data.part[msgId] ?? emptyParts
  const { retrying, retryFailedTurn, errorMessage } = useTimelineRetry({
    sessionID,
    messageByID,
    getMsgParts,
  })
  const childTaskDescription = createMemo(() => {
    const id = sessionID()
    if (!id) return
    return parentMessages()
      .flatMap((message) => getMsgParts(message.id))
      .map((part) => taskDescription(part, id))
      .findLast((value): value is string => !!value)
  })
  const childTitle = createMemo(() => {
    if (!parentID()) return titleLabel() ?? ""
    if (childTaskDescription()) return childTaskDescription()
    const value = titleLabel()?.replace(/\s+\(@[^)]+ subagent\)$/, "")
    if (value) return value
    return language.t("command.session.new")
  })
  const showHeader = createMemo(() => !!(titleValue() || parentID()))
  const scrollButtonVisible = createMemo(() => props.scroll.overflow && props.scroll.jump)

  const messageRowMemos = createMemo(
    mapArray(
      () => props.userMessages,
      (userMessage, indexAccessor) => {
        return createMemo((previous: TimelineRow.TimelineRow[] | undefined) => {
          const rows = Timeline.constructMessageRows(
            userMessage,
            getMsgParts,
            assistantMessagesByParent().get(userMessage.id) ?? emptyAssistantMessages,
            indexAccessor(),
            settings.general.showReasoningSummaries(),
            sessionStatus().type,
            activeMessageID() === userMessage.id,
          )

          return reuseTimelineRows(previous, rows)
        })
      },
    ),
  )

  const timelineRows = createMemo((previous: TimelineRow.TimelineRow[] | undefined) => {
    const rows = messageRowMemos().flatMap((memo) => memo())
    if (rows.length === 0) return rows
    return reuseTimelineRows(previous, [...rows, new TimelineRow.BottomSpacer()])
  })
  const timelineRowKeys = createMemo(() => timelineRows().map(TimelineRow.key), [] as string[], { equals: sameKeys })
  const virtualCache = createMemo(() => readTimelineCache(sessionKey(), timelineRowKeys()))
  const messageRowIndex = createMemo(() => {
    const result = new Map<string, number>()
    timelineRows().forEach((row, index) => {
      if (!("userMessageID" in row)) return
      if (result.has(row.userMessageID)) return
      result.set(row.userMessageID, index)
    })
    return result
  })
  const lastAssistantGroupKey = createMemo(() => {
    const result = new Map<string, string>()
    timelineRows().forEach((row) => {
      if (row._tag !== "AssistantPart") return
      result.set(row.userMessageID, row.group.key)
    })
    return result
  })
  const keepMounted = createMemo(() => {
    const id = activeMessageID()
    if (!id) return
    const rows = timelineRows()
    const index = rows.findLastIndex((row) => "userMessageID" in row && row.userMessageID === id)
    if (index < 0) return
    return [index]
  })
  const activeAssistantMessages = createMemo(() => {
    const id = activeMessageID() ?? props.userMessages[props.userMessages.length - 1]?.id
    if (!id) return emptyAssistantMessages
    return assistantMessagesByParent().get(id) ?? emptyAssistantMessages
  })
  const activeAssistantContentVersion = createMemo(() => {
    let hash = 0x811c9dc4
    let tokens = 0
    let length = 0
    const mix = (token: string) => {
      tokens++
      length += token.length
      for (let i = 0; i < token.length; i++) hash = Math.imul(hash ^ token.charCodeAt(i), 16777619)
    }
    for (const message of activeAssistantMessages()) {
      mix(`${message.id}:${message.time.completed ?? ""}:${message.error?.name ?? ""}`)
      for (const part of getMsgParts(message.id)) {
        if (part.type === "text" || part.type === "reasoning") {
          mix(`${part.id}:${part.type}:${part.text.length}`)
          continue
        }
        if (part.type === "tool") {
          const metadata = "metadata" in part.state ? part.state.metadata : undefined
          const output =
            "output" in part.state && typeof part.state.output === "string" ? part.state.output.length : 0
          const metadataOutput =
            metadata && typeof metadata === "object" && "output" in metadata && typeof metadata.output === "string"
              ? metadata.output.length
              : 0
          mix(`${part.id}:${part.tool}:${part.state.status}:${output}:${metadataOutput}`)
          continue
        }
        mix(`${part.id}:${part.type}`)
      }
    }
    return `${tokens.toString(36)}:${length.toString(36)}:${(hash >>> 0).toString(36)}`
  })

  const scroller = useTimelineScroller({
    sessionKey,
    timelineRowKeys,
    messageRowIndex,
    activeAssistantContentVersion,
    sessionStatusType: () => sessionStatus().type,
    working,
    shouldAnchorBottom: props.shouldAnchorBottom,
    setRevealMessage: props.setRevealMessage,
    setScrollRef: props.setScrollRef,
    setContentRef: props.setContentRef,
    onScheduleScrollState: props.onScheduleScrollState,
    onHistoryScroll: props.onHistoryScroll,
    hasScrollGesture: props.hasScrollGesture,
    onUserScroll: props.onUserScroll,
    onAutoScrollHandleScroll: props.onAutoScrollHandleScroll,
    onMarkScrollGesture: props.onMarkScrollGesture,
  })

  const [title, setTitle] = createStore({
    draft: "",
    editing: false,
    menuOpen: false,
    pendingRename: false,
    pendingShare: false,
  })
  let titleRef: HTMLInputElement | undefined

  const [share, setShare] = createStore({
    open: false,
    dismiss: null as "escape" | "outside" | null,
  })
  const [bar, setBar] = createStore({
    ms: pace(640),
  })
  const [toolOpen, setToolOpen] = createStore<Record<string, boolean | undefined>>({})

  let more: HTMLButtonElement | undefined
  let head: HTMLDivElement | undefined

  const updateTitleMetrics = () => {
    if (!head || head.clientWidth <= 0) return
    setBar("ms", pace(head.clientWidth))
  }

  createResizeObserver(() => head, updateTitleMetrics)

  const viewShare = () => {
    const url = shareUrl()
    if (!url) return
    platform.openLink(url)
  }

  const shareMutation = useMutation(() => ({
    mutationFn: (id: string) => serverSDK.client.session.share({ sessionID: id, directory: sdk.directory }),
    onError: (err) => {
      console.error("Failed to share session", err)
    },
  }))

  const unshareMutation = useMutation(() => ({
    mutationFn: (id: string) => serverSDK.client.session.unshare({ sessionID: id, directory: sdk.directory }),
    onError: (err) => {
      console.error("Failed to unshare session", err)
    },
  }))

  const titleMutation = useMutation(() => ({
    mutationFn: (input: { id: string; title: string }) =>
      sdk.client.session.update({ sessionID: input.id, title: input.title }),
    onSuccess: (_, input) => {
      sync.set(
        produce((draft) => {
          const index = draft.session.findIndex((s) => s.id === input.id)
          if (index !== -1) draft.session[index].title = input.title
        }),
      )
      setTitle("editing", false)
    },
    onError: (err) => {
      showToast({
        title: language.t("common.requestFailed"),
        description: errorMessage(err),
      })
    },
  }))

  const shareSession = () => {
    const id = sessionID()
    if (!id || shareMutation.isPending) return
    if (!shareEnabled()) return
    shareMutation.mutate(id)
  }

  const unshareSession = () => {
    const id = sessionID()
    if (!id || unshareMutation.isPending) return
    if (!shareEnabled()) return
    unshareMutation.mutate(id)
  }

  createEffect(
    on(
      sessionKey,
      () =>
        setTitle({
          draft: "",
          editing: false,
          menuOpen: false,
          pendingRename: false,
          pendingShare: false,
        }),
      { defer: true },
    ),
  )

  createEffect(
    on(
      () => [parentID(), childTaskDescription()] as const,
      ([id, description]) => {
        if (!id || description) return
        if (sync.data.message[id] !== undefined) return
        void sync.session.sync(id)
      },
      { defer: true },
    ),
  )

  const openTitleEditor = () => {
    if (!sessionID() || parentID()) return
    setTitle({ editing: true, draft: titleLabel() ?? "" })
    requestAnimationFrame(() => {
      titleRef?.focus()
      titleRef?.select()
    })
  }

  const closeTitleEditor = () => {
    if (titleMutation.isPending) return
    setTitle("editing", false)
  }

  const saveTitleEditor = () => {
    const id = sessionID()
    if (!id) return
    if (titleMutation.isPending) return

    const next = title.draft.trim()
    if (!next || next === (titleLabel() ?? "")) {
      setTitle("editing", false)
      return
    }

    titleMutation.mutate({ id, title: next })
  }

  const navigateAfterSessionRemoval = (sessionID: string, parentID?: string, nextSessionID?: string) => {
    if (params.id !== sessionID) return
    if (parentID) {
      navigate(`/${params.dir}/session/${parentID}`)
      return
    }
    if (nextSessionID) {
      navigate(`/${params.dir}/session/${nextSessionID}`)
      return
    }
    navigate(`/${params.dir}/session`)
  }

  const archiveSession = async (sessionID: string) => {
    const session = sync.session.get(sessionID)
    if (!session) return

    const sessions = sync.data.session ?? []
    const index = sessions.findIndex((s) => s.id === sessionID)
    const nextSession = index === -1 ? undefined : (sessions[index + 1] ?? sessions[index - 1])

    await sdk.client.session
      .update({ sessionID, time: { archived: Date.now() } })
      .then(() => {
        sync.set(
          produce((draft) => {
            const index = draft.session.findIndex((s) => s.id === sessionID)
            if (index !== -1) draft.session.splice(index, 1)
          }),
        )
        sync.session.evict(sessionID)
        navigateAfterSessionRemoval(sessionID, session.parentID, nextSession?.id)
        notifySessionTabsRemoved({ directory: sdk.directory, sessionIDs: [sessionID] })
      })
      .catch((err) => {
        showToast({
          title: language.t("common.requestFailed"),
          description: errorMessage(err),
        })
      })
  }

  const deleteSession = async (sessionID: string) => {
    const session = sync.session.get(sessionID)
    if (!session) return false

    const sessions = (sync.data.session ?? []).filter((s) => !s.parentID && !s.time?.archived)
    const index = sessions.findIndex((s) => s.id === sessionID)
    const nextSession = index === -1 ? undefined : (sessions[index + 1] ?? sessions[index - 1])

    const result = await sdk.client.session
      .delete({ sessionID })
      .then((x) => x.data)
      .catch((err) => {
        showToast({
          title: language.t("session.delete.failed.title"),
          description: errorMessage(err),
        })
        return false
      })

    if (!result) return false

    const removed = new Set<string>([sessionID])
    const byParent = new Map<string, string[]>()
    for (const item of sync.data.session) {
      const parentID = item.parentID
      if (!parentID) continue
      const existing = byParent.get(parentID)
      if (existing) {
        existing.push(item.id)
        continue
      }
      byParent.set(parentID, [item.id])
    }

    const stack = [sessionID]
    while (stack.length) {
      const parentID = stack.pop()
      if (!parentID) continue

      const children = byParent.get(parentID)
      if (!children) continue

      for (const child of children) {
        if (removed.has(child)) continue
        removed.add(child)
        stack.push(child)
      }
    }

    navigateAfterSessionRemoval(sessionID, session.parentID, nextSession?.id)

    sync.set(
      produce((draft) => {
        draft.session = draft.session.filter((s) => !removed.has(s.id))
      }),
    )

    for (const id of removed) {
      sync.session.evict(id)
    }
    notifySessionTabsRemoved({ directory: sdk.directory, sessionIDs: [...removed] })
    return true
  }

  const navigateParent = () => {
    const id = parentID()
    if (!id) return
    navigate(`/${params.dir}/session/${id}`)
  }

  function DialogDeleteSession(props: { sessionID: string }) {
    const name = createMemo(
      () => sessionTitle(sync.session.get(props.sessionID)?.title) ?? language.t("command.session.new"),
    )
    const handleDelete = async () => {
      await deleteSession(props.sessionID)
      dialog.close()
    }

    return (
      <Dialog title={language.t("session.delete.title")} fit>
        <div class="flex flex-col gap-4 pl-6 pr-2.5 pb-3">
          <div class="flex flex-col gap-1">
            <span class="text-14-regular text-text-strong">
              {language.t("session.delete.confirm", { name: name() })}
            </span>
          </div>
          <div class="flex justify-end gap-2">
            <Button variant="ghost" size="large" onClick={() => dialog.close()}>
              {language.t("common.cancel")}
            </Button>
            <Button variant="contrast" size="large" onClick={handleDelete}>
              {language.t("session.delete.button")}
            </Button>
          </div>
        </div>
      </Dialog>
    )
  }

  const workingTurn = (userMessageID: string) => sessionStatus().type !== "idle" && activeMessageID() === userMessageID

  const turnDurationMs = (userMessageID: string) => {
    const message = messageByID().get(userMessageID)
    if (!message || message.role !== "user") return
    const end = (assistantMessagesByParent().get(userMessageID) ?? emptyAssistantMessages).reduce<number | undefined>(
      (max, item) => {
        const completed = item.time.completed
        if (typeof completed !== "number") return max
        if (max === undefined) return completed
        return Math.max(max, completed)
      },
      undefined,
    )
    if (typeof end !== "number") return
    if (end < message.time.created) return
    return end - message.time.created
  }

  const assistantCopyPartID = (userMessageID: string) => {
    if (workingTurn(userMessageID)) return null
    const messages = assistantMessagesByParent().get(userMessageID) ?? emptyAssistantMessages

    for (let i = messages.length - 1; i >= 0; i--) {
      const message = messages[i]
      if (!message) continue

      const parts = getMsgParts(message.id)
      for (let j = parts.length - 1; j >= 0; j--) {
        const part = parts[j]
        if (!part || part.type !== "text" || !part.text?.trim()) continue
        return part.id
      }
    }
  }

  const getMsgPart = (messageID: string, partID: string) => getMsgParts(messageID).find((part) => part.id === partID)

  const turnLabelFor = (userMessageID: string) => {
    const messages = assistantMessagesByParent().get(userMessageID) ?? emptyAssistantMessages
    // Text turns already carry the "agent · model · duration" meta on the last
    // text part, so the top label is reserved for tool-only turns where that
    // meta is absent (the wall-of-tools case that benefits most from it).
    const hasText = messages.some((message) =>
      getMsgParts(message.id).some((part) => part.type === "text" && part.text?.trim()),
    )
    if (hasText) return undefined
    const lastMessage = messages[messages.length - 1]
    const agent = lastMessage?.agent
    const name = agent ? agent[0]?.toUpperCase() + agent.slice(1) : undefined
    return (
      <Show when={name}>
        <TurnLabel color={tint()} name={name} durationMs={turnDurationMs(userMessageID)} />
      </Show>
    )
  }


  const turnMemoList = createMemo(
    mapArray(
      () => props.userMessages,
      (userMessage) => ({
        userMessageID: userMessage.id,
        working: createMemo(() => workingTurn(userMessage.id)),
        label: createMemo(() => turnLabelFor(userMessage.id)),
        copyPartID: createMemo(() => assistantCopyPartID(userMessage.id)),
        durationMs: createMemo(() => turnDurationMs(userMessage.id)),
      }),
    ),
  )
  const turnMemosByID = createMemo(() =>
    new Map(turnMemoList().map((entry) => [entry.userMessageID, entry] as const)),
  )
  const turnMemosFor = (userMessageID: string) => turnMemosByID().get(userMessageID)

  const renderTimelineRow = (row: Accessor<TimelineRow.TimelineRow>) => {
    switch (row()._tag) {
      case "CommentStrip": {
        const commentStripRow = row as Accessor<TimelineRowByTag<"CommentStrip">>
        return (
          <TimelineCommentStrip
            row={commentStripRow}
            getParts={getMsgParts}
            anchorId={props.anchor}
            centered={props.centered}
          />
        )
      }
      case "UserMessage": {
        const userMessageRow = row as Accessor<TimelineRowByTag<"UserMessage">>
        return (
          <TimelineUserMessage
            row={userMessageRow}
            getMessage={(id) => messageByID().get(id)}
            getParts={getMsgParts}
            actions={props.actions}
            anchorId={props.anchor}
            centered={props.centered}
          />
        )
      }
      case "TurnDivider": {
        const turnDividerRow = row as Accessor<TimelineRowByTag<"TurnDivider">>
        return (
          <TimelineTurnDivider
            row={turnDividerRow}
            label={language.t(
              turnDividerRow().label === "compaction" ? "ui.messagePart.compaction" : "ui.message.interrupted",
            )}
            anchorId={props.anchor}
            centered={props.centered}
          />
        )
      }
      case "AssistantPart": {
        const assistantPartRow = row as Accessor<TimelineRowByTag<"AssistantPart">>
        const turnMemos = () => turnMemosFor(assistantPartRow().userMessageID)
        return (
          <TimelineRowFrame row={assistantPartRow} anchorId={props.anchor} centered={props.centered}>
            <div data-slot="session-turn-message-container" class="w-full">
              <Show when={!assistantPartRow().previousAssistantPart}>{turnMemos()?.label()}</Show>
              <div
                data-slot="session-turn-assistant-content"
                aria-busy={turnMemos()?.working() || undefined}
              >
                <TimelineAssistantPartGroup
                  row={assistantPartRow}
                  busy={
                    (turnMemos()?.working() ?? false) &&
                    lastAssistantGroupKey().get(assistantPartRow().userMessageID) === assistantPartRow().group.key
                  }
                  copyPartID={turnMemos()?.copyPartID()}
                  durationMs={turnMemos()?.durationMs()}
                  getMessage={(id) => messageByID().get(id)}
                  getPart={getMsgPart}
                  shellExpanded={settings.general.shellToolPartsExpanded()}
                  editExpanded={settings.general.editToolPartsExpanded()}
                  toolOpen={toolOpen}
                  onToolOpenChange={(id, open) => setToolOpen(id, open)}
                  onSizeChange={scroller.measureTimeline}
                />
              </div>
            </div>
          </TimelineRowFrame>
        )
      }
      case "ToolRun": {
        const toolRunRow = row as Accessor<TimelineRowByTag<"ToolRun">>
        const turnMemos = () => turnMemosFor(toolRunRow().userMessageID)
        return (
          <TimelineRowFrame row={toolRunRow} anchorId={props.anchor} centered={props.centered}>
            <div data-slot="session-turn-message-container" class="w-full">
              <Show when={!toolRunRow().previousAssistantPart}>{turnMemos()?.label()}</Show>
              <div
                data-slot="session-turn-assistant-content"
                aria-busy={turnMemos()?.working() || undefined}
              >
                <TimelineToolRun
                  row={toolRunRow}
                  copyPartID={turnMemos()?.copyPartID()}
                  durationMs={turnMemos()?.durationMs()}
                  getMessage={(id) => messageByID().get(id)}
                  getPart={getMsgPart}
                  shellExpanded={settings.general.shellToolPartsExpanded()}
                  editExpanded={settings.general.editToolPartsExpanded()}
                  toolOpen={toolOpen}
                  onToolOpenChange={(id, open) => setToolOpen(id, open)}
                  onSizeChange={scroller.measureTimeline}
                />
              </div>
            </div>
          </TimelineRowFrame>
        )
      }
      case "Thinking": {
        const thinkingRow = row as Accessor<TimelineRowByTag<"Thinking">>
        return (
          <TimelineRowFrame row={thinkingRow} anchorId={props.anchor} centered={props.centered}>
            <div data-slot="session-turn-message-container" class="w-full">
              <TimelineThinkingRow
                reasoningHeading={thinkingRow().reasoningHeading}
                showReasoningSummaries={settings.general.showReasoningSummaries()}
              />
            </div>
          </TimelineRowFrame>
        )
      }
      case "Retry": {
        const retryRow = row as Accessor<TimelineRowByTag<"Retry">>
        return (
          <TimelineRowFrame row={retryRow} anchorId={props.anchor} centered={props.centered}>
            <div data-slot="session-turn-message-container" class="w-full">
              <SessionRetry status={sessionStatus()} show={activeMessageID() === retryRow().userMessageID} />
            </div>
          </TimelineRowFrame>
        )
      }
      case "DiffSummary": {
        const diffSummaryRow = row as Accessor<TimelineRowByTag<"DiffSummary">>
        return (
          <TimelineRowFrame row={diffSummaryRow} anchorId={props.anchor} centered={props.centered}>
            <div data-slot="session-turn-message-container" class="w-full">
              <TimelineDiffSummaryRow diffs={diffSummaryRow().diffs} />
            </div>
          </TimelineRowFrame>
        )
      }
      case "Error": {
        const errorRow = row as Accessor<TimelineRowByTag<"Error">>
        return (
          <TimelineRowFrame row={errorRow} anchorId={props.anchor} centered={props.centered}>
            <div data-slot="session-turn-message-container" class="w-full">
              <StreamErrorCard
                error={errorRow().error}
                text={errorRow().text}
                retrying={working() || retrying()}
                onRetry={() => void retryFailedTurn(errorRow().userMessageID)}
              />
            </div>
          </TimelineRowFrame>
        )
      }
      case "BottomSpacer":
        return <div data-timeline-row="bottom-spacer" aria-hidden="true" class="h-12" />
    }
  }

  function TimelineRowView(props: { row: TimelineRow.TimelineRow }) {
    return renderTimelineRow(() => props.row)
  }

  return (
    <div class="relative w-full h-full min-w-0">
      <div
        class="absolute left-1/2 -translate-x-1/2 bottom-6 z-floating pointer-events-none transition-all duration-200 ease-out"
        classList={{
          "opacity-100 translate-y-0 scale-100": scrollButtonVisible(),
          "opacity-0 translate-y-2 scale-95": !scrollButtonVisible(),
        }}
        aria-hidden={!scrollButtonVisible()}
        inert={!scrollButtonVisible()}
      >
        <button
          type="button"
          aria-label={language.t("session.scrollToBottom")}
          tabIndex={scrollButtonVisible() ? 0 : -1}
          class="pointer-events-auto flex items-center justify-center w-11 h-11 bg-transparent border-none cursor-pointer p-0 group"
          onClick={props.onResumeScroll}
        >
          <div
            class="flex items-center justify-center w-8 h-6 rounded border border-border-weaker-base bg-surface-raised-stronger-non-alpha shadow-popover transition-colors group-hover:border-[var(--border-weak-base)] group-hover:[--icon-base:var(--icon-hover)]"
          >
            <Icon name="arrow-down-to-line" size="small" />
          </div>
        </button>
      </div>
      <ScrollView
        viewportRef={scroller.bindListRoot}
        onWheel={scroller.handleListWheel}
        onTouchStart={scroller.handleListTouchStart}
        onTouchMove={scroller.handleListTouchMove}
        onTouchEnd={scroller.handleListTouchEnd}
        onTouchCancel={scroller.handleListTouchEnd}
        onPointerDown={scroller.handleListPointerDown}
        onScroll={scroller.handleListScroll}
        onClick={props.onAutoScrollInteraction}
        class="relative min-w-0 w-full h-full"
        style={{
          "--sticky-accordion-top": showHeader() ? "48px" : "0px",
        }}
      >
        <Show when={workingStatus() !== "hidden" && settings.general.showSessionProgressBar()}>
          <div data-component="session-progress" data-state={workingStatus()} aria-hidden="true" class="sticky top-0 z-30 w-full">
            <div
              data-component="session-progress-bar"
              style={{
                background: tint() ?? "var(--icon-interactive-base)",
                animation: `session-progress-whip ${bar.ms}ms infinite`,
              }}
            />
          </div>
        </Show>

        <Show when={scroller.scrollRoot()}>
          {(root) => (
            <Virtualizer
              data={timelineRows()}
              cache={virtualCache()}
              itemSize={virtualCache() ? undefined : timelineFallbackItemSize}
              scrollRef={root()}
              shift={props.historyShift}
              keepMounted={keepMounted()}
              startMargin={64}
              ref={(handle) => scroller.connectVirtualizer(handle, root())}
            >
              {(row) => <TimelineRowView row={row} />}
            </Virtualizer>
          )}
        </Show>
      </ScrollView>
      
      <div aria-live="polite" class="sr-only">
        <Show when={workingStatus() !== "hidden"}>
          {language.t("session.status.working") || "Assistant is working..."}
        </Show>
      </div>
    </div>
  )
}




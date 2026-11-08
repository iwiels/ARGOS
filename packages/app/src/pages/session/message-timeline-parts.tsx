import { Index, Show, createMemo, type Accessor, type JSX } from "solid-js"
import {
  ContextToolGroup,
  Message,
  MessageDivider,
  Part as MessagePart,
  partDefaultOpen,
  type UserActions,
} from "@argos/ui/message-part"
import { FileIcon } from "@argos/ui/file-icon"
import type { Message as MessageType, Part as PartType, ToolPart, UserMessage } from "@argos/sdk/client"
import { getFilename } from "@/core/path"
import { MessageComment, TimelineRow, TimelineRowMap } from "./message-timeline.data"
import { ToolRunGroup, type ToolRunItem } from "./tool-run"

const emptyTools: ToolPart[] = []

export type FramedTimelineRow = Exclude<TimelineRow.TimelineRow, { _tag: "BottomSpacer" }>
export type TimelineRowByTag<T extends TimelineRow.TimelineRow["_tag"]> = Extract<TimelineRow.TimelineRow, { _tag: T }>

type FrameProps = {
  anchorId: (id: string) => string
  centered: boolean
}

export function TimelineRowFrame(input: {
  row: Accessor<FramedTimelineRow>
  anchorId: (id: string) => string
  centered: boolean
  children: JSX.Element
}) {
  const anchor = () => {
    const row = input.row()
    return row._tag === "CommentStrip" || (row._tag === "UserMessage" && row.anchor)
  }
  const previousUserMessage = () => {
    const row = input.row()
    return (row._tag === "CommentStrip" || row._tag === "UserMessage") && row.previousUserMessage
  }

  return (
    <div
      id={anchor() ? input.anchorId(input.row().userMessageID) : undefined}
      data-message-id={input.row().userMessageID}
      data-timeline-row={input.row()._tag}
      classList={{
        "min-w-0 w-full max-w-full px-4 md:px-5": true,
        "py-3.5": input.row()._tag !== "ToolRun",
        "py-2.5": input.row()._tag === "ToolRun",
        "md:max-w-200 2xl:max-w-250": input.centered,
        "md:mx-auto": input.centered,
        "pt-7": previousUserMessage(),
      }}
    >
      <div data-component="session-turn" class="min-w-0 w-full relative" style={{ height: "auto" }}>
        {input.children}
      </div>
    </div>
  )
}

export function TimelineCommentStrip(props: {
  row: Accessor<TimelineRowByTag<"CommentStrip">>
  getParts: (messageID: string) => PartType[]
} & FrameProps) {
  const comments = createMemo(() =>
    props.getParts(props.row().userMessageID).flatMap((part) => MessageComment.fromPart(part) ?? []),
  )
  return (
    <TimelineRowFrame row={props.row} anchorId={props.anchorId} centered={props.centered}>
      <div class="w-full pb-2">
        <div class="ml-auto max-w-[82%] overflow-x-auto no-scrollbar">
          <div class="flex w-max min-w-full justify-end gap-2">
            <Index each={comments()}>
              {(comment) => (
                <div class="shrink-0 max-w-65 rounded-md border border-border-weak-base bg-bg-elevated px-2.5 py-2">
                  <div class="flex items-center gap-1.5 min-w-0 text-11-medium text-text-strong">
                    <FileIcon node={{ path: comment().path, type: "file" }} class="size-3.5 shrink-0" />
                    <span class="truncate">{getFilename(comment().path)}</span>
                    <Show when={comment().selection}>
                      {(selection) => (
                        <span class="shrink-0 text-text-weak">
                          {selection().startLine === selection().endLine
                            ? `:${selection().startLine}`
                            : `:${selection().startLine}-${selection().endLine}`}
                        </span>
                      )}
                    </Show>
                  </div>
                  <div class="pt-1 text-12-regular text-text-strong whitespace-pre-wrap break-words">
                    {comment().comment}
                  </div>
                </div>
              )}
            </Index>
          </div>
        </div>
      </div>
    </TimelineRowFrame>
  )
}

export function TimelineUserMessage(props: {
  row: Accessor<TimelineRowByTag<"UserMessage">>
  getMessage: (id: string) => MessageType | undefined
  getParts: (messageID: string) => PartType[]
  actions?: UserActions
} & FrameProps) {
  const message = createMemo(() => {
    const m = props.getMessage(props.row().userMessageID)
    if (m?.role === "user") return m
  })
  return (
    <TimelineRowFrame row={props.row} anchorId={props.anchorId} centered={props.centered}>
      <Show when={message()}>
        {(message) => (
          <div data-slot="session-turn-message-container" class="w-full">
            <div data-slot="session-turn-message-content">
              <Message message={message()} parts={props.getParts(props.row().userMessageID)} actions={props.actions} />
            </div>
          </div>
        )}
      </Show>
    </TimelineRowFrame>
  )
}

export function TimelineTurnDivider(props: { row: Accessor<TimelineRowByTag<"TurnDivider">>; label: string } & FrameProps) {
  return (
    <TimelineRowFrame row={props.row} anchorId={props.anchorId} centered={props.centered}>
      <div data-slot="session-turn-message-container" class="w-full px-4 md:px-5">
        <div data-slot="session-turn-compaction">
          <MessageDivider label={props.label} />
        </div>
      </div>
    </TimelineRowFrame>
  )
}

export function TimelineAssistantPartGroup(props: {
  row: Accessor<TimelineRowMap["AssistantPart"]>
  busy: boolean
  copyPartID: string | null | undefined
  durationMs: number | undefined
  getMessage: (messageID: string) => MessageType | undefined
  getPart: (messageID: string, partID: string) => PartType | undefined
  shellExpanded: boolean
  editExpanded: boolean
  toolOpen: Record<string, boolean | undefined>
  onToolOpenChange: (partID: string, open: boolean) => void
  onSizeChange: () => void
}) {
  if (props.row().group.type === "context") {
    const parts = createMemo(() => {
      const group = props.row().group
      if (group.type !== "context") return emptyTools
      return group.refs
        .map((ref) => props.getPart(ref.messageID, ref.partID))
        .filter((part): part is ToolPart => part?.type === "tool")
    })

    return (
      <ContextToolGroup parts={parts()} busy={props.busy} onSizeChange={props.onSizeChange} />
    )
  }

  const message = createMemo(() => {
    const group = props.row().group
    if (group.type !== "part") return
    return props.getMessage(group.ref.messageID)
  })
  const part = createMemo(() => {
    const group = props.row().group
    if (group.type !== "part") return
    return props.getPart(group.ref.messageID, group.ref.partID)
  })
  const defaultOpen = createMemo(() => {
    const item = part()
    if (!item) return
    return partDefaultOpen(item, props.shellExpanded, props.editExpanded)
  })

  return (
    <Show when={message()}>
      {(message) => (
        <Show when={part()}>
          {(part) => (
            <MessagePart
              part={part()}
              message={message()}
              showAssistantCopyPartID={props.copyPartID}
              turnDurationMs={props.durationMs}
              defaultOpen={defaultOpen()}
              toolOpen={props.toolOpen[part().id] ?? defaultOpen()}
              onToolOpenChange={(open) => props.onToolOpenChange(part().id, open)}
              deferToolContent={false}
              virtualizeDiff={true}
            />
          )}
        </Show>
      )}
    </Show>
  )
}

export function TimelineToolRun(props: {
  row: Accessor<TimelineRowByTag<"ToolRun">>
  copyPartID: string | null | undefined
  durationMs: number | undefined
  getMessage: (messageID: string) => MessageType | undefined
  getPart: (messageID: string, partID: string) => PartType | undefined
  shellExpanded: boolean
  editExpanded: boolean
  toolOpen: Record<string, boolean | undefined>
  onToolOpenChange: (partID: string, open: boolean) => void
  onSizeChange: () => void
}) {
  const items = createMemo<ToolRunItem[]>(() =>
    props
      .row()
      .refs.map((ref) => {
        const part = props.getPart(ref.messageID, ref.partID)
        if (part?.type !== "tool") return
        return {
          part,
          message: props.getMessage(ref.messageID),
        } as ToolRunItem
      })
      .filter((item): item is ToolRunItem => !!item),
  )

  return (
    <ToolRunGroup
      tool={props.row().tool}
      items={items()}
      onSizeChange={props.onSizeChange}
      renderPart={(item) => (
        <Show when={item.message}>
          {(message) => (
            <MessagePart
              part={item.part}
              message={message()}
              showAssistantCopyPartID={props.copyPartID}
              turnDurationMs={props.durationMs}
              defaultOpen={partDefaultOpen(item.part, props.shellExpanded, props.editExpanded)}
              toolOpen={props.toolOpen[item.part.id]}
              onToolOpenChange={(open) => props.onToolOpenChange(item.part.id, open)}
              deferToolContent={false}
              virtualizeDiff={true}
            />
          )}
        </Show>
      )}
    />
  )
}

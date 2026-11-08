import { parseCommentNote, readCommentMetadata } from "@/utils/comment-note"
import { AssistantMessage, Part, SessionStatus, SnapshotFileDiff, UserMessage } from "@argos/sdk/client"

export type TimelineMessageError = Exclude<AssistantMessage["error"], { name: "MessageAbortedError" }>
import { groupParts, PartGroup, PartRef, renderable } from "@argos/ui/message-part"
import { Data, Equal } from "effect"
import { errorRowFor, reasoningHeading } from "./message-timeline-helpers"

export type SummaryDiff = SnapshotFileDiff & { file: string }

export type TimelineRowMap = {
  CommentStrip: {
    userMessageID: string
    previousUserMessage: boolean
  }
  UserMessage: {
    userMessageID: string
    anchor: boolean
    previousUserMessage: boolean
  }
  TurnDivider: {
    userMessageID: string
    label: "compaction" | "interrupted"
  }
  AssistantPart: {
    userMessageID: string
    group: PartGroup
    previousAssistantPart: boolean
  }
  ToolRun: {
    userMessageID: string
    tool: string
    refs: PartRef[]
    previousAssistantPart: boolean
  }
  Thinking: { userMessageID: string; reasoningHeading?: string }
  Retry: { userMessageID: string }
  DiffSummary: { userMessageID: string; diffs: SummaryDiff[] }
  Error: { userMessageID: string; text: string; error: TimelineMessageError | undefined }
  BottomSpacer: {}
}

export namespace TimelineRow {
  export class CommentStrip extends Data.TaggedClass("CommentStrip")<{
    userMessageID: string
    previousUserMessage: boolean
  }> {}
  export class UserMessage extends Data.TaggedClass("UserMessage")<{
    userMessageID: string
    anchor: boolean
    previousUserMessage: boolean
  }> {}
  export class TurnDivider extends Data.TaggedClass("TurnDivider")<{
    userMessageID: string
    label: "compaction" | "interrupted"
  }> {}
  export class AssistantPart extends Data.TaggedClass("AssistantPart")<{
    userMessageID: string
    group: PartGroup
    previousAssistantPart: boolean
  }> {}
  export class ToolRun extends Data.TaggedClass("ToolRun")<{
    userMessageID: string
    tool: string
    refs: PartRef[]
    previousAssistantPart: boolean
  }> {}
  export class Thinking extends Data.TaggedClass("Thinking")<{
    userMessageID: string
    reasoningHeading?: string
  }> {}
  export class DiffSummary extends Data.TaggedClass("DiffSummary")<{
    userMessageID: string
    diffs: SummaryDiff[]
  }> {}
  export class Error extends Data.TaggedClass("Error")<{
    userMessageID: string
    text: string
    error: TimelineMessageError | undefined
  }> {}
  export class Retry extends Data.TaggedClass("Retry")<{
    userMessageID: string
  }> {}
  export class BottomSpacer extends Data.TaggedClass("BottomSpacer")<{}> {}

  export type TimelineRow =
    | CommentStrip
    | UserMessage
    | TurnDivider
    | AssistantPart
    | ToolRun
    | Thinking
    | DiffSummary
    | Error
    | Retry
    | BottomSpacer

  export const key = (row: TimelineRow) => {
    switch (row._tag) {
      case "CommentStrip":
        return `comment-strip:${row.userMessageID}`
      case "UserMessage":
        return `user-message:${row.userMessageID}`
      case "TurnDivider":
        return `turn-divider:${row.userMessageID}:${row.label}`
      case "AssistantPart":
        return `assistant-part:${row.userMessageID}:${row.group.key}`
      case "ToolRun":
        return `tool-run:${row.userMessageID}:${row.tool}:${row.refs
          .map((ref) => `${ref.messageID}:${ref.partID}`)
          .join(",")}`
      case "Thinking":
        return `thinking:${row.userMessageID}`
      case "DiffSummary":
        return `diff-summary:${row.userMessageID}`
      case "Error":
        return `error:${row.userMessageID}`
      case "Retry":
        return `retry:${row.userMessageID}`
      case "BottomSpacer":
        return "bottom-spacer"
    }
  }

  export function equals(a: TimelineRow, b: TimelineRow) {
    return Equal.equals(a, b)
  }
}

export namespace Timeline {
  export function constructMessageRows(
    userMessage: UserMessage,
    getMessageParts: (messageID: string) => Part[],
    assistantMessages: AssistantMessage[],
    index: number,
    showReasoning: boolean,
    status: SessionStatus["type"],
    isActive: boolean,
  ) {
    const rows: TimelineRow.TimelineRow[] = []

    const previousUserMessage = index > 0
    const userParts = getMessageParts(userMessage.id)
    const comments = userParts.flatMap((p) => MessageComment.fromPart(p) ?? [])
    const compaction = userParts.some((p) => p.type === "compaction")
    const interruptedMessageIndex = assistantMessages.findIndex((m) => m.error?.name === "MessageAbortedError")
    const interrupted = interruptedMessageIndex !== -1
    const error = assistantMessages.find(
      (m): m is AssistantMessage & { error: TimelineMessageError } =>
        m.error !== undefined && m.error.name !== "MessageAbortedError",
    )?.error

    const assistantPartRefs = assistantMessages.flatMap((message, messageIndex) =>
      getMessageParts(message.id)
        .filter((part) => renderable(part, showReasoning))
        .map((part) => ({ messageID: message.id, messageIndex, part })),
    )
    const assistantItems =
      interrupted && !compaction
        ? [
            ...groupParts(assistantPartRefs.filter((ref) => ref.messageIndex <= interruptedMessageIndex)).map(
              (group) => ({
                type: "part" as const,
                group,
              }),
            ),
            { type: "interrupted" as const },
            ...groupParts(assistantPartRefs.filter((ref) => ref.messageIndex > interruptedMessageIndex)).map(
              (group) => ({
                type: "part" as const,
                group,
              }),
            ),
          ]
        : groupParts(assistantPartRefs).map((group) => ({ type: "part" as const, group }))
    if (comments.length > 0)
      rows.push(
        new TimelineRow.CommentStrip({
          userMessageID: userMessage.id,
          previousUserMessage,
        }),
      )

    rows.push(
      new TimelineRow.UserMessage({
        userMessageID: userMessage.id,
        anchor: comments.length === 0,
        previousUserMessage: comments.length === 0 && previousUserMessage,
      }),
    )

    if (compaction) {
      rows.push(
        new TimelineRow.TurnDivider({
          userMessageID: userMessage.id,
          label: "compaction",
        }),
      )
    }

    let assistantGroupIndex = 0
    let run: { tool: string; refs: PartRef[]; group: PartGroup } | undefined

    const pushPart = (group: PartGroup) => {
      rows.push(
        new TimelineRow.AssistantPart({
          userMessageID: userMessage.id,
          group,
          previousAssistantPart: assistantGroupIndex > 0,
        }),
      )
      assistantGroupIndex += 1
    }

    const flushRun = () => {
      if (!run) return
      // A single isolated tool call keeps the regular one-click AssistantPart
      // treatment (respects partDefaultOpen and the e2e row contract); only
      // actual runs of 2+ consecutive same-tool calls get grouped.
      if (run.refs.length === 1) {
        pushPart(run.group)
      } else {
        rows.push(
          new TimelineRow.ToolRun({
            userMessageID: userMessage.id,
            tool: run.tool,
            refs: run.refs,
            previousAssistantPart: assistantGroupIndex > 0,
          }),
        )
        assistantGroupIndex += 1
      }
      run = undefined
    }

    assistantItems.forEach((item) => {
      if (item.type === "interrupted") {
        flushRun()
        rows.push(
          new TimelineRow.TurnDivider({
            userMessageID: userMessage.id,
            label: "interrupted",
          }),
        )
        return
      }

      const group = item.group
      if (group.type === "context") {
        flushRun()
        pushPart(group)
        return
      }

      const part = getMessageParts(group.ref.messageID).find((p) => p.id === group.ref.partID)
      const ref = { messageID: group.ref.messageID, partID: group.ref.partID }
      if (part?.type === "tool") {
        if (run && run.tool === part.tool) {
          run.refs.push(ref)
          return
        }
        flushRun()
        run = { tool: part.tool, refs: [ref], group }
        return
      }

      flushRun()
      pushPart(group)
    })
    flushRun()

    if (isActive && status === "busy" && !error && (showReasoning ? assistantPartRefs.length === 0 : true)) {
      const heading = assistantMessages
        .flatMap((message) => getMessageParts(message.id))
        .map((part) => (part.type === "reasoning" && part.text ? reasoningHeading(part.text) : undefined))
        .find((value): value is string => !!value)

      rows.push(
        new TimelineRow.Thinking({
          userMessageID: userMessage.id,
          reasoningHeading: heading,
        }),
      )
    }

    if (isActive && status === "retry") rows.push(new TimelineRow.Retry({ userMessageID: userMessage.id }))

    const diffs = (userMessage.summary?.diffs ?? [])
      .reduceRight<SummaryDiff[]>((result, diff) => {
        if (!isSummaryDiff(diff)) return result
        if (result.some((item) => item.file === diff.file)) return result
        result.push(diff)
        return result
      }, [])
      .reverse()
    if (diffs.length > 0 && (status === "idle" || !isActive)) {
      rows.push(
        new TimelineRow.DiffSummary({
          userMessageID: userMessage.id,
          diffs,
        }),
      )
    }

    if (error) {
      const row = errorRowFor(error)
      if (row) {
        rows.push(
          new TimelineRow.Error({
            userMessageID: userMessage.id,
            ...row,
          }),
        )
      }
    }

    return rows
  }

  function isSummaryDiff(value: SnapshotFileDiff): value is SummaryDiff {
    return typeof value.file === "string"
  }
}

export namespace MessageComment {
  export type MessageComment = {
    path: string
    comment: string
    selection?: {
      startLine: number
      endLine: number
    }
  }

  export const fromPart = (part: Part): MessageComment | undefined => {
    if (part.type !== "text" || !part.synthetic) return
    const next = readCommentMetadata(part.metadata) ?? parseCommentNote(part.text)
    if (!next) return
    return {
      path: next.path,
      comment: next.comment,
      selection: next.selection
        ? {
            startLine: next.selection.startLine,
            endLine: next.selection.endLine,
          }
        : undefined,
    }
  }
}



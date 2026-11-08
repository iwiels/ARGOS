/**
 * Self-contained row components for the session timeline.
 * Extracted verbatim from message-timeline.tsx (C1 split).
 */
import { createMemo, For, Show } from "solid-js"
import { createStore } from "solid-js/store"
import { Dynamic } from "solid-js/web"
import { Accordion } from "@argos/ui/accordion"
import { DiffChanges } from "@argos/ui/diff-changes"
import { Icon } from "@argos/ui/icon"
import { ThinkingOrb } from "@argos/ui/thinking-orb"
import { StickyAccordionHeader } from "@argos/ui/sticky-accordion-header"
import { TextReveal } from "@argos/ui/text-reveal"
import { TextShimmer } from "@argos/ui/text-shimmer"
import { normalize } from "@argos/ui/session-diff"
import { useFileComponent } from "@argos/ui/context/file"
import { getDirectory, getFilename } from "@/core/path"
import { useLanguage } from "@/context/language"
import type { SummaryDiff } from "./message-timeline.data"

export function TimelineThinkingRow(props: { reasoningHeading?: string; showReasoningSummaries: boolean }) {
  const language = useLanguage()

  return (
    <div data-slot="session-turn-thinking" class="flex items-center gap-2">
      <ThinkingOrb state="working" size={16} theme="dark" class="shrink-0" />
      <TextShimmer text={language.t("ui.sessionTurn.status.thinking")} />
      <Show when={!props.showReasoningSummaries}>
        <TextReveal text={props.reasoningHeading} class="session-turn-thinking-heading" travel={25} duration={700} />
      </Show>
    </div>
  )
}

export function TurnLabel(props: { color?: string; name?: string; durationMs?: number }) {
  const duration = createMemo(() => {
    const ms = props.durationMs
    if (typeof ms !== "number" || ms < 0) return
    const total = Math.round(ms / 1000)
    if (total < 60) return `${total}s`
    return `${Math.floor(total / 60)}m ${total % 60}s`
  })

  return (
    <div data-component="session-turn-label">
      <span
        data-slot="turn-label-dot"
        style={{ background: props.color ?? "var(--icon-interactive-base)" }}
        aria-hidden="true"
      />
      <Show when={props.name}>
        <span data-slot="turn-label-agent">{props.name}</span>
      </Show>
      <Show when={duration()}>
        <span data-slot="turn-label-duration">{duration()}</span>
      </Show>
    </div>
  )
}

export function TimelineDiffSummaryRow(props: { diffs: SummaryDiff[] }) {
  const language = useLanguage()
  const maxFiles = 10
  const [state, setState] = createStore({
    showAll: false,
    expanded: [] as string[],
  })
  const showAll = () => state.showAll
  const expanded = () => state.expanded
  const overflow = createMemo(() => Math.max(0, props.diffs.length - maxFiles))
  const visible = createMemo(() => (showAll() ? props.diffs : props.diffs.slice(0, maxFiles)))

  return (
    <div
      data-slot="session-turn-diffs"
      data-component="session-turn-diffs-group"
      data-show-all={showAll() || undefined}
    >
      <div data-slot="session-turn-diffs-header">
        <span data-slot="session-turn-diffs-label">
          {props.diffs.length} {language.t("ui.sessionTurn.diffs.changed")}{" "}
          {language.t(props.diffs.length === 1 ? "ui.common.file.one" : "ui.common.file.other")}
        </span>
        <DiffChanges changes={props.diffs} />
        <Show when={overflow() > 0}>
          <button
            type="button"
            data-slot="session-turn-diffs-toggle"
            onClick={() => setState("showAll", !showAll())}
          >
            {showAll() ? language.t("ui.sessionTurn.diffs.showLess") : language.t("ui.sessionTurn.diffs.showAll")}
          </button>
        </Show>
      </div>
      <div data-component="session-turn-diffs-content">
        <Accordion
          multiple
          style={{ "--sticky-accordion-offset": "44px" }}
          value={expanded()}
          onChange={(value) => setState("expanded", Array.isArray(value) ? value : value ? [value] : [])}
        >
          <For each={visible()}>
            {(diff) => {
              const opened = createMemo(() => expanded().includes(diff.file))

              return (
                <Accordion.Item value={diff.file}>
                  <StickyAccordionHeader>
                    <Accordion.Trigger>
                      <div data-slot="session-turn-diff-trigger">
                        <span data-slot="session-turn-diff-path">
                          <Show when={diff.file.includes("/")}>
                            <span data-slot="session-turn-diff-directory">{`\u202A${getDirectory(diff.file)}\u202C`}</span>
                          </Show>
                          <span data-slot="session-turn-diff-filename">{getFilename(diff.file)}</span>
                        </span>
                        <div data-slot="session-turn-diff-meta">
                          <span data-slot="session-turn-diff-changes">
                            <DiffChanges changes={diff} />
                          </span>
                          <span data-slot="session-turn-diff-chevron">
                            <Icon name="chevron-down" size="small" />
                          </span>
                        </div>
                      </div>
                    </Accordion.Trigger>
                  </StickyAccordionHeader>
                  <Accordion.Content>
                    <Show when={opened()}>
                      <TimelineDiffView diff={diff} />
                    </Show>
                  </Accordion.Content>
                </Accordion.Item>
              )
            }}
          </For>
        </Accordion>
        <Show when={!showAll() && overflow() > 0}>
          <button
            type="button"
            data-slot="session-turn-diffs-more"
            onClick={() => setState("showAll", true)}
          >
            {language.t("ui.sessionTurn.diffs.more", { count: String(overflow()) })}
          </button>
        </Show>
      </div>
    </div>
  )
}

export function TimelineDiffView(props: { diff: SummaryDiff }) {
  const fileComponent = useFileComponent()
  const view = normalize(props.diff)

  return (
    <div data-slot="session-turn-diff-view" data-scrollable>
      <Dynamic component={fileComponent} mode="diff" virtualize={true} fileDiff={view.fileDiff} />
    </div>
  )
}

import { createMemo, Show } from "solid-js"
import { Button } from "@argos/ui/button"
import { Callout, CalloutActions, CalloutDescription, CalloutTitle } from "@argos/ui/card"
import { Icon } from "@argos/ui/icon"
import { useLanguage } from "@/context/language"
import { resolveStreamErrorKind, type StreamErrorKind } from "./message-timeline-helpers"

const COPY: Record<StreamErrorKind, { title: string; description: string }> = {
  queueFull: {
    title: "errors.streaming.queueFull.title",
    description: "errors.streaming.queueFull.description",
  },
  rateLimit: {
    title: "errors.streaming.rateLimit.title",
    description: "errors.streaming.rateLimit.description",
  },
  server: {
    title: "errors.streaming.server.title",
    description: "errors.streaming.server.description",
  },
  auth: {
    title: "errors.streaming.auth.title",
    description: "errors.streaming.auth.description",
  },
  contextOverflow: {
    title: "errors.streaming.contextOverflow.title",
    description: "errors.streaming.contextOverflow.description",
  },
  structuredOutput: {
    title: "errors.streaming.structuredOutput.title",
    description: "errors.streaming.structuredOutput.description",
  },
  generic: {
    title: "errors.streaming.generic.title",
    description: "errors.streaming.generic.description",
  },
}

export function StreamErrorCard(props: {
  error: unknown
  text: string
  retrying: boolean
  onRetry?: () => void
}) {
  const language = useLanguage()
  const meta = createMemo(() => resolveStreamErrorKind(props.error))
  const copy = createMemo(() => COPY[meta().kind])
  const showRetry = createMemo(() => meta().retryable && !!props.onRetry)
  const t = (key: string) => language.t(key as Parameters<typeof language.t>[0])

  return (
    <Callout class="stream-error-card rounded-lg border border-border-weaker-base bg-bg-surface p-3.5" data-component="stream-error-card">
      <div class="flex flex-col gap-2 min-w-0">
        <div class="flex items-center gap-2 font-medium text-12-regular text-text-primary">
          <Icon name="warning" class="size-3.5 shrink-0 text-text-secondary" />
          <span>{t(copy().title)}</span>
        </div>
        <CalloutDescription class="pl-5.5 text-12-regular text-text-secondary">{t(copy().description)}</CalloutDescription>
        <Show when={props.text}>
          <details data-slot="stream-error-details" class="ml-5.5 rounded-md border border-border-weaker-base bg-bg-surface p-2.5 text-10-mono">
            <summary class="cursor-pointer select-none text-text-secondary outline-none hover:text-text-primary">
              {t("errors.streaming.details")}
            </summary>
            <pre class="mt-2 max-h-40 overflow-auto whitespace-pre-wrap break-words text-10-mono text-text-secondary">
              {props.text}
            </pre>
          </details>
        </Show>
        <Show when={showRetry()}>
          <CalloutActions class="mt-1 pl-5.5">
            <Button
              type="button"
              variant="secondary"
              size="small"
              disabled={props.retrying}
              onClick={props.onRetry}
            >
              {props.retrying ? t("errors.streaming.retrying") : t("errors.streaming.retry")}
            </Button>
          </CalloutActions>
        </Show>
      </div>
    </Callout>
  )
}

import { For, Show } from "solid-js"
import type { PermissionRequest } from "@argos/sdk/client"
import { Button } from "@argos/ui/button"
import { DockPrompt } from "@argos/ui/dock-prompt"
import { Icon } from "@argos/ui/icon"
import { useLanguage } from "@/context/language"

export function SessionPermissionDock(props: {
  request: PermissionRequest
  responding: boolean
  onDecide: (response: "once" | "always" | "reject") => void
}) {
  const language = useLanguage()

  const toolDescription = () => {
    const permission = props.request.permission
    const key = `settings.permissions.tool.${permission}.description`
    const value = language.t(key as Parameters<typeof language.t>[0])
    if (value === key) return permission
    return value
  }

  return (
    <DockPrompt
      kind="permission"
      header={
        <div data-slot="permission-row" data-variant="header">
          <span data-slot="permission-icon">
            <Icon name="shield" size="small" />
          </span>
          <div data-slot="permission-header-title">{language.t("notification.permission.title")}</div>
        </div>
      }
      footer={
        <>
          <div />
          <div data-slot="permission-footer-actions">
            <Button variant="ghost" size="normal" onClick={() => props.onDecide("reject")} disabled={props.responding}>
              {language.t("ui.permission.deny")}
            </Button>
            <Button
              variant="secondary"
              size="normal"
              onClick={() => props.onDecide("always")}
              disabled={props.responding}
            >
              {language.t("ui.permission.allowAlways")}
            </Button>
            <Button variant="contrast" size="normal" onClick={() => props.onDecide("once")} disabled={props.responding}>
              {language.t("ui.permission.allowOnce")}
            </Button>
          </div>
        </>
      }
    >
      <Show when={toolDescription()}>
        <div data-slot="permission-row">
          <span data-slot="permission-spacer" aria-hidden="true" />
          <div data-slot="permission-hint">{toolDescription()}</div>
        </div>
      </Show>

      <Show when={props.request.patterns.some((pattern) => pattern !== "*")}>
        <div data-slot="permission-row">
          <span data-slot="permission-spacer" aria-hidden="true" />
          <div data-slot="permission-patterns">
            <For each={props.request.patterns.filter((pattern) => pattern !== "*")}>
              {(pattern) => (
                <div class="flex items-start gap-2 font-mono text-12-regular text-text-primary">
                  <span class="text-text-tertiary select-none font-mono">$</span>
                  <code class="font-mono text-12-regular text-text-primary break-all">{pattern}</code>
                </div>
              )}
            </For>
          </div>
        </div>
      </Show>
    </DockPrompt>
  )
}



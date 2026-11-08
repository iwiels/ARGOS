import { Show } from "solid-js"
import { Dialog } from "@argos/ui/dialog"
import { Button } from "@argos/ui/button"
import { useDialog } from "@argos/ui/context/dialog"
import { useLanguage } from "@/context/language"

/**
 * Confirmation gate for argos:// new-session deep links that carry a
 * prompt: the OS "open this app?" dialog does not cover what happens after,
 * and silently pre-seeding an AI prompt into an arbitrary directory is a
 * social-engineering vector.
 */
export function DialogDeepLinkConfirm(props: { directory: string; prompt?: string; onConfirm: () => void }) {
  const dialog = useDialog()
  const language = useLanguage()

  const accept = () => {
    dialog.close()
    props.onConfirm()
  }

  return (
    <Dialog title={language.t("deeplink.confirm.title")} fit>
      <div class="flex flex-col gap-4 pl-6 pr-2.5 pb-3">
        <span class="text-14-regular text-text-primary">
          {language.t("deeplink.confirm.body", { directory: props.directory })}
        </span>
        <Show when={props.prompt} keyed>
          {(prompt) => (
            <span class="text-12-regular text-text-secondary break-all">
              {language.t("deeplink.confirm.prompt", { prompt })}
            </span>
          )}
        </Show>
        <div class="flex justify-end gap-2">
          <Button variant="ghost" size="large" onClick={() => dialog.close()}>
            {language.t("common.cancel")}
          </Button>
          <Button variant="primary" size="large" onClick={accept}>
            {language.t("common.open")}
          </Button>
        </div>
      </div>
    </Dialog>
  )
}

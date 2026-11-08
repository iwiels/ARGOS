import { Dialog } from "@argos/ui/dialog"
import { List } from "@argos/ui/list"
import { Show } from "solid-js"
import { useDialog } from "@argos/ui/context/dialog"
import type { CommandPaletteProps } from "@/context/command"
import { useLanguage } from "@/context/language"

export function DialogCommandPalette(props: CommandPaletteProps) {
  const dialog = useDialog()
  const language = useLanguage()

  const items = () =>
    props.options.filter(
      (option) =>
        !option.disabled && !option.hidden && !option.id.startsWith("suggested.") && option.id !== "file.open",
    )

  return (
    <Dialog title={language.t("command.palette")}>
      <List
        class="px-3"
        search={{ placeholder: language.t("palette.search.placeholder"), autofocus: true }}
        emptyMessage={language.t("palette.empty")}
        items={items}
        key={(item) => item.id}
        filterKeys={["title", "description", "category"]}
        groupBy={(item) => item.category ?? ""}
        onSelect={(item) => {
          if (!item) return
          dialog.close(() => props.trigger(item.id, "palette"))
        }}
      >
        {(item) => (
          <div class="flex w-full min-w-0 items-center justify-between gap-4 px-1">
            <div class="flex min-w-0 items-center gap-2">
              <span class="truncate text-14-regular text-text-strong">{item.title}</span>
              <Show when={item.description}>
                {(description) => <span class="truncate text-14-regular text-text-weak">{description()}</span>}
              </Show>
            </div>
            <Show when={item.keybind}>
              {(keybind) => (
                <span class="shrink-0 font-mono text-12-regular text-text-weak">
                  {props.keybind(item.id) || keybind()}
                </span>
              )}
            </Show>
          </div>
        )}
      </List>
    </Dialog>
  )
}

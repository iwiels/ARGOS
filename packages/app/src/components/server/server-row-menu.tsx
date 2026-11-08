import { Icon as IconV2 } from "@argos/ui/icon"
import { IconButton } from "@argos/ui/icon-button"
import { Menu } from "@argos/ui/menu"
import { type Component, Show } from "solid-js"
import { useServerManagementController } from "@/components/dialog-select-server"
import { useLanguage } from "@/context/language"
import { ServerConnection } from "@/context/server"

export const ServerRowMenu: Component<{
  server: ServerConnection.Any
  controller: ReturnType<typeof useServerManagementController>
  onEdit: (server: ServerConnection.Http) => void
  open?: boolean
  onOpenChange?: (open: boolean) => void
}> = (props) => {
  const language = useLanguage()
  const key = ServerConnection.key(props.server)
  const builtin = ServerConnection.builtin(props.server)
  const isDefault = () => props.controller.defaultKey() === key

  return (
    <Menu gutter={4} modal={false} placement="bottom-end" open={props.open} onOpenChange={props.onOpenChange}>
      <Menu.Trigger
        as={IconButton}
        variant="ghost-muted"
        size="small"
        icon={<IconV2 name="outline-dots" />}
        aria-label={language.t("common.moreOptions")}
      />
      <Menu.Portal>
        <Menu.Content>
          <Menu.Group>
            <Menu.GroupLabel>{language.t("settings.section.server")}</Menu.GroupLabel>
            <Menu.Item
              disabled={builtin || props.server.type !== "http"}
              onSelect={() => props.onEdit(props.server as ServerConnection.Http)}
            >
              {language.t("dialog.server.menu.edit")}
            </Menu.Item>
            <Show when={props.controller.canDefault() && !isDefault()}>
              <Menu.Item onSelect={() => props.controller.setDefault(key)}>
                {language.t("dialog.server.menu.default")}
              </Menu.Item>
            </Show>
            <Show when={props.controller.canDefault() && isDefault()}>
              <Menu.Item onSelect={() => props.controller.setDefault(null)}>
                {language.t("dialog.server.menu.defaultRemove")}
              </Menu.Item>
            </Show>
            <Menu.Separator />
            <Menu.Item disabled={builtin} onSelect={() => props.controller.handleRemove(key)}>
              {language.t("dialog.server.menu.delete")}
            </Menu.Item>
          </Menu.Group>
        </Menu.Content>
      </Menu.Portal>
    </Menu>
  )
}



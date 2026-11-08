import { useDialog } from "@argos/ui/context/dialog"
import { Tag } from "@argos/ui/tag"
import { Button } from "@argos/ui/button"
import { Dialog } from "@argos/ui/dialog"
import { Icon as IconV2 } from "@argos/ui/icon"
import { IconButton } from "@argos/ui/icon-button"
import { Menu } from "@argos/ui/menu"
import { useMutation } from "@tanstack/solid-query"
import fuzzysort from "fuzzysort"
import { type Accessor, For, Show, createMemo } from "solid-js"
import type { useServerManagementController } from "@/components/dialog-select-server"
import { ServerHealthIndicator } from "@/components/server/server-row"
import { useLanguage } from "@/context/language"
import { usePlatform } from "@/context/platform"
import { ServerConnection } from "@/context/server"
import { showToast } from "@/utils/toast"
import { DialogAddWslServer } from "./dialog-add-server"
import { useWslServers } from "./context"
import { wslOpencodeAction, wslRuntimeRetryable } from "./settings-model"

type Controller = ReturnType<typeof useServerManagementController>

export function isWslServer(server: ServerConnection.Any) {
  return server.type === "sidecar" && server.variant === "wsl"
}

export function WslAddServerButton() {
  const platform = usePlatform()
  const dialog = useDialog()
  const language = useLanguage()
  const openAdd = () => {
    void dialog.push(() => (
      <Dialog title={language.t("wsl.server.add")} size="large" fit class="settings-v2-wsl-dialog">
        <DialogAddWslServer />
      </Dialog>
    ))
  }
  return (
    <Show when={platform.wslServers}>
      <Button variant="ghost-muted" icon="plus" onClick={openAdd}>
        {language.t("wsl.server.addShort")}
      </Button>
    </Show>
  )
}

export function useFilteredWslServers(filter: Accessor<string>) {
  const wsl = useWslServers()
  return createMemo(() => {
    const servers = wsl.data?.servers ?? []
    const query = filter().trim()
    if (!query) return servers
    return fuzzysort
      .go(query, servers, { keys: [(item) => item.config.distro, (item) => item.config.id] })
      .map((x) => x.obj)
  })
}

export function WslServerSettings(props: {
  controller: Controller
  servers: ReturnType<typeof useFilteredWslServers>
}) {
  const platform = usePlatform()
  const language = useLanguage()
  const wsl = useWslServers()
  const api = platform.wslServers

  const request = useMutation(() => ({
    mutationFn: (action: () => Promise<unknown>) => action(),
    onError: (error) =>
      showToast({
        title: language.t("common.requestFailed"),
        description: error instanceof Error ? error.message : String(error),
      }),
  }))

  const remove = (key: ServerConnection.Key) => {
    request.mutate(() => props.controller.handleRemove(key))
  }

  return (
    <Show when={api}>
      <For each={props.servers()}>
        {(item) => {
          const key = ServerConnection.Key.make(item.config.id)
          const check = () => wsl.data?.opencodeChecks[item.config.distro]
          const opencodeAction = () => wslOpencodeAction(check())
          const busy = () => wsl.data?.job?.kind === "install-opencode" && wsl.data.job.distro === item.config.distro
          return (
            <div class="settings-v2-servers-row">
              <div class="settings-v2-servers-lead">
                <ServerHealthIndicator health={props.controller.status()[key]} />
                <div class="settings-v2-servers-copy">
                  <span class="flex min-w-0 items-center gap-1">
                    <span class="settings-v2-servers-name">{item.config.distro}</span>
                    <span class="shrink-0 rounded-[3px] border border-border-strong px-1 py-0.5 text-[9px] leading-none text-text-secondary">
                      {language.t("wsl.server.label")}
                    </span>
                  </span>
                  <span class="settings-v2-servers-meta">
                    <Show when={check()?.version}>{(version) => `v${version()}`}</Show>
                  </span>
                </div>
              </div>
              <div class="settings-v2-servers-actions">
                <Show when={props.controller.canDefault() && props.controller.defaultKey() === key}>
                  <Tag>{language.t("dialog.server.status.default")}</Tag>
                </Show>
                <Show when={opencodeAction()}>
                  {(label) => (
                    <Button
                      size="small"
                      disabled={busy() || request.isPending}
                      onClick={() => api && request.mutate(() => api.installOpencode(item.config.distro))}
                    >
                      {busy() ? language.t("wsl.server.updating") : label()}
                    </Button>
                  )}
                </Show>
                <Menu gutter={4} modal={false} placement="bottom-end">
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
                        <Menu.GroupLabel>{language.t("wsl.server.menu.label")}</Menu.GroupLabel>
                        <Show when={wslRuntimeRetryable(item.runtime)}>
                          <Menu.Item onSelect={() => api && request.mutate(() => api.startServer(key))}>
                            {language.t("wsl.server.retryStart")}
                          </Menu.Item>
                        </Show>
                        <Show when={props.controller.canDefault() && props.controller.defaultKey() !== key}>
                          <Menu.Item onSelect={() => props.controller.setDefault(key)}>
                            {language.t("dialog.server.menu.default")}
                          </Menu.Item>
                        </Show>
                        <Show when={props.controller.canDefault() && props.controller.defaultKey() === key}>
                          <Menu.Item onSelect={() => props.controller.setDefault(null)}>
                            {language.t("dialog.server.menu.defaultRemove")}
                          </Menu.Item>
                        </Show>
                        <Menu.Separator />
                        <Menu.Item onSelect={() => remove(key)}>
                          {language.t("dialog.server.menu.delete")}
                        </Menu.Item>
                      </Menu.Group>
                    </Menu.Content>
                  </Menu.Portal>
                </Menu>
              </div>
            </div>
          )
        }}
      </For>
    </Show>
  )
}



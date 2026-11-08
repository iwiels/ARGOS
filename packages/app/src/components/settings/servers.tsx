import { Button } from "@argos/ui/button"
import { Tag } from "@argos/ui/tag"
import { Icon as IconV2 } from "@argos/ui/icon"
import { IconButton } from "@argos/ui/icon-button"
import { TextInput } from "@argos/ui/text-input"
import { useDialog } from "@argos/ui/context/dialog"
import fuzzysort from "fuzzysort"
import { type Component, For, Show, createMemo } from "solid-js"
import { createStore } from "solid-js/store"
import { ServerRowMenu } from "@/components/server/server-row-menu"
import { ServerHealthIndicator } from "@/components/server/server-row"
import { useLanguage } from "@/context/language"
import { ServerConnection, serverName } from "@/context/server"
import { useServerManagementController } from "../dialog-select-server"
import { DialogServer } from "./dialog-server"
import { SettingsList } from "./parts/list"
import { isWslServer, useFilteredWslServers, WslAddServerButton, WslServerSettings } from "@/wsl/settings"
import "./settings.css"

export const SettingsServers: Component = () => {
  const dialog = useDialog()
  const language = useLanguage()
  const controller = useServerManagementController()
  const [store, setStore] = createStore({ filter: "" })
  const wslServers = useFilteredWslServers(() => store.filter)

  const showSearch = createMemo(
    () => controller.sortedItems().filter((item) => !isWslServer(item)).length + wslServers().length > 1,
  )

  const filtered = createMemo(() => {
    const items = controller.sortedItems().filter((item) => !isWslServer(item))
    const query = store.filter.trim()
    if (!query) return items
    return fuzzysort
      .go(query, items, {
        keys: [(item) => serverName(item), (item) => item.http.url],
      })
      .map((result) => result.obj)
  })

  const openAdd = () => {
    void dialog.push(() => <DialogServer mode="add" />)
  }

  const openEdit = (server: ServerConnection.Http) => {
    void dialog.push(() => <DialogServer mode="edit" server={server} />)
  }

  return (
    <>
      <div
        class="settings-tab-header settings-servers-header"
        classList={{ "settings-tab-header--stacked": showSearch() }}
      >
        <div class="settings-tab-header-row">
          <h2 class="settings-tab-title">{language.t("status.popover.tab.servers")}</h2>
          <Button variant="ghost-muted" icon="plus" onClick={openAdd}>
            {language.t("dialog.server.add.button")}
          </Button>
          <WslAddServerButton />
        </div>
        <Show when={showSearch()}>
          <div class="settings-tab-search">
            <TextInput
              id="settings-server-search"
              name="settings-server-search"
              type="search"
              appearance="base"
              value={store.filter}
              onInput={(event) => setStore("filter", event.currentTarget.value)}
              placeholder={language.t("dialog.server.search.placeholder")}
              spellcheck={false}
              autocorrect="off"
              autocomplete="off"
              autocapitalize="off"
              aria-label={language.t("dialog.server.search.placeholder")}
            />
            <Show when={store.filter}>
              <IconButton
                type="button"
                variant="ghost-muted"
                size="small"
                class="settings-tab-search-clear"
                icon={<IconV2 name="close" size="large" class="text-icon-muted" />}
                aria-label={language.t("common.clearSearch")}
                onClick={() => setStore("filter", "")}
              />
            </Show>
          </div>
        </Show>
      </div>

      <div class="settings-tab-body settings-servers">
        <Show
          when={filtered().length > 0 || wslServers().length > 0}
          fallback={
            <div class="settings-servers-status">
              <span>{store.filter ? language.t("palette.empty") : language.t("dialog.server.empty")}</span>
              <Show when={store.filter}>
                <span class="settings-servers-status-filter">&quot;{store.filter}&quot;</span>
              </Show>
            </div>
          }
        >
          <SettingsList>
            <WslServerSettings controller={controller} servers={wslServers} />
            <For each={filtered()}>
              {(item) => {
                const key = ServerConnection.key(item)
                const health = () => controller.status()[key]
                const isDefault = () => controller.defaultKey() === key
                return (
                  <div class="settings-servers-row">
                    <div class="settings-servers-lead">
                      <ServerHealthIndicator health={health()} />
                      <div class="settings-servers-copy">
                        <span class="settings-servers-name">{serverName(item)}</span>
                        <span class="settings-servers-meta">
                          <Show when={health()?.version}>v{health()?.version}</Show>
                          <Show when={health()?.version && item.type === "http"}> • </Show>
                          <Show
                            when={item.type === "http" && item.http.username}
                            fallback={<Show when={item.type === "http"}>{language.t("server.row.noUsername")}</Show>}
                          >
                            {item.http.username}
                          </Show>
                        </span>
                      </div>
                    </div>
                    <div class="settings-servers-actions">
                      <Show when={controller.canDefault() && isDefault()}>
                        <Tag>{language.t("dialog.server.status.default")}</Tag>
                      </Show>
                      <ServerRowMenu server={item} controller={controller} onEdit={openEdit} />
                    </div>
                  </div>
                )
              }}
            </For>
          </SettingsList>
        </Show>
      </div>
    </>
  )
}



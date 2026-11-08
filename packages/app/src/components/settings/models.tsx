import { useFilteredList } from "@argos/ui/hooks"
import { ProviderIcon } from "@argos/ui/provider-icon"
import { Switch } from "@argos/ui/switch"
import { Icon as IconV2 } from "@argos/ui/icon"
import { IconButton } from "@argos/ui/icon-button"
import { TextInput } from "@argos/ui/text-input"
import { type Component, For, Show } from "solid-js"
import { useLanguage } from "@/context/language"
import { useModels } from "@/context/models"
import { popularProviders } from "@/hooks/use-providers"
import { SettingsList } from "./parts/list"
import { SettingsRow } from "./parts/row"
import "./settings.css"

type ModelItem = ReturnType<ReturnType<typeof useModels>["list"]>[number]

const PROVIDER_ICON_SIZE = 16

export const SettingsModels: Component = () => {
  const language = useLanguage()
  const models = useModels()

  const list = useFilteredList<ModelItem>({
    items: (_filter) => models.list(),
    key: (x) => `${x.provider.id}:${x.id}`,
    filterKeys: ["provider.name", "name", "id"],
    sortBy: (a, b) => a.name.localeCompare(b.name),
    groupBy: (x) => x.provider.id,
    sortGroupsBy: (a, b) => {
      const aIndex = popularProviders.indexOf(a.category)
      const bIndex = popularProviders.indexOf(b.category)
      const aPopular = aIndex >= 0
      const bPopular = bIndex >= 0

      if (aPopular && !bPopular) return -1
      if (!aPopular && bPopular) return 1
      if (aPopular && bPopular) return aIndex - bIndex

      const aName = a.items[0].provider.name
      const bName = b.items[0].provider.name
      return aName.localeCompare(bName)
    },
  })

  return (
    <>
      <div class="settings-tab-header settings-tab-header--stacked">
        <h2 class="settings-tab-title">{language.t("settings.models.title")}</h2>
        <div class="settings-tab-search">
          <TextInput
            id="settings-model-search"
            name="settings-model-search"
            type="search"
            appearance="base"
            value={list.filter()}
            onInput={(event) => list.onInput(event.currentTarget.value)}
            placeholder={language.t("dialog.model.search.placeholder")}
            spellcheck={false}
            autocorrect="off"
            autocomplete="off"
            autocapitalize="off"
            aria-label={language.t("dialog.model.search.placeholder")}
          />
          <Show when={list.filter()}>
            <IconButton
              type="button"
              variant="ghost-muted"
              size="small"
              class="settings-tab-search-clear"
              icon={<IconV2 name="close" size="large" class="text-icon-muted" />}
              aria-label={language.t("common.clearSearch")}
              onClick={() => list.clear()}
            />
          </Show>
        </div>
      </div>

      <div class="settings-tab-body settings-models">
        <Show
          when={!list.grouped.loading}
          fallback={
            <div class="settings-models-status">
              {language.t("common.loading")}
              {language.t("common.loading.ellipsis")}
            </div>
          }
        >
          <Show
            when={list.flat().length > 0}
            fallback={
              <div class="settings-models-status">
                <span>{language.t("dialog.model.empty")}</span>
                <Show when={list.filter()}>
                  <span class="settings-models-status-filter">&quot;{list.filter()}&quot;</span>
                </Show>
              </div>
            }
          >
            <For each={list.grouped.latest}>
              {(group) => (
                <div class="settings-section" data-component="settings-models-provider">
                  <div class="settings-models-group-header">
                    <ProviderIcon
                      id={group.category}
                      width={PROVIDER_ICON_SIZE}
                      height={PROVIDER_ICON_SIZE}
                      class="settings-models-provider-icon shrink-0"
                    />
                    <h3 class="settings-section-title">{group.items[0].provider.name}</h3>
                  </div>
                  <SettingsList>
                    <For each={group.items}>
                      {(item) => {
                        const key = { providerID: item.provider.id, modelID: item.id }
                        return (
                          <SettingsRow title={item.name} description="">
                            <div>
                              <Switch
                                checked={models.visible(key)}
                                onChange={(checked) => {
                                  models.setVisibility(key, checked)
                                }}
                                hideLabel
                              >
                                {item.name}
                              </Switch>
                            </div>
                          </SettingsRow>
                        )
                      }}
                    </For>
                  </SettingsList>
                </div>
              )}
            </For>
          </Show>
        </Show>
      </div>
    </>
  )
}



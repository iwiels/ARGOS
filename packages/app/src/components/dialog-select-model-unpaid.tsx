import { Button } from "@argos/ui/button"
import { useDialog } from "@argos/ui/context/dialog"
import { Dialog } from "@argos/ui/dialog"
import { List, type ListRef } from "@argos/ui/list"
import { ProviderIcon } from "@argos/ui/provider-icon"
import { Tag } from "@argos/ui/tag"
import { Tooltip } from "@argos/ui/tooltip"
import { type Component, Show } from "solid-js"
import { useLocal } from "@/context/local"
import { popularProviders, useProviders } from "@/hooks/use-providers"
import { ModelTooltip } from "./model-tooltip"
import { useLanguage } from "@/context/language"

type ModelState = ReturnType<typeof useLocal>["model"]

export const DialogSelectModelUnpaid: Component<{ model?: ModelState }> = (props) => {
  const model = props.model ?? useLocal().model
  const dialog = useDialog()
  const providers = useProviders()
  const language = useLanguage()

  const connect = (provider: string) => {
    void import("./dialog-connect-provider").then((x) => {
      void dialog.show(() => <x.DialogConnectProvider provider={provider} />)
    })
  }

  const all = () => {
    void import("./dialog-select-provider").then((x) => {
      void dialog.show(() => <x.DialogSelectProvider />)
    })
  }

  let listRef: ListRef | undefined
  const handleKeyDown = (e: KeyboardEvent) => {
    if (e.key === "Escape") return
    listRef?.onKeyDown(e)
  }

  return (
    <Dialog title={language.t("dialog.model.select.title")} size="large">
      <div class="grid grid-cols-2 gap-4 px-4 pb-4 h-full min-h-0" onKeyDown={handleKeyDown}>
        {/* Left column: Free Models */}
        <div class="flex flex-col min-h-0 h-full">
          <div class="text-13-medium text-text-weak px-2 mb-2">
            {language.t("dialog.model.unpaid.freeModels.title")}
          </div>
          <div class="flex-1 min-h-0 overflow-y-auto rounded-md border border-border-weak-base/60 bg-bg-surface/50 p-1">
            <List
              class="w-full"
              label={language.t("dialog.model.unpaid.freeModels.title")}
              ref={(ref) => (listRef = ref)}
              items={model.list}
              current={model.current()}
              key={(x) => `${x.provider.id}:${x.id}`}
              itemWrapper={(item, node) => (
                <Tooltip
                  class="w-full"
                  placement="right-start"
                  gutter={12}
                  value={
                    <ModelTooltip
                      model={item}
                      latest={item.latest}
                      free={item.provider.id === "opencode" && (!item.cost || item.cost.input === 0)}
                    />
                  }
                >
                  {node}
                </Tooltip>
              )}
              onSelect={(x) => {
                model.set(x ? { modelID: x.id, providerID: x.provider.id } : undefined, {
                  recent: true,
                })
                dialog.close()
              }}
            >
              {(i) => (
                <div class="w-full flex items-center gap-x-2">
                  <span class="truncate">{i.name}</span>
                  <Tag>{language.t("model.tag.free")}</Tag>
                  <Show when={i.latest}>
                    <Tag>{language.t("model.tag.latest")}</Tag>
                  </Show>
                </div>
              )}
            </List>
          </div>
        </div>

        {/* Right column: Popular Providers */}
        <div class="flex flex-col min-h-0 h-full rounded-md border border-border-weak-base bg-bg-surface/40 p-3">
          <div class="text-13-medium text-text-weak px-1 mb-2">
            {language.t("dialog.model.unpaid.addMore.title")}
          </div>
          <div class="flex-1 min-h-0 overflow-y-auto">
            <List
              class="w-full"
              label={language.t("dialog.model.unpaid.addMore.title")}
              key={(p) => p.id}
              items={providers.popular}
              activeIcon="plus-small"
              sortBy={(a, b) => {
                if (popularProviders.includes(a.id) && popularProviders.includes(b.id))
                  return popularProviders.indexOf(a.id) - popularProviders.indexOf(b.id)
                return a.name.localeCompare(b.name)
              }}
              onSelect={(x) => {
                if (!x) return
                connect(x.id)
              }}
            >
              {(i) => (
                <div class="w-full flex items-center justify-between gap-x-2 min-w-0">
                  <div class="flex items-center gap-x-2.5 min-w-0 truncate">
                    <ProviderIcon data-slot="list-item-extra-icon" id={i.id} />
                    <span class="truncate">{i.name}</span>
                  </div>
                  <Show when={i.id === "opencode" || i.id === "opencode-go"}>
                    <Tag>{language.t("dialog.provider.tag.recommended")}</Tag>
                  </Show>
                </div>
              )}
            </List>
          </div>
          <Button
            variant="ghost"
            class="w-full justify-start mt-2 px-2.5 py-2 gap-2.5 text-13-medium text-text-weak hover:text-text-base"
            icon="dot-grid"
            onClick={all}
          >
            {language.t("dialog.provider.viewAll")}
          </Button>
        </div>
      </div>
    </Dialog>
  )
}



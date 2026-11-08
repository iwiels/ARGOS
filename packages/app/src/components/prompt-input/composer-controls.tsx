import { Popover as KobaltePopover } from "@kobalte/core/popover"
import { For, Show, splitProps, type ComponentProps, type JSX } from "solid-js"
import { Button } from "@argos/ui/button"
import { Icon, type IconProps } from "@argos/ui/icon"
import { ProviderIcon } from "@argos/ui/provider-icon"
import { Select } from "@argos/ui/select"
import { Tooltip } from "@argos/ui/tooltip"
import { ModelSelectorPopover } from "@/components/dialog-select-model"
import { useLocal } from "@/context/local"

export type ComposerPickerItemState = {
  icon: IconProps["name"]
  label: string
  selected?: boolean
  onSelect: () => void
}

export type ComposerPickerTriggerState = {
  action: string
  icon?: IconProps["name"]
  label: string
  class?: string
  style: JSX.CSSProperties | undefined
  onPress: () => void
}

export type ComposerPickerState = {
  open: boolean
  trigger: ComposerPickerTriggerState
  search: string
  searchPlaceholder: string
  clearLabel: string
  items: ComposerPickerItemState[]
  action: ComposerPickerItemState
  listClass?: string
  searchRef: (el: HTMLInputElement) => void
  onOpenChange: (open: boolean) => void
  onSearchInput: (value: string) => void
  onSearchClear: () => void
}

export type ComposerAgentControlState = {
  title: string
  keybind: string
  options: string[]
  current: string
  style: JSX.CSSProperties | undefined
  onSelect: (value: string | null) => void
}

export type ComposerModelControlState = {
  loading: boolean
  paid: boolean
  title: string
  keybind: string
  model: ReturnType<typeof useLocal>["model"]
  providerID?: string
  modelName: string
  style: JSX.CSSProperties | undefined
  onClose: () => void
  onUnpaidClick: () => void
}

export function ComposerPickerTrigger(props: ComponentProps<"button"> & { state: ComposerPickerTriggerState }) {
  const [local, rest] = splitProps(props, ["state", "class", "style", "onClick"])
  return (
    <button
      {...rest}
      data-action={local.state.action}
      type="button"
      class={`group flex h-7 min-w-0 items-center gap-1.5 rounded px-2 text-base font-normal leading-5 tracking-[-0.04px] text-text-secondary transition-colors hover:bg-overlay-hover hover:text-text-primary focus-visible:bg-overlay-hover focus-visible:outline-none ${local.state.class ?? ""}`}
      style={local.state.style}
      onClick={() => local.state.onPress()}
    >
      <Show when={local.state.icon}>
        {(icon) => (
          <Icon
            name={icon()}
            class="size-4 shrink-0 text-icon-muted group-hover:text-text-secondary transition-colors"
          />
        )}
      </Show>
      <span class="min-w-0 truncate leading-5">{local.state.label}</span>
      <Icon
        name="chevron-down"
        size="normal"
        class="size-4 shrink-0 text-icon-muted group-hover:text-text-secondary transition-colors"
      />
    </button>
  )
}

function ComposerPickerMenuItem(props: { state: ComposerPickerItemState }) {
  return (
    <button
      type="button"
      class="flex h-7 w-full items-center gap-2 rounded px-3 text-left text-base font-normal leading-5 tracking-[-0.04px] text-text-primary hover:bg-overlay-hover focus-visible:bg-overlay-hover focus-visible:outline-none"
      onClick={props.state.onSelect}
    >
      <Icon name={props.state.icon} class="shrink-0 text-icon-muted" />
      <span class="min-w-0 flex-1 truncate leading-5">{props.state.label}</span>
      <Show when={props.state.selected}>
        <Icon name="check-small" class="shrink-0 text-icon-info" />
      </Show>
    </button>
  )
}

export function ComposerPicker(props: { state: ComposerPickerState }) {
  return (
    <KobaltePopover
      open={props.state.open}
      placement="bottom-start"
      gutter={4}
      modal={false}
      onOpenChange={props.state.onOpenChange}
    >
      <KobaltePopover.Trigger as={ComposerPickerTrigger} state={props.state.trigger} />
      <KobaltePopover.Portal>
        <KobaltePopover.Content
          class="w-60.75 overflow-hidden rounded-md border border-border-weak-base bg-bg-surface shadow-popover focus:outline-none z-50"
          onOpenAutoFocus={(event) => event.preventDefault()}
        >
          <div class={`flex flex-col p-0.5 ${props.state.listClass ?? ""}`}>
            <div class="flex h-7 items-center gap-2 rounded px-3 text-icon-muted">
              <Icon name="magnifying-glass" class="shrink-0" />
              <input
                ref={props.state.searchRef}
                value={props.state.search}
                placeholder={props.state.searchPlaceholder}
                class="h-7 min-w-0 flex-1 border-0 bg-transparent text-base font-normal leading-5 tracking-[-0.04px] text-text-primary outline-none placeholder:text-text-tertiary"
                onInput={(event) => props.state.onSearchInput(event.currentTarget.value)}
              />
              <Show when={props.state.search.trim()}>
                <button
                  type="button"
                  class="flex size-5 items-center justify-center rounded text-icon-muted hover:bg-overlay-hover"
                  onClick={props.state.onSearchClear}
                  aria-label={props.state.clearLabel}
                >
                  <Icon name="close-small" />
                </button>
              </Show>
            </div>
            <For each={props.state.items}>{(item) => <ComposerPickerMenuItem state={item} />}</For>
          </div>
          <div class="h-px bg-border-weaker-base" />
          <div class="flex flex-col p-0.5">
            <ComposerPickerMenuItem state={props.state.action} />
          </div>
        </KobaltePopover.Content>
      </KobaltePopover.Portal>
    </KobaltePopover>
  )
}

export function ComposerAgentControl(props: { state: ComposerAgentControlState }) {
  return (
    <div class="relative">
      <div class="pointer-events-none absolute left-2 top-1/2 z-10 flex size-4 -translate-y-1/2 items-center justify-center text-icon-muted">
        <Icon name="sliders"  />
      </div>
      <Tooltip placement="top" gutter={4} value={props.state.title} >
        <Select
          options={props.state.options}
          current={props.state.current}
          onSelect={props.state.onSelect}
          class="max-w-43.75 justify-start text-text-secondary [&_[data-component=icon]]:text-icon-muted"
          valueClass="truncate pl-5 text-base font-normal leading-5 text-text-secondary"
        />
      </Tooltip>
    </div>
  )
}

export function ComposerModelControl(props: { state: ComposerModelControlState }) {
  return (
    <Show when={!props.state.loading}>
      <Show
        when={props.state.paid}
        fallback={
          <Tooltip placement="top" gutter={4} value={props.state.title} >
            <Button
              data-action="prompt-model"
              as="div"
              variant="ghost"

              class="min-w-0 max-w-55 justify-start text-base font-normal leading-5 text-text-secondary group"
              style={props.state.style}
              onClick={props.state.onUnpaidClick}
            >
              <Show when={props.state.providerID}>
                {(providerID) => (
                  <ProviderIcon
                    id={providerID()}
                    class="size-4 shrink-0 opacity-60 group-hover:opacity-100 transition-opacity duration-150"
                    style={{ "will-change": "opacity", transform: "translateZ(0)" }}
                  />
                )}
              </Show>
              <span class="truncate">{props.state.modelName}</span>
              <Icon name="chevron-down"  class="shrink-0 text-icon-muted" />
            </Button>
          </Tooltip>
        }
      >
        <Tooltip placement="top" gutter={4} value={props.state.title} >
          <ModelSelectorPopover
            model={props.state.model}
            triggerAs={Button}
            triggerProps={{
              variant: "ghost",
              size: "normal",
              style: props.state.style,
              class:
                "min-w-0 max-w-55 justify-start text-base font-normal leading-5 text-text-secondary group",
              "data-action": "prompt-model",
            }}
            onClose={props.state.onClose}
          >
            <Show when={props.state.providerID}>
              {(providerID) => (
                <ProviderIcon
                  id={providerID()}
                  class="size-4 shrink-0 opacity-60 group-hover:opacity-100 transition-opacity duration-150"
                  style={{ "will-change": "opacity", transform: "translateZ(0)" }}
                />
              )}
            </Show>
            <span class="truncate">{props.state.modelName}</span>
            <Icon name="chevron-down" size="normal" class="size-4 shrink-0 text-icon-muted" />
          </ModelSelectorPopover>
        </Tooltip>
      </Show>
    </Show>
  )
}

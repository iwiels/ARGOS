import { For, Show } from "solid-js"
import { Icon } from "@argos/ui/icon"
import { IconButton } from "@argos/ui/icon-button"

export function AttckFilterBar(props: {
  techniques: { id: string; name: string }[]
  activeTechnique: string | null
  onSelectTechnique: (id: string) => void
  search: string
  onSearchChange: (query: string) => void
}) {
  return (
    <div class="shrink-0 px-6 py-2.5 bg-bg-surface border-b border-border-weaker-base flex flex-wrap items-center justify-between gap-3">
      {/* Lista horizontal de técnicas MITRE ATT&CK */}
      <div class="flex items-center gap-1.5 overflow-x-auto min-w-0 max-w-full py-0.5">
        <span class="text-11-mono text-text-tertiary shrink-0 mr-1">{"Vectores ATT&CK:"}</span>
        <For each={props.techniques}>
          {(t) => {
            const isActive = () => props.activeTechnique === t.id
            return (
              <button
                type="button"
                onClick={() => props.onSelectTechnique(t.id)}
                class={`shrink-0 px-2 py-1 rounded-sm font-mono text-11-mono border transition-colors ${
                  isActive()
                    ? "bg-text-primary text-bg-base border-text-primary font-medium"
                    : "bg-bg-surface text-text-secondary border-border-weaker-base hover:border-border-strong hover:text-text-primary"
                }`}
                title={t.name}
              >
                {`${t.id} · ${t.name}`}
              </button>
            )
          }}
        </For>
        <Show when={props.techniques.length === 0}>
          <span class="text-11-mono text-text-tertiary">{"Sin técnicas mapeadas"}</span>
        </Show>
      </div>

      {/* Input de búsqueda rápida */}
      <div class="relative w-full sm:w-64">
        <input
          type="text"
          value={props.search}
          onInput={(e) => props.onSearchChange((e.target as HTMLInputElement).value)}
          placeholder={"Buscar CWE, IoC, dominio…"}
          class="w-full bg-bg-surface border border-border-weaker-base rounded-sm px-2.5 py-1.5 text-xs font-mono text-text-primary placeholder:text-text-tertiary focus:outline-none focus:border-border-strong transition-colors pr-7"
        />
        <Show when={props.search.trim().length > 0}>
          <IconButton
            icon={<Icon name="close-small" />}
            size="small"
            variant="ghost-muted"
            onClick={() => props.onSearchChange("")}
            class="absolute right-1 top-1/2 -translate-y-1/2"
            aria-label={"Limpiar búsqueda"}
          />
        </Show>
      </div>
    </div>
  )
}

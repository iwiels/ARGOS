import { createSignal, For, Show } from "solid-js"
import { Icon } from "@argos/ui/icon"

export function StrategistDrawer(props: {
  isOpen: boolean
  onClose: () => void
  onQuickAction: (actionText: string) => void
  onPromptSubmit: (prompt: string) => void
  chatLog: { text: string; response: string }[]
  targetDomain?: string
  onDossierClick?: () => void
}) {
  const [inputValue, setInputValue] = createSignal("")

  const handleSubmit = (e: Event) => {
    e.preventDefault()
    const text = inputValue().trim()
    if (!text) return
    props.onPromptSubmit(text)
    setInputValue("")
  }

  return (
    <>
      <Show when={props.isOpen}>
        <div
          class="fixed inset-0 bg-black/50 z-30 xl:hidden no-print print:hidden transition-opacity"
          onClick={() => props.onClose()}
        />
      </Show>

      <aside
        class={`shrink-0 bg-bg-surface border-r border-border-weaker-base flex flex-col h-full transition-all duration-200 z-40 xl:z-20 no-print print:hidden ${
          props.isOpen
            ? "fixed inset-y-0 left-0 w-80 shadow-2xl xl:static xl:shadow-none"
            : "w-0 overflow-hidden border-r-0 xl:static fixed"
        }`}
      >
      <Show when={props.isOpen}>
        {/* Cabecera del asistente */}
        <div class="h-10 px-4 border-b border-border-weaker-base flex items-center justify-between shrink-0">
            <span class="text-xs font-medium text-text-primary">{"Estado del expediente"}</span>
          <button
            type="button"
            onClick={() => props.onClose()}
            title={"Ocultar consola"}
            class="text-text-tertiary hover:text-text-primary transition-colors text-sm px-1"
          >
            {"«"}
          </button>
        </div>

        {/* Cuerpo scrolleable */}
        <div class="flex-1 overflow-y-auto p-4 space-y-6 min-h-0">
          <section class="space-y-2">
            <h3 class="text-10-mono font-medium uppercase tracking-wider text-text-tertiary">{"Contexto"}</h3>
            <p class="text-xs leading-relaxed text-text-secondary">
              {"Directorio de trabajo: "}
              <span class="font-mono text-11-mono text-text-primary">{props.targetDomain || "no indicado"}</span>
            </p>
            <p class="text-xs leading-relaxed text-text-secondary">
              {"Este panel no recibe telemetría del runtime ni ejecuta comandos. Las acciones de auditoría disponibles se muestran cuando estén conectadas a la sesión."}
            </p>
          </section>

          {/* Acciones rápidas predefinidas */}
          <section class="space-y-2">
            <h3 class="text-10-mono font-medium uppercase tracking-wider text-text-tertiary">
              {"Acciones rápidas"}
            </h3>
            <div class="space-y-1.5">
              <button
                type="button"
                onClick={() => props.onQuickAction("Ocultar hallazgos no persistidos")}
                class="w-full text-left px-3 py-2 rounded-sm border border-border-weaker-base bg-bg-base/40 text-xs text-text-secondary hover:border-border-strong hover:text-text-primary transition-colors flex items-center justify-between gap-2"
              >
                <span>{"Ocultar hallazgos no persistidos"}</span>
                <span class="font-mono text-10-mono text-text-tertiary shrink-0">{"Filtrar"}</span>
              </button>
              <button
                type="button"
                onClick={() => {
                  if (props.onDossierClick) {
                    props.onDossierClick()
                  } else {
                    props.onQuickAction("Emitir dossier ejecutivo TLP:AMBER")
                  }
                }}
                class="w-full text-left px-3 py-2 rounded-sm border border-border-weaker-base bg-bg-base/40 text-xs text-text-secondary hover:border-border-strong hover:text-text-primary transition-colors flex items-center justify-between gap-2"
              >
                <span>{"Abrir borrador de informe"}</span>
                <span class="font-mono text-10-mono text-text-tertiary shrink-0">{"Informe"}</span>
              </button>
            </div>
          </section>

          {/* Historial de comandos interactivos */}
          <Show when={props.chatLog.length > 0}>
            <section class="space-y-2 pt-2 border-t border-border-weaker-base">
              <h3 class="text-10-mono font-medium uppercase tracking-wider text-text-tertiary">
                {"Registro de sesión"}
              </h3>
              <div class="space-y-2">
                <For each={props.chatLog}>
                  {(item) => (
                    <div class="rounded-sm border border-border-weaker-base bg-bg-base/70 p-2.5 space-y-1">
                      <div class="font-mono text-10-mono text-text-tertiary break-words">
                        {`→ ${item.text}`}
                      </div>
                      <div class="text-xs text-text-secondary leading-relaxed">
                        {item.response}
                      </div>
                    </div>
                  )}
                </For>
              </div>
            </section>
          </Show>
        </div>

        {/* Input inferior de comandos */}
        <div class="p-3 border-t border-border-weaker-base bg-bg-surface shrink-0">
          <form onSubmit={handleSubmit} class="relative">
            <input
              type="text"
              value={inputValue()}
              onInput={(e) => setInputValue((e.target as HTMLInputElement).value)}
              placeholder={"Las acciones deben estar conectadas para ejecutarse"}
              class="w-full bg-bg-base border border-border-weaker-base rounded-sm pl-3 pr-8 py-2 text-xs text-text-primary placeholder:text-text-tertiary focus:outline-none focus:border-border-strong transition-colors"
            />
            <button
              type="submit"
              title={"Enviar comando"}
              class="absolute right-1.5 top-1/2 -translate-y-1/2 size-6 rounded-xs flex items-center justify-center text-text-tertiary hover:text-text-primary transition-colors"
            >
              <Icon name="arrow-up" class="size-3.5" />
            </button>
          </form>
        </div>
      </Show>
    </aside>
    </>
  )
}

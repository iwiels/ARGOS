import { createMemo, ErrorBoundary, For, Show, type JSX, type ParentProps } from "solid-js"

/**
 * Vocabulario visual compartido de los paneles laterales de sesión
 * (Hallazgos / Cumplimiento / Contexto).
 *
 * La pestaña Contexto definió la estética de referencia: escala tipográfica
 * semántica (text-NN-*, nunca tamaños arbitrarios), un ritmo vertical único,
 * y una tarjeta de resumen con barra de distribución + leyenda. Estos
 * primitivos existen para que las tres vistas COMPARTAN esa estética en lugar
 * de reimplementarla cada una con clases ligeramente distintas — que es
 * exactamente como se desincronizaron.
 */

/** Ritmo vertical de un panel: mismo padding y separación en las tres vistas. */
export function PanelBody(props: ParentProps<{ class?: string }>) {
  return <div class={`flex flex-col gap-5 px-4 pt-3 pb-10 ${props.class ?? ""}`}>{props.children}</div>
}

/** Encabezado de sección: etiqueta tenue con filete hairline pericial estilo dossier. */
export function PanelSection(props: ParentProps<{ label: string; actions?: JSX.Element }>) {
  return (
    <div class="flex flex-col gap-2.5">
      <div class="flex items-center justify-between gap-2 border-b border-border-weaker-base/60 pb-1">
        <div class="font-mono text-10-medium uppercase tracking-wider text-text-weak">{props.label}</div>
        {props.actions}
      </div>
      {props.children}
    </div>
  )
}

/** Par etiqueta/valor. La unidad de dato de todos los paneles. */
export function Stat(props: { label: string; value: JSX.Element }) {
  return (
    <div class="flex flex-col gap-0.5 rounded-sm border border-border-weaker-base/60 bg-bg-surface/50 p-2">
      <div class="font-mono text-10-regular uppercase tracking-wider text-text-weak">{props.label}</div>
      <div class="font-mono text-12-medium text-text-strong tabular-nums">{props.value}</div>
    </div>
  )
}

/** Rejilla de Stats: una columna en panel angosto, dos cuando hay espacio. */
export function StatGrid(props: ParentProps) {
  return <div class="grid grid-cols-1 @[32rem]:grid-cols-2 gap-2.5">{props.children}</div>
}

export interface DistributionSegment {
  key: string
  label: string
  /** Color CSS resuelto (p.ej. "var(--severity-fg-critical)"). */
  color: string
  /** Ancho proporcional en la barra, 0-100. */
  width: number
  /** Valor mostrado en la leyenda (conteo o porcentaje ya formateado). */
  display: string
}

/**
 * Piso de ancho por segmento, en %. Sin esto un único hallazgo crítico entre
 * cien informativos —o un solo control deficiente de 106— se dibuja como una
 * astilla invisible: justo el dato que hay que ver desaparece. Se aplica el
 * piso y se renormaliza para que la barra siga sumando 100%.
 */
export const MIN_SEGMENT_WIDTH = 4

export function withVisibleSegments(segments: DistributionSegment[]): DistributionSegment[] {
  const present = segments.filter((segment) => segment.width > 0)
  if (present.length === 0) return []
  const floored = present.map((segment) => ({ ...segment, width: Math.max(segment.width, MIN_SEGMENT_WIDTH) }))
  const total = floored.reduce((sum, segment) => sum + segment.width, 0)
  if (total <= 0) return []
  return floored.map((segment) => ({ ...segment, width: (segment.width / total) * 100 }))
}

/**
 * Tarjeta de resumen: ficha de índice pericial estilo Mosby Files.
 * Píldora de estado en mono, métrica de severidad máxima, barra segmentada y leyenda tabular.
 */
export function PanelSummaryCard(props: {
  status: string
  metric?: string
  /** Color del punto de estado; por defecto el acento del tema. */
  tone?: string
  segments: DistributionSegment[]
  actions?: JSX.Element
  footer?: JSX.Element
}) {
  const tone = () => props.tone ?? "var(--accent)"
  const bars = createMemo(() => withVisibleSegments(props.segments))
  return (
    <div class="flex flex-col gap-2.5 rounded-sm border border-border-weaker-base/80 bg-bg-surface p-3 shadow-xs">
      <div class="flex items-center justify-between gap-2 border-b border-border-weaker-base/50 pb-2">
        <div class="flex min-w-0 items-center gap-2">
          <span
            class="size-2 shrink-0 rounded-full"
            style={{
              "background-color": tone(),
              "box-shadow": `0 0 6px color-mix(in srgb, ${tone()} 60%, transparent)`,
            }}
          />
          <span class="truncate font-mono text-11-medium uppercase tracking-wider text-text-primary">{props.status}</span>
        </div>
        <div class="flex items-center gap-2 shrink-0">
          <Show when={props.metric}>
            <span class="shrink-0 rounded-sm border border-border-weaker-base bg-bg-elevated px-2 py-0.5 font-mono text-10-regular font-bold uppercase tracking-wider text-text-primary">
              {props.metric}
            </span>
          </Show>
          {props.actions}
        </div>
      </div>

      <Show when={bars().length > 0}>
        <div class="flex h-1.5 w-full gap-0.5 overflow-hidden rounded-sm bg-bg-elevated">
          <For each={bars()}>
            {(segment) => (
              <div
                class="h-full transition-all duration-300"
                style={{ width: `${segment.width}%`, "background-color": segment.color }}
                title={`${segment.label}: ${segment.display}`}
              />
            )}
          </For>
        </div>

        <div class="flex flex-wrap items-center gap-1.5">
          <For each={bars()}>
            {(segment) => (
              <div class="inline-flex min-w-0 items-center gap-1.5 rounded-sm border border-border-weaker-base/60 bg-bg-elevated/40 px-2 py-0.5">
                <span class="size-1.5 shrink-0 rounded-full" style={{ "background-color": segment.color }} />
                <span class="truncate font-mono text-10-regular text-text-weak">
                  {segment.label}: <span class="font-bold text-text-primary tabular-nums">{segment.display}</span>
                </span>
              </div>
            )}
          </For>
        </div>
      </Show>

      {props.footer}
    </div>
  )
}

import { useLanguage } from "@/context/language"

/** Error boundary granular para aislar fallos en paneles laterales sin romper la sesión. */
export function PanelErrorBoundary(props: ParentProps<{ name?: string }>) {
  const language = useLanguage()
  return (
    <ErrorBoundary
      fallback={(err, reset) => (
        <div class="flex flex-col items-center justify-center gap-3 p-6 text-center text-text-secondary">
          <div class="text-12-medium text-text-primary">
            {props.name ? `Error: ${props.name}` : "Error"}
          </div>
          <div class="text-11-mono text-text-weak max-w-xs truncate">{err instanceof Error ? err.message : String(err)}</div>
          <button
            type="button"
            onClick={reset}
            class="mt-2 inline-flex items-center gap-1.5 rounded-md border border-border-weaker-base bg-bg-elevated px-2.5 py-1 text-11-medium text-text-primary hover:bg-bg-surface transition-colors cursor-pointer"
          >
            <span>{language.t("governance.retry")}</span>
          </button>
        </div>
      )}
    >
      {props.children}
    </ErrorBoundary>
  )
}

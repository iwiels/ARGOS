import { createSignal, onCleanup, onMount, splitProps, type ComponentProps, type Accessor } from "solid-js"
import { PIXEL_ICONS } from "./pixel-icons.data"

export interface PixelWindRoseProps extends ComponentProps<"svg"> {
  name?: string
  size?: number
  /** Vueltas completas por todo el recorrido de scroll (como las wind-roses de Mosby). */
  turns?: number
  /** Refleja horizontalmente (las wind-roses de Mosby alternan dirección). */
  mirrored?: boolean
  /** Contenedor que hace scroll (selector CSS). Fallback: la ventana. */
  target?: string
}

/**
 * Rosa de los vientos pixel-art que rota con el progreso de scroll del
 * documento. La referencia es el footer de mosbyfiles.com: varias brújulas
 * pequeñas giran mientras el lector avanza, cada una con su propia dirección.
 * En Argos vive como firma visual en el pie del dossier y de las listas.
 */
export function PixelWindRose(props: PixelWindRoseProps) {
  const [split, rest] = splitProps(props, ["name", "size", "turns", "mirrored", "target", "class", "classList"])
  const [rotation, setRotation] = createSignal(0)
  const [scrollable, setScrollable] = createSignal(false)

  const update = () => {
    const el = split.target ? document.querySelector(split.target) : undefined
    if (el) {
      const max = el.scrollHeight - el.clientHeight
      if (max <= 0) {
        setScrollable(false)
        setRotation(0)
        return
      }
      setScrollable(true)
      const progress = Math.min(Math.max(el.scrollTop / max, 0), 1)
      const turns = split.turns ?? 2
      setRotation(progress * 360 * turns * (split.mirrored ? -1 : 1))
      return
    }
    const doc = document.documentElement
    const max = doc.scrollHeight - window.innerHeight
    if (max <= 0) {
      setScrollable(false)
      setRotation(0)
      return
    }
    setScrollable(true)
    const progress = Math.min(Math.max(window.scrollY / max, 0), 1)
    const turns = split.turns ?? 2
    setRotation(progress * 360 * turns * (split.mirrored ? -1 : 1))
  }

  onMount(() => {
    update()
    window.addEventListener("scroll", update, { passive: true, capture: true })
    window.addEventListener("resize", update, { passive: true })
  })
  onCleanup(() => {
    window.removeEventListener("scroll", update, { capture: true } as EventListenerOptions)
    window.removeEventListener("resize", update)
  })

  const pathData = () => {
    const name = split.name ?? "safari-compass"
    return (
      PIXEL_ICONS[name] ??
      PIXEL_ICONS[name.replace(/\s+/g, "-").toLowerCase()] ??
      PIXEL_ICONS["interface-essential-safari-compass"] ??
      ""
    )
  }

  const size = () => split.size ?? 24

  return (
    <svg
      viewBox="0 0 32 32"
      width={size()}
      height={size()}
      fill="currentColor"
      aria-hidden="true"
      data-component="pixel-wind-rose"
      shape-rendering="crispEdges"
      classList={{
        "shrink-0 inline-block align-middle": true,
        ...split.classList,
        [split.class ?? ""]: !!split.class,
      }}
      style={{
        transform: scrollable() ? `rotate(${rotation()}deg)` : undefined,
        "will-change": "transform",
        ...(typeof rest.style === "object" ? rest.style : {}),
      }}
      {...rest}
    >
      <path d={pathData()} fill="currentColor" />
    </svg>
  )
}

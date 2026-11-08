import { onMount, onCleanup } from "solid-js"
import { MODE_DRAWS, resolvePreset, type OrbState, type OrbSize, type OrbTheme } from "thinking-orbs"

export type { OrbState, OrbSize, OrbTheme }

export interface ThinkingOrbProps {
  state?: OrbState
  size?: number
  theme?: OrbTheme
  speed?: number
  class?: string
}

export function ThinkingOrb(props: ThinkingOrbProps) {
  let canvasRef: HTMLCanvasElement | undefined
  let animId: number

  onMount(() => {
    if (!canvasRef) return
    const ctx = canvasRef.getContext("2d")
    if (!ctx) return

    let startTime = performance.now()

    const render = (now: number) => {
      if (!canvasRef || !ctx) return

      const state = props.state ?? "listening"
      const size = props.size ?? 64
      const speedMul = props.speed ?? 1
      const isDark = props.theme !== "light"

      const presetSize: OrbSize = typeof size === "number" && size < 64 ? 20 : 64
      const resolved = resolvePreset(state, presetSize)
      const painter = MODE_DRAWS[resolved.mode]

      const t = ((now - startTime) / 1000) * resolved.speed * speedMul

      const dpr = window.devicePixelRatio || 1
      const canvasWidth = size * dpr
      const canvasHeight = size * dpr

      if (canvasRef.width !== canvasWidth || canvasRef.height !== canvasHeight) {
        canvasRef.width = canvasWidth
        canvasRef.height = canvasHeight
        canvasRef.style.width = `${size}px`
        canvasRef.style.height = `${size}px`
      }

      ctx.save()
      ctx.scale(dpr, dpr)
      ctx.clearRect(0, 0, size, size)

      if (painter) {
        painter(ctx, size, t, isDark, resolved.opts)
      }
      ctx.restore()

      animId = requestAnimationFrame(render)
    }

    animId = requestAnimationFrame(render)

    onCleanup(() => {
      if (animId) cancelAnimationFrame(animId)
    })
  })

  return <canvas ref={canvasRef} class={`inline-block ${props.class ?? ""}`} />
}

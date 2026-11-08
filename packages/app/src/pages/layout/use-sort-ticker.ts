import { createSignal, onCleanup } from "solid-js"

/**
 * Minute-aligned tick that forces the session lists to re-sort relative
 * timestamps without any per-second timer cost.
 */
export function useSortTicker() {
  const [sortNow, setSortNow] = createSignal(Date.now())

  let interval: ReturnType<typeof setInterval> | undefined
  const timeout = setTimeout(
    () => {
      setSortNow(Date.now())
      interval = setInterval(() => setSortNow(Date.now()), 60_000)
    },
    60_000 - (Date.now() % 60_000),
  )

  onCleanup(() => {
    clearTimeout(timeout)
    if (interval) clearInterval(interval)
  })

  return sortNow
}

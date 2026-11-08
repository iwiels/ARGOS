import type { TrafficExchange } from "./traffic-api"

type Translate = (key: string, params?: Record<string, string | number>) => string

/**
 * Arma el mensaje que el botón "Reenviar" inserta en el chat.
 *
 * El replay NO lo hace la UI: la request tiene que salir del cliente atado
 * al ScopeGuard del binario Go (IP-pinning, rate limit, audit log
 * encadenado) y sólo el agente tiene esa tool. La UI delega el trabajo y
 * deja la decisión de alcance donde tiene que estar.
 */
export function buildReplayPrompt(exchange: TrafficExchange, t: Translate): string {
  const details = [
    t("traffic.replay.method", { value: exchange.method }),
    t("traffic.replay.url", { value: exchange.url }),
    t("traffic.replay.id", { value: exchange.id }),
    t("traffic.replay.status", { value: String(exchange.status) }),
    exchange.sourceTool ? t("traffic.replay.tool", { value: exchange.sourceTool }) : undefined,
  ].filter((line): line is string => !!line)

  return [
    t("traffic.replay.intro"),
    "",
    details.join("\n"),
    "",
    t("traffic.replay.task"),
    "",
    t("traffic.replay.honesty"),
  ].join("\n")
}

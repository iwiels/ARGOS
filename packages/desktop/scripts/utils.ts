export type Channel = "dev" | "beta" | "prod"

export function resolveChannel(): Channel {
  const raw = process.env.ARGOS_CHANNEL ?? process.env.OPENCODE_CHANNEL
  if (raw === "dev" || raw === "beta" || raw === "prod") return raw
  return "dev"
}

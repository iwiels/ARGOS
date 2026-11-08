export function isRecord(val: unknown): val is Record<string, any> {
  return typeof val === "object" && val !== null && !Array.isArray(val)
}

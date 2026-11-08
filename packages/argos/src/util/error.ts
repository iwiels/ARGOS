export function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message
  if (typeof err === "string") return err
  if (typeof err === "object" && err !== null && "message" in err) return String((err as any).message)
  return String(err)
}

export function errorData(err: unknown): unknown {
  if (typeof err === "object" && err !== null && "data" in err) return (err as any).data
  return undefined
}

export function errorFormat(err: unknown): string {
  return errorMessage(err)
}

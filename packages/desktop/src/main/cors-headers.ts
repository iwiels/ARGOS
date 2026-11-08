/**
 * Ajuste de cabeceras CORS para las respuestas que ve el renderer.
 *
 * Vive aparte de windows.ts a propósito: sin importar `electron`, la lógica se
 * puede probar directamente.
 */

/**
 * Headers que el renderer envía y que Chromium debe permitir.
 *
 * Chromium deprecó el wildcard (*) en Access-Control-Allow-Headers cuando el
 * request incluye Authorization, por eso hay que enumerarlos.
 *
 * Es una red de seguridad para respuestas que no traen CORS propio, NO la
 * fuente de verdad: la lista autoritativa vive en el servidor
 * (packages/argos/.../httpapi/server.ts, ALLOWED_HEADERS).
 */
export const RENDERER_ALLOWED_HEADERS = [
  "Authorization",
  "Content-Type",
  "Accept",
  "x-opencode-directory",
  "x-opencode-workspace",
  // El ticket de conexión de PTY. Su ausencia aquí rompía la terminal: por muy
  // bien que respondiera el servidor, el handler de onHeadersReceived pisaba su
  // cabecera y Chromium bloqueaba el preflight de /pty/{id}/connect-token.
  "x-opencode-ticket",
]

/**
 * Une lo que ya respondió el servidor con la lista local en vez de reemplazarlo.
 *
 * Sobrescribir era la causa de un fallo difícil de diagnosticar: el servidor
 * respondía correctamente (verificable con curl), pero el handler descartaba su
 * cabecera y dejaba una lista fija que se había quedado desactualizada. Con la
 * unión, un header nuevo en el servidor funciona aunque nadie actualice esta
 * lista, y nunca se pierde lo que ya estaba permitido.
 */
export function mergeAllowedHeaders(existing: unknown): string[] {
  const fromServer = (Array.isArray(existing) ? existing : typeof existing === "string" ? [existing] : [])
    .flatMap((entry) => String(entry).split(","))
    .map((entry) => entry.trim())
    .filter(Boolean)

  const merged: string[] = []
  const seen = new Set<string>()
  for (const header of [...fromServer, ...RENDERER_ALLOWED_HEADERS]) {
    const key = header.toLowerCase()
    if (seen.has(key)) continue
    seen.add(key)
    merged.push(header)
  }
  return merged
}

/** Lee un header sin depender de cómo venga capitalizado. */
export function findHeaderValue(headers: Record<string, unknown>, name: string) {
  const lower = name.toLowerCase()
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return headers[key]
  }
  return undefined
}

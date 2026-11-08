/**
 * Política de recuperación de terminales.
 *
 * Cuando una terminal pierde la conexión, la app clona su PTY para que el
 * usuario conserve una terminal viva. Eso está bien ante una caída transitoria
 * (el servidor se reinició, el PTY murió), pero es peligroso ante un fallo
 * SISTÉMICO: si el motor de terminal no puede cargar, la terminal clonada falla
 * igual y clona otra, que falla y clona otra... Terminal 1, 2, 3, 4... sin
 * límite, cada una con su toast de "Conexión perdida".
 *
 * El guard anterior indexaba por `titleNumber`, pero cada clon recibe un número
 * NUEVO, así que la clave siempre era distinta y nunca frenaba nada.
 *
 * La regla aquí es: se permite recuperar mientras alguna terminal haya logrado
 * conectar. Una racha de recuperaciones sin una sola conexión exitosa significa
 * que el problema no es transitorio, y clonar más no lo va a arreglar.
 */

/** Recuperaciones consecutivas permitidas sin que ninguna llegue a conectar. */
export const MAX_RECOVERY_STREAK = 3

export interface RecoveryState {
  /** PTYs que ya intentamos recuperar (por id, que sí es estable). */
  readonly attempted: Readonly<Record<string, boolean>>
  /** Recuperaciones seguidas sin una conexión exitosa de por medio. */
  readonly streak: number
}

export type RecoveryDecision =
  | { recover: false; reason: "already-attempted" | "systemic-failure" }
  | { recover: true; next: { attemptedID: string; streak: number } }

export function decideRecovery(state: RecoveryState, ptyID: string): RecoveryDecision {
  if (state.attempted[ptyID]) return { recover: false, reason: "already-attempted" }
  if (state.streak >= MAX_RECOVERY_STREAK) return { recover: false, reason: "systemic-failure" }
  return { recover: true, next: { attemptedID: ptyID, streak: state.streak + 1 } }
}

/**
 * Qué hacer ante un fallo de conexión.
 *
 * `gone` significa que el servidor respondió 404: esa PTY no existe. Pasa
 * siempre que se reinicia el servidor, porque las PTY viven en memoria pero la
 * lista de terminales se persiste en localStorage. Clonar una PTY muerta sólo
 * produce otra muerta, así que se descarta.
 */
export type ConnectFailureAction =
  | { action: "drop" }
  | { action: "clone"; next: { attemptedID: string; streak: number } }
  | { action: "give-up"; reason: "already-attempted" | "systemic-failure" }

export function onConnectFailure(state: RecoveryState, ptyID: string, gone: boolean): ConnectFailureAction {
  if (gone) return { action: "drop" }
  const decision = decideRecovery(state, ptyID)
  if (!decision.recover) return { action: "give-up", reason: decision.reason }
  return { action: "clone", next: decision.next }
}

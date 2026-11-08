import { describe, expect, test } from "bun:test"
import { decideRecovery, MAX_RECOVERY_STREAK, onConnectFailure, type RecoveryState } from "./terminal-recovery"

const empty: RecoveryState = { attempted: {}, streak: 0 }

/** Simula la cascada real: cada recuperación clona un PTY con un id NUEVO. */
function runCascade(limit: number) {
  let state: RecoveryState = empty
  let clones = 0
  for (let i = 0; i < limit; i++) {
    const decision = decideRecovery(state, `pty_${i}`)
    if (!decision.recover) return { clones, stoppedBy: decision.reason }
    clones++
    state = {
      attempted: { ...state.attempted, [decision.next.attemptedID]: true },
      streak: decision.next.streak,
    }
  }
  return { clones, stoppedBy: undefined }
}

describe("decideRecovery", () => {
  test("stops the unbounded clone cascade on a systemic failure", () => {
    // Antes esto no paraba nunca: la clave era el titleNumber, que cambiaba en
    // cada clon, así que el guard jamás coincidía.
    const result = runCascade(100)
    expect(result.clones).toBe(MAX_RECOVERY_STREAK)
    expect(result.stoppedBy).toBe("systemic-failure")
  })

  test("never recovers the same pty twice", () => {
    const first = decideRecovery(empty, "pty_a")
    expect(first.recover).toBe(true)

    const after: RecoveryState = { attempted: { pty_a: true }, streak: 1 }
    const second = decideRecovery(after, "pty_a")
    expect(second.recover).toBe(false)
    if (!second.recover) expect(second.reason).toBe("already-attempted")
  })

  test("a successful connect resets the streak so later drops still recover", () => {
    // Caso legítimo: se reinicia el servidor, varias terminales caen, pero cada
    // reconexión exitosa limpia la racha.
    let state: RecoveryState = { attempted: {}, streak: MAX_RECOVERY_STREAK }
    expect(decideRecovery(state, "pty_x").recover).toBe(false)

    // markTerminalConnected -> streak = 0
    state = { attempted: state.attempted, streak: 0 }
    expect(decideRecovery(state, "pty_x").recover).toBe(true)
  })

  test("allows many recoveries as long as connections keep succeeding", () => {
    let state: RecoveryState = empty
    for (let i = 0; i < 20; i++) {
      const decision = decideRecovery(state, `pty_${i}`)
      expect(decision.recover).toBe(true)
      // Cada intento conecta bien -> la racha vuelve a cero.
      state = { attempted: { ...state.attempted, [`pty_${i}`]: false }, streak: 0 }
    }
  })
})

describe("onConnectFailure", () => {
  test("drops a pty the server no longer has instead of cloning it", () => {
    // Servidor reiniciado: las PTY viven en memoria, la lista en localStorage.
    expect(onConnectFailure(empty, "pty_stale", true)).toEqual({ action: "drop" })
  })

  test("dropping never consumes the recovery budget", () => {
    let state: RecoveryState = empty
    for (let i = 0; i < 10; i++) {
      expect(onConnectFailure(state, `pty_stale_${i}`, true).action).toBe("drop")
      // drop no toca el estado, así que la racha sigue intacta...
    }
    // ...y una caída transitoria posterior todavía puede recuperarse.
    expect(onConnectFailure(state, "pty_live", false).action).toBe("clone")
  })

  test("still clones on a transient failure, and still stops when systemic", () => {
    expect(onConnectFailure(empty, "pty_live", false).action).toBe("clone")

    const exhausted: RecoveryState = { attempted: {}, streak: MAX_RECOVERY_STREAK }
    const result = onConnectFailure(exhausted, "pty_live", false)
    expect(result.action).toBe("give-up")
    if (result.action === "give-up") expect(result.reason).toBe("systemic-failure")
  })
})

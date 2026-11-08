import { describe, expect, test } from "bun:test"
import { staticAppEnv } from "./app-env"

describe("staticAppEnv", () => {
  test("disables external skill discovery (.claude/.agents)", () => {
    // Regresión: sin esta bandera, el descubrimiento de skills de opencode
    // camina hacia arriba desde el directorio del CLIENTE que se está
    // auditando buscando .claude/.agents (ver
    // packages/argos/src/skill/index.ts). Un SKILL.md plantado en el
    // repo auditado se cargaría como si fuera nuestro. Argos solo debe
    // leer skills de OPENCODE_CONFIG_DIR (argos-config/skills/**),
    // que no pasa por esta bandera.
    const env = staticAppEnv("C:/fake/user-data")
    expect(env.ARGOS_DISABLE_EXTERNAL_SKILLS).toBe("true")
    expect(env.OPENCODE_DISABLE_EXTERNAL_SKILLS).toBe("true")
  })

  test("identifies the client as desktop", () => {
    const env = staticAppEnv("C:/fake/user-data")
    expect(env.ARGOS_CLIENT).toBe("desktop")
    expect(env.OPENCODE_CLIENT).toBe("desktop")
  })

  test("derives XDG dirs from userDataPath when not already set", () => {
    const original = process.env.XDG_CONFIG_HOME
    delete process.env.XDG_CONFIG_HOME
    try {
      const env = staticAppEnv("C:/fake/user-data")
      expect(env.XDG_CONFIG_HOME).toContain("user-data")
      expect(env.XDG_CONFIG_HOME).toContain("config")
    } finally {
      if (original !== undefined) process.env.XDG_CONFIG_HOME = original
    }
  })

  test("respects an already-set XDG_CONFIG_HOME instead of overriding it", () => {
    const original = process.env.XDG_CONFIG_HOME
    process.env.XDG_CONFIG_HOME = "/custom/xdg/config"
    try {
      const env = staticAppEnv("C:/fake/user-data")
      expect(env.XDG_CONFIG_HOME).toBe("/custom/xdg/config")
    } finally {
      if (original === undefined) delete process.env.XDG_CONFIG_HOME
      else process.env.XDG_CONFIG_HOME = original
    }
  })
})

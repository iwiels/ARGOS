import { describe, expect, test } from "bun:test"
import fs from "fs/promises"
import os from "os"
import path from "path"
import { Global } from "@argos/core/global"

describe("global paths", () => {
  test("tmp path is under the system temp directory", () => {
    expect(Global.Path.tmp).toBe(path.join(os.tmpdir(), "argos"))
    expect(Global.make().tmp).toBe(Global.Path.tmp)
  })

  test("tmp path is created on module load", async () => {
    expect((await fs.stat(Global.Path.tmp)).isDirectory()).toBe(true)
  })

  test("home respects ARGOS_TEST_HOME and falls back to OPENCODE_TEST_HOME", () => {
    const originalArgos = process.env.ARGOS_TEST_HOME
    const originalOpencode = process.env.OPENCODE_TEST_HOME
    try {
      delete process.env.ARGOS_TEST_HOME
      process.env.OPENCODE_TEST_HOME = "/fake/opencode/home"
      expect(Global.Path.home).toBe("/fake/opencode/home")

      process.env.ARGOS_TEST_HOME = "/fake/argos/home"
      expect(Global.Path.home).toBe("/fake/argos/home")
    } finally {
      if (originalArgos !== undefined) process.env.ARGOS_TEST_HOME = originalArgos
      else delete process.env.ARGOS_TEST_HOME
      if (originalOpencode !== undefined) process.env.OPENCODE_TEST_HOME = originalOpencode
      else delete process.env.OPENCODE_TEST_HOME
    }
  })
})

import { describe, expect, test } from "bun:test"
import { FSUtil } from "../src/fs-util"

describe("FSUtil.normalizeRuntimePath", () => {
  test("maps Windows drive paths to WSL automount paths", () => {
    expect(FSUtil.normalizeRuntimePath("C:\\Users\\victo\\Downloads\\prueba-ciber", true)).toBe(
      "/mnt/c/Users/victo/Downloads/prueba-ciber",
    )
  })

  test("accepts forward-slash Windows drive paths", () => {
    expect(FSUtil.normalizeRuntimePath("D:/work/project", true)).toBe("/mnt/d/work/project")
  })

  test("leaves Linux paths and non-WSL Windows paths unchanged", () => {
    expect(FSUtil.normalizeRuntimePath("/home/argos/project", true)).toBe("/home/argos/project")
    expect(FSUtil.normalizeRuntimePath("C:\\work\\project", false)).toBe("C:\\work\\project")
    expect(FSUtil.resolveRuntimePath("C:\\work\\project", false)).toBe("C:\\work\\project")
  })
})

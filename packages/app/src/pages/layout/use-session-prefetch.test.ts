import { describe, expect, test } from "bun:test"
import { mergeByID } from "./use-session-prefetch"

describe("mergeByID", () => {
  test("returns empty when both arrays are empty", () => {
    expect(mergeByID([], [])).toEqual([])
  })

  test("returns incoming sorted when current is empty", () => {
    const items = [{ id: "c" }, { id: "a" }, { id: "b" }]
    const result = mergeByID([], items)
    expect(result.map((i) => i.id)).toEqual(["a", "b", "c"])
  })

  test("merges incoming into current, incoming wins on id collision", () => {
    const current = [{ id: "1", v: "old" }, { id: "2", v: "old" }]
    const incoming = [{ id: "2", v: "new" }, { id: "3", v: "new" }]
    const result = mergeByID(current, incoming)
    expect(result).toEqual([
      { id: "1", v: "old" },
      { id: "2", v: "new" },
      { id: "3", v: "new" },
    ])
  })

  test("result is sorted by id", () => {
    const current = [{ id: "z" }, { id: "m" }]
    const incoming = [{ id: "a" }, { id: "z" }]
    const result = mergeByID(current, incoming)
    expect(result.map((i) => i.id)).toEqual(["a", "m", "z"])
  })

  test("does not mutate input arrays", () => {
    const current = [{ id: "1" }]
    const incoming = [{ id: "2" }]
    mergeByID(current, incoming)
    expect(current).toEqual([{ id: "1" }])
    expect(incoming).toEqual([{ id: "2" }])
  })
})

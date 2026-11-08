import { describe, expect, it } from "bun:test"
import { Schema } from "effect"
import {
  SecurityFindingCaseMergeInput,
  SecurityFindingCaseOperationHistoryQuery,
  SecurityFindingCaseReverseInput,
  SecurityFindingCaseSplitInput,
  SecurityFindingCaseStatusInput,
  SecurityFindingCaseHistoryQuery,
  SecurityFindingCasesQuery,
  SecurityFindingImportInput,
  SecurityFindingsQuery,
} from "./security"

describe("SecurityFindingsQuery", () => {
  it("decodes the includeSuppressed query string to a boolean", () => {
    const decode = Schema.decodeUnknownSync(SecurityFindingsQuery)

    expect(decode({ includeSuppressed: "true" }).includeSuppressed).toBe(true)
    expect(decode({ includeSuppressed: "false" }).includeSuppressed).toBe(false)
    expect(() => decode({ includeSuppressed: "yes" })).toThrow()
  })
})

describe("SecurityFindingImportInput", () => {
  it("accepts only registered import formats and bounded payloads", () => {
    const decode = Schema.decodeUnknownSync(SecurityFindingImportInput)
    expect(decode({ format: "sarif-2.1", content: '{"version":"2.1.0"}', importID: "ci-run-24" })).toMatchObject({
      format: "sarif-2.1",
      importID: "ci-run-24",
    })
    expect(() => decode({ format: "unknown", content: "{}" })).toThrow()
    expect(() => decode({ format: "nuclei-jsonl", content: "x".repeat(8 * 1024 * 1024 + 1) })).toThrow()
  })
})

describe("finding case contracts", () => {
  it("bounds pagination and requires an expiry for accepted-risk updates", () => {
    const decodeQuery = Schema.decodeUnknownSync(SecurityFindingCasesQuery)
    const decodeHistoryQuery = Schema.decodeUnknownSync(SecurityFindingCaseHistoryQuery)
    expect(decodeQuery({ limit: "25", offset: "0" })).toEqual({ limit: 25, offset: 0 })
    expect(() => decodeQuery({ limit: "201" })).toThrow()
    expect(decodeHistoryQuery({ limit: "100" })).toEqual({ limit: 100 })
    expect(() => decodeHistoryQuery({ limit: "101" })).toThrow()

    const decodeInput = Schema.decodeUnknownSync(SecurityFindingCaseStatusInput)
    expect(decodeInput({ status: "in-progress", reason: "Assigned" })).toMatchObject({ status: "in-progress" })
    expect(decodeInput({ status: "accepted-risk", acceptedRiskUntil: 2_000_000_000_000 })).toMatchObject({
      status: "accepted-risk",
      acceptedRiskUntil: 2_000_000_000_000,
    })
    expect(() => decodeInput({ status: "unknown" })).toThrow()
    expect(() => decodeInput({ status: "accepted-risk", acceptedRiskUntil: -1 })).toThrow()
  })

  it("bounds reversible case operation inputs", () => {
    const decodeMerge = Schema.decodeUnknownSync(SecurityFindingCaseMergeInput)
    const decodeSplit = Schema.decodeUnknownSync(SecurityFindingCaseSplitInput)
    const decodeReverse = Schema.decodeUnknownSync(SecurityFindingCaseReverseInput)
    const decodeHistory = Schema.decodeUnknownSync(SecurityFindingCaseOperationHistoryQuery)
    expect(decodeMerge({ targetCaseID: "case-2", reason: "Same endpoint and parameter" })).toMatchObject({
      targetCaseID: "case-2",
    })
    expect(() => decodeMerge({ targetCaseID: "case-2", reason: "  " })).toThrow()
    expect(decodeSplit({ findingIDs: ["finding-1"], reason: "Different root cause" })).toMatchObject({
      findingIDs: ["finding-1"],
    })
    expect(() => decodeSplit({ findingIDs: [], reason: "No findings" })).toThrow()
    expect(() =>
      decodeSplit({ findingIDs: Array.from({ length: 501 }, (_, i) => `finding-${i}`), reason: "Split" }),
    ).toThrow()
    expect(decodeReverse({ reason: "Undo incorrect merge" })).toMatchObject({ reason: "Undo incorrect merge" })
    expect(() => decodeReverse({ reason: " " })).toThrow()
    expect(decodeHistory({ limit: "100" })).toEqual({ limit: 100 })
    expect(() => decodeHistory({ limit: "101" })).toThrow()
  })
})

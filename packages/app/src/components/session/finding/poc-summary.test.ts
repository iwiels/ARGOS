import { describe, expect, test } from "bun:test"
import { pocSummaryFromEvidence } from "./poc-summary"

describe("pocSummaryFromEvidence", () => {
  test("lee el PoC cuando la evidencia lo lleva dentro", () => {
    const summary = pocSummaryFromEvidence(
      JSON.stringify({
        surface: "query",
        parameter: "id",
        poc: {
          kind: "sqli",
          method: "GET",
          url: "http://target.test/item?id=1",
          payload: "1' AND '1'='1",
          matcher: { kind: "body_absent", needle: "1' AND '1'='1" },
        },
      }),
    )
    expect(summary?.kind).toBe("sqli")
    expect(summary?.matcher).toBe("body_absent")
    expect(summary?.method).toBe("GET")
    expect(summary?.url).toBe("http://target.test/item?id=1")
    expect(summary?.payload).toBe("1' AND '1'='1")
  })

  test("lee el PoC cuando la evidencia ya viene desenvuelta", () => {
    const summary = pocSummaryFromEvidence(
      JSON.stringify({
        kind: "xss",
        method: "GET",
        url: "http://target.test/?q=%3Cscript%3E",
        matcher: { kind: "body_absent", needle: "<script>" },
      }),
    )
    expect(summary?.kind).toBe("xss")
    expect(summary?.matcher).toBe("body_absent")
  })

  test("ignora una evidencia que no es un PoC", () => {
    expect(pocSummaryFromEvidence(undefined)).toBeUndefined()
    expect(pocSummaryFromEvidence("mysql_fetch_array()")).toBeUndefined()
    expect(pocSummaryFromEvidence("{}")).toBeUndefined()
    expect(pocSummaryFromEvidence(JSON.stringify({ kind: "sqli" }))).toBeUndefined()
    expect(pocSummaryFromEvidence(JSON.stringify({ kind: "sqli", matcher: {} }))).toBeUndefined()
  })
})

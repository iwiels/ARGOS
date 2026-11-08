/**
 * Coverage gate: parses bun's `--coverage` text report from stdin and fails
 * when the "All files" totals fall below the configured floors.
 *
 * Usage: bun test --coverage ... | bun scripts/coverage-gate.ts <minLines> <minFuncs>
 *
 * (bunfig coverageThreshold is unreliable in this environment - it exits 1
 * with no message - so the gate lives here where it is deterministic.)
 */
const raw = await new Response(Bun.stdin.stream()).text()

const [minLinesArg, minFuncsArg] = process.argv.slice(2)
const minLines = Number(minLinesArg)
const minFuncs = Number(minFuncsArg)

if (!Number.isFinite(minLines) || !Number.isFinite(minFuncs)) {
  console.error("coverage-gate: usage <minLines> <minFuncs>")
  process.exit(2)
}

const rows = raw.split("\n")
const header = rows.find((line) => line.trim().startsWith("File"))
const summaryRow = rows.find((line) => line.startsWith("All files"))
if (!header || !summaryRow) {
  console.error("coverage-gate: coverage report table not found in input")
  process.exit(2)
}

const headers = header.split("|").map((cell) => cell.trim().toLowerCase())
const funcsIndex = headers.findIndex((cell) => cell.includes("funcs"))
const linesIndex = headers.findIndex((cell) => cell.includes("lines"))
if (funcsIndex === -1 || linesIndex === -1) {
  console.error(`coverage-gate: unexpected table header: ${header}`)
  process.exit(2)
}

const cells = summaryRow.split("|").map((cell) => cell.trim())
const funcs = Number(cells[funcsIndex])
const lines = Number(cells[linesIndex])

if (!Number.isFinite(lines) || !Number.isFinite(funcs)) {
  console.error(`coverage-gate: could not parse summary row: ${row}`)
  process.exit(2)
}

console.log(`coverage-gate: lines ${lines}% (min ${minLines}) · funcs ${funcs}% (min ${minFuncs})`)

if (lines < minLines || funcs < minFuncs) {
  console.error("coverage-gate: FAILED")
  process.exit(1)
}

console.log("coverage-gate: OK")

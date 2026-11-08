export interface PatchGenerationInput {
  filePath: string
  originalContent: string
  remediatedContent: string
  findingID?: string
  cwe?: string
  title?: string
}

export interface GeneratedPatch {
  filePath: string
  patch: string
  hasChanges: boolean
  additions: number
  deletions: number
}

export class RemediationPatchService {
  /**
   * Genera un patch unificado estándar (unified diff) sin dependencias externas (Etapa 3).
   */
  static generatePatch(input: PatchGenerationInput): GeneratedPatch {
    const original = input.originalContent
    const modified = input.remediatedContent

    if (original === modified) {
      return {
        filePath: input.filePath,
        patch: "",
        hasChanges: false,
        additions: 0,
        deletions: 0,
      }
    }

    const origLines = original.split(/\r?\n/)
    const modLines = modified.split(/\r?\n/)

    const hunks = RemediationPatchService.computeHunks(origLines, modLines)
    if (hunks.length === 0) {
      return {
        filePath: input.filePath,
        patch: "",
        hasChanges: false,
        additions: 0,
        deletions: 0,
      }
    }

    const header = [
      `--- a/${input.filePath}`,
      `+++ b/${input.filePath}`,
    ]

    let additions = 0
    let deletions = 0

    const hunkStrings: string[] = []
    for (const hunk of hunks) {
      hunkStrings.push(`@@ -${hunk.origStart},${hunk.origCount} +${hunk.modStart},${hunk.modCount} @@`)
      for (const line of hunk.lines) {
        if (line.startsWith("+")) additions++
        if (line.startsWith("-")) deletions++
        hunkStrings.push(line)
      }
    }

    const fullPatch = [...header, ...hunkStrings].join("\n") + "\n"

    return {
      filePath: input.filePath,
      patch: fullPatch,
      hasChanges: true,
      additions,
      deletions,
    }
  }

  private static computeHunks(
    a: string[],
    b: string[],
  ): Array<{ origStart: number; origCount: number; modStart: number; modCount: number; lines: string[] }> {
    // Computar matriz LCS
    const m = a.length
    const n = b.length
    const dp: number[][] = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0))

    for (let i = 0; i < m; i++) {
      for (let j = 0; j < n; j++) {
        if (a[i] === b[j]) {
          dp[i + 1][j + 1] = dp[i][j] + 1
        } else {
          dp[i + 1][j + 1] = Math.max(dp[i + 1][j], dp[i][j + 1])
        }
      }
    }

    // Reconstruir diff
    const diffOps: Array<{ type: "=" | "-" | "+"; text: string; origIdx: number; modIdx: number }> = []
    let i = m
    let j = n

    while (i > 0 || j > 0) {
      if (i > 0 && j > 0 && a[i - 1] === b[j - 1]) {
        diffOps.unshift({ type: "=", text: a[i - 1], origIdx: i, modIdx: j })
        i--
        j--
      } else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) {
        diffOps.unshift({ type: "+", text: b[j - 1], origIdx: i, modIdx: j })
        j--
      } else if (i > 0 && (j === 0 || dp[i][j - 1] < dp[i - 1][j])) {
        diffOps.unshift({ type: "-", text: a[i - 1], origIdx: i, modIdx: j })
        i--
      }
    }

    // Agrupar en hunks con 3 líneas de contexto
    const hunks: Array<{ origStart: number; origCount: number; modStart: number; modCount: number; lines: string[] }> = []
    let currentHunk: { origStart: number; origCount: number; modStart: number; modCount: number; lines: string[] } | null = null

    let origLineNum = 1
    let modLineNum = 1

    for (const op of diffOps) {
      if (op.type === "=") {
        if (currentHunk) {
          currentHunk.lines.push(` ${op.text}`)
          currentHunk.origCount++
          currentHunk.modCount++
        }
        origLineNum++
        modLineNum++
      } else if (op.type === "-") {
        if (!currentHunk) {
          currentHunk = {
            origStart: origLineNum,
            origCount: 0,
            modStart: modLineNum,
            modCount: 0,
            lines: [],
          }
          hunks.push(currentHunk)
        }
        currentHunk.lines.push(`-${op.text}`)
        currentHunk.origCount++
        origLineNum++
      } else if (op.type === "+") {
        if (!currentHunk) {
          currentHunk = {
            origStart: origLineNum,
            origCount: 0,
            modStart: modLineNum,
            modCount: 0,
            lines: [],
          }
          hunks.push(currentHunk)
        }
        currentHunk.lines.push(`+${op.text}`)
        currentHunk.modCount++
        modLineNum++
      }
    }

    return hunks
  }
}

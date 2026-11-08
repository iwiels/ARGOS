/**
 * Redaction pass applied to every text file that leaves the machine in an
 * exported debug-log bundle. Renderer console is mirrored into log files
 * and the netlog records URLs, so credentials that end up there must not
 * leave in plaintext.
 */

const PATTERNS: Array<[RegExp, string]> = [
  // PTY / WS connection tickets and any other token passed as query param.
  [/(auth_token=)[^&\s"')]+/gi, "$1[REDACTED]"],
  // Authorization headers pasted into logs.
  [/(bearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi, "$1[REDACTED]"],
  [/(x-api-key\s*[:=]\s*)[^\s,"'}\]]+/gi, "$1[REDACTED]"],
  [/(authorization\s*[:=]\s*["']?)[^"'\s,}]+/gi, "$1[REDACTED]"],
  // JSON-ish fields persisted by settings or echoed by the server.
  [/("(?:password|api[_-]?key|secret|token)"\s*:\s*")[^"]+/gi, "$1[REDACTED]"],
  // Basic-auth embedded in URLs.
  [/(\w[\w.-]*:\/\/[^/\s:@"]+:)([^@\s/"]+@)/g, "$1[REDACTED]@"],
]

export function redactSecrets(input: string): string {
  let output = input
  for (const [pattern, replacement] of PATTERNS) {
    output = output.replace(pattern, replacement)
  }
  return output
}

/** Only plain-text formats are rewritten; binaries (crash dumps) are skipped. */
export function isRedactableFile(name: string): boolean {
  return /\.(log|json|ndjson|txt)$/i.test(name)
}

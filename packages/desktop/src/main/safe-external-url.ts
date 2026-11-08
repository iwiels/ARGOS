/**
 * Single choke point for every URL that leaves the app through
 * `shell.openExternal` (IPC `open-link`, terminal link parsing, markdown
 * anchors, blocked navigations).
 *
 * Only http(s) is allowed: schemes like `file:`, `ms-msdt:`, `search-ms:` or
 * `smb:` are known Windows command-execution / phishing vectors when handed
 * to the OS shell handler.
 */
export function isSafeExternalUrl(value: unknown): value is string {
  if (typeof value !== "string" || !URL.canParse(value)) return false
  const protocol = new URL(value).protocol
  return protocol === "https:" || protocol === "http:"
}

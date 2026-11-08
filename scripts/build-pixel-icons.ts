import * as fs from "node:fs"
import * as path from "node:path"

const iconsDir = path.resolve(process.cwd(), "docs/design-reference/streamline-pixel/icons")
const outFile = path.resolve(process.cwd(), "packages/ui/src/components/pixel-icons.data.ts")

const files = fs.readdirSync(iconsDir).filter((f) => f.endsWith(".svg"))

console.log(`Processing ${files.length} pixel icons...`)

const iconsMap: Record<string, string> = {}

for (const file of files) {
  const content = fs.readFileSync(path.join(iconsDir, file), "utf-8")
  const pathMatches = Array.from(content.matchAll(/<path[^>]*d="([^"]+)"/gi)).map((m) => m[1])
  if (pathMatches.length > 0) {
    const slug = file.replace(/\.svg$/, "")
    iconsMap[slug] = pathMatches.join(" ")
  }
}

// Crisp pixel art primitives for universal UI operations
iconsMap["plus"] = "M14 6h4v8h8v4h-8v8h-4v-8H6v-4h8V6z"
iconsMap["minus"] = "M6 14h20v4H6z"
iconsMap["close"] = "M6 6h4v4h4v-4h4v4h-4v4h4v4h-4v-4h-4v4H6v-4h4v-4H6V6z"
iconsMap["xmark-small"] = "M8 8h3v3h3v-3h3v3h-3v3h3v3h-3v-3h-3v3H8v-3h3v-3H8V8z"
iconsMap["chevron-right"] = "M12 6h4v4h4v4h4v4h-4v4h-4v4h-4v-4h4v-4h4v-4h-4v-4h-4V6z"
iconsMap["chevron-down"] = "M6 12h4v4h4v4h4v4h4v-4h-4v-4h-4v-4h-4v-4H6v4z"
iconsMap["chevron-left"] = "M20 6h-4v4h-4v4H8v4h4v4h4v4h4v-4h-4v-4h-4v-4h4v-4h4V6z"
iconsMap["chevron-up"] = "M6 20h4v-4h4v-4h4v-4h4v4h-4v4h-4v4h-4v4H6v-4z"

// Add intuitive short aliases for core Cockpit SecOps icons
const aliases: Record<string, string> = {
  "alert-triangle": "interface-essential-alert-triangle-1",
  "alert": "interface-essential-alert-triangle-1",
  "shield-check": "coding-apps-websites-shield-lock",
  "shield": "interface-essential-lock-shield",
  "terminal": "coding-apps-websites-programming-hold-code",
  "code": "coding-apps-websites-programming-hold-code",
  "bug": "coding-apps-websites-programming-bug",
  "folder": "content-files-folder-open",
  "folder-open": "content-files-folder-open",
  "folder-closed": "content-files-folder-open",
  "dossier": "content-files-folder-open",
  "radar": "interface-essential-stat",
  "topology": "interface-essential-stat",
  "network": "interface-essential-stat",
  "robot": "technology-robot-ai",
  "agent": "technology-robot-ai",
  "bin": "interface-essential-bin",
  "trash": "interface-essential-bin",
  "clock": "interface-essential-clock",
  "lock": "interface-essential-lock",
  "search": "interface-essential-search-1",
  "magnifying-glass": "interface-essential-search-1",
  "search-bug": "coding-apps-websites-search-bug",
  "check": "interface-essential-check-1",
  "gear": "interface-essential-setting-cog",
  "settings": "interface-essential-setting-cog",
  "settings-gear": "interface-essential-setting-cog",
  "document": "interface-essential-folder-document",
  "copy": "interface-essential-copy-paste-select-add",
  "chat": "interface-essential-message",
  "message": "interface-essential-message",
  "checklist": "interface-essential-list",
  "server": "coding-apps-websites-database",
  "database": "coding-apps-websites-database",
  "help": "interface-essential-question-help-circle-1",
  "eye": "interface-essential-view-eye",
  "battery": "interface-essential-battery",
  "globe": "interface-essential-global-public",
  "box": "building-real-eastate-storage",
  "open-file": "content-files-folder-open",
  "download": "internet-network-computer-download",
  "warning": "interface-essential-alert-triangle-1",
  "refresh": "interface-essential-refresh",
  "check-small": "interface-essential-check-1",
  "paperclip": "interface-essential-clip-1",
  "dot-grid": "interface-essential-dial-pad-1",
  "more": "interface-essential-dial-pad-1",
  "stop": "interface-essential-stop-sign-1",
  "brain": "interface-essential-face-id",
  "dot-grid": "interface-essential-dial-pad-2",
  "sparkle": "interface-essential-flash",
  "zap": "interface-essential-flash",
  "folder-document": "business-products-data-file-bars",
  "dossier": "business-products-data-file-bars",
  "file": "content-files-note",
  "report-sparkle": "business-products-data-file-bars",
  "radar": "interface-essential-stat",
  "target": "business-product-target",
  "printer": "interface-essential-print",
  "upload": "internet-network-upload",
  "cloud-upload": "internet-network-upload",
  "cloud-download": "interface-essential-clound-download",
  "copy": "content-files-write-note",
  "clipboard": "content-files-write-note",
  "paperclip": "interface-essential-clip-1",
  "link": "interface-essential-hyperlink",
  "glasses": "interface-essential-search-binocular",
  "probe": "interface-essential-search-binocular",
  "document": "content-files-note",
  "file-text": "content-files-note",
  "note": "content-files-note",
  "book": "content-files-book",
  "contacts": "content-files-phone-book",
  "archive": "content-files-archive-books-1",
  "new-session": "content-files-folder-open",
  "folder-new": "content-files-folder-open",
  "folder-add-left": "content-files-folder-open",
  "log": "content-files-notepad",
  "compass": "interface-essential-safari-compass",
  "safari-compass": "interface-essential-safari-compass",
  "stat": "interface-essential-stat",
  "chart": "business-product-report-present-grahp",
  "history": "interface-essential-clock",
  "key": "interface-essential-key",
  "key-lock": "interface-essential-key-lock",
  "password": "interface-essential-key-lock",
  "credentials": "interface-essential-key",
  "protect-guard": "interface-essential-protect-guard",
  "user-shield": "single-user-shield",
  "user": "single-user-shield",
  "users": "multiple-user",
  "profile": "interface-essential-profile-male",
  "print": "interface-essential-print",
  "send": "interface-essential-send-mail",
  "mail": "interface-essential-send-mail",
  "save": "interface-essential-floppy-disk",
  "skull": "interface-essential-skull-1",
  "critical": "interface-essential-skull-1",
  "firewall": "coding-apps-websites-firewall",
  "wifi": "interface-essential-wifi-signal",
  "upload-file": "internet-network-computer-upload",
  "computer": "computers-devices-electronics-monitor",
  "monitor": "computers-devices-electronics-monitor",
  "desktop": "computers-devices-electronics-monitor",
}

for (const [alias, target] of Object.entries(aliases)) {
  if (iconsMap[target]) {
    iconsMap[alias] = iconsMap[target]
  }
}

const tsContent = `// Auto-generated by scripts/build-pixel-icons.ts - Streamline Pixel Icons (CC BY 4.0)
export const PIXEL_ICONS: Record<string, string> = ${JSON.stringify(iconsMap, null, 2)}
`

fs.writeFileSync(outFile, tsContent, "utf-8")
console.log(`Wrote ${Object.keys(iconsMap).length} pixel icon definitions to ${outFile}`)

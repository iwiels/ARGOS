import fs from "fs"
import path from "path"

const outDir = path.resolve("docs/design-reference/streamline-pixel/icons")
fs.mkdirSync(outDir, { recursive: true })

async function fetchAllIcons() {
  let skip = 0
  let totalSaved = 0
  const manifest: Array<{ slug: string; name: string; category: string; filename: string }> = []

  while (true) {
    console.log(`Fetching skip=${skip}...`)
    const res = await fetch(`https://api-production.streamlinehq.com/v5/icons/grouped/pixel?skip=${skip}`, {
      headers: { "x-requester": "StreamlineApp" },
    })
    if (!res.ok) {
      console.error("Failed to fetch:", res.status)
      break
    }
    const data = (await res.json()) as any
    const groups = data.iconsGrouped || {}
    let batchCount = 0

    for (const [groupId, icons] of Object.entries<any[]>(groups)) {
      for (const icon of icons) {
        if (!icon.svg || !icon.slug) continue
        const filename = `${icon.slug}.svg`
        const normalizedSvg = icon.svg
          .replace(/var\(--sl-c-000000,#000000\)/g, "currentColor")
          .replace(/fill="#000000"/g, 'fill="currentColor"')
        fs.writeFileSync(path.join(outDir, filename), normalizedSvg, "utf8")
        manifest.push({
          slug: icon.slug,
          name: icon.name,
          category: icon.subcategoryName || groupId,
          filename,
        })
        batchCount++
        totalSaved++
      }
    }

    console.log(`Batch saved: ${batchCount}, Total so far: ${totalSaved}`)
    if (!data.pagination?.hasMore || batchCount === 0) {
      break
    }
    skip = data.pagination.nextSkip
  }

  const manifestPath = path.resolve("docs/design-reference/streamline-pixel/manifest.json")
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), "utf8")
  console.log(`Successfully saved ${totalSaved} pixel SVG icons and manifest.json!`)
}

fetchAllIcons().catch(console.error)

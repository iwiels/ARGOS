import { writeFileSync } from "node:fs"
import { resolveChannel } from "./utils"

const arg = process.argv[2]
const channel = arg === "dev" || arg === "beta" || arg === "prod" ? arg : resolveChannel()

const appId = channel === "prod" ? "ai.argos.desktop" : `ai.argos.desktop.${channel}`
const productName = channel === "prod" ? "Argos" : `Argos ${channel.charAt(0).toUpperCase() + channel.slice(1)}`
const summary = `AI-powered security auditing platform${channel !== "prod" ? ` (${channel})` : ""}`

const xml = `<?xml version="1.0" encoding="UTF-8"?>
<component type="desktop-application">
  <id>${appId}</id>

  <metadata_license>CC0-1.0</metadata_license>
  <project_license>MIT</project_license>

  <name>${productName}</name>
  <summary>${summary}</summary>

  <developer id="ai.argos">
    <name>Argos</name>
  </developer>

  <description>
    <p>
      Argos is an AI-powered platform for security auditing, compliance and threat intelligence.
    </p>
  </description>

  <launchable type="desktop-id">${appId}.desktop</launchable>

  <content_rating type="oars-1.1" />

  <url type="homepage">https://github.com/iwiels/ARGOS</url>
</component>
`

writeFileSync(`resources/${appId}.metainfo.xml`, xml)
console.log(`Generated metainfo for ${channel} at resources/${appId}.metainfo.xml`)

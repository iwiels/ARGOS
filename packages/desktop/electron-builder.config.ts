import type { Configuration } from "electron-builder"

const channel = (() => {
  const raw = process.env.OPENCODE_CHANNEL
  if (raw === "dev" || raw === "beta" || raw === "prod") return raw
  return "dev"
})()

const getBase = (): Configuration => ({
  artifactName: "argos-desktop-${os}-${arch}.${ext}",
  directories: {
    output: "dist",
    buildResources: "resources",
  },
  files: ["out/**/*", "resources/**/*"],
  publish: null,
  extraResources: [
    {
      from: "native/",
      to: "native/",
      filter: ["index.js", "index.d.ts", "build/Release/mac_window.node", "swift-build/**"],
    },
    {
      from: "../../argos-bin/bin/",
      to: "argos-bin/bin/",
      filter: ["!*~", "!*.bak*", "!worker-image.json"],
    },
    {
      from: "../../argos-config/",
      to: "argos-config/",
    },
    { from: "../../LICENSE", to: "LICENSE" },
    { from: "../../NOTICE", to: "NOTICE" },
    { from: "../../THIRD_PARTY_NOTICES.md", to: "THIRD_PARTY_NOTICES.md" },
    { from: "../../third-party-licenses/Inter-OFL.txt", to: "third-party-licenses/Inter-OFL.txt" },
  ],
  mac: {
    category: "public.app-category.developer-tools",
    icon: `resources/icons/icon.icns`,
    hardenedRuntime: true,
    gatekeeperAssess: false,
    entitlements: "resources/entitlements.plist",
    entitlementsInherit: "resources/entitlements.plist",
    notarize: true,
    target: ["dmg", "zip"],
  },
  dmg: {
    sign: true,
  },
  protocols: {
    name: "Argos",
    schemes: ["argos"],
  },
  win: {
    icon: `resources/icons/icon.ico`,
    target: ["nsis"],
    verifyUpdateCodeSignature: true,
  },
  nsis: {
    oneClick: true,
    perMachine: false,
    installerIcon: `resources/icons/icon.ico`,
    installerHeaderIcon: `resources/icons/icon.ico`,
  },
  linux: {
    executableName: channel === "prod" ? "argos" : `argos-${channel}`,
    icon: `resources/icons`,
    category: "Development",
    target: ["AppImage", "deb", "rpm"],
  },
})

function getConfig() {
  const base = getBase()

  switch (channel) {
    case "dev": {
      return {
        ...base,
        appId: "ai.argos.desktop.dev",
        productName: "Argos Dev",
        rpm: { packageName: "argos-dev" },
      }
    }
    case "beta": {
      return {
        ...base,
        appId: "ai.argos.desktop.beta",
        productName: "Argos Beta",
        protocols: { name: "Argos Beta", schemes: ["argos"] },
        rpm: { packageName: "argos-beta" },
      }
    }
    case "prod": {
      return {
        ...base,
        appId: "ai.argos.desktop",
        productName: "Argos",
        protocols: { name: "Argos", schemes: ["argos"] },
        rpm: { packageName: "argos" },
      }
    }
  }
}

export default getConfig()



import { sentryVitePlugin } from "@sentry/vite-plugin"
import { defineConfig } from "electron-vite"
import appPlugin from "@argos/app/vite"
import { cjsInterop } from "vite-plugin-cjs-interop"
import * as fs from "node:fs/promises"

const ARGOS_SERVER_DIST = "../argos/dist/node"

const channel = (() => {
  const raw = process.env.ARGOS_CHANNEL ?? process.env.OPENCODE_CHANNEL
  if (raw === "dev" || raw === "beta" || raw === "prod") return raw
  if (raw === "latest") return "prod"
  return "dev"
})()

const nodePtyPkg = `@lydell/node-pty-${process.platform}-${process.arch}`

const sentry =
  process.env.SENTRY_AUTH_TOKEN && process.env.SENTRY_ORG && process.env.SENTRY_PROJECT
    ? sentryVitePlugin({
        authToken: process.env.SENTRY_AUTH_TOKEN,
        org: process.env.SENTRY_ORG,
        project: process.env.SENTRY_PROJECT,
        telemetry: false,
        release: {
          name: process.env.SENTRY_RELEASE ?? process.env.VITE_SENTRY_RELEASE,
        },
        sourcemaps: {
          assets: "./out/renderer/**",
          filesToDeleteAfterUpload: "./out/renderer/**/*.map",
        },
      })
    : false

export default defineConfig({
  main: {
    define: {
      "import.meta.env.ARGOS_CHANNEL": JSON.stringify(channel),
      "import.meta.env.OPENCODE_CHANNEL": JSON.stringify(channel),
    },
    build: {
      rollupOptions: {
        input: { index: "src/main/index.ts", sidecar: "src/main/sidecar.ts" },
        onLog(level, log) {
          if (level === "warn" && log.message.toLowerCase().includes("eval")) return
        },
      },
      externalizeDeps: { include: [nodePtyPkg] },
    },
    plugins: [
      {
        name: "argos:node-pty-narrower",
        enforce: "pre",
        resolveId(s) {
          if (s === "@lydell/node-pty") return nodePtyPkg
        },
      },
      {
        name: "argos:virtual-server-module",
        enforce: "pre",
        resolveId(id) {
          if (id === "virtual:argos-server" || id === "virtual:opencode-server") {
            return this.resolve(`${ARGOS_SERVER_DIST}/node.js`)
          }
        },
      },
      {
        name: "argos:copy-server-assets",
        async writeBundle() {
          for (const l of await fs.readdir(ARGOS_SERVER_DIST)) {
            if (!l.endsWith(".wasm")) continue
            await fs.writeFile(`./out/main/chunks/${l}`, await fs.readFile(`${ARGOS_SERVER_DIST}/${l}`))
          }
        },
      },
    ],
  },
  preload: {
    build: {
      rollupOptions: {
        input: { index: "src/preload/index.ts" },
        output: {
          format: "cjs",
          entryFileNames: "[name].js",
        },
      },
    },
  },
  renderer: {
    esbuild: {
      jsx: "automatic",
      jsxImportSource: "solid-js",
    },
    optimizeDeps: {
      esbuildOptions: {
        jsx: "automatic",
        jsxImportSource: "solid-js",
      },
    },
    plugins: [
      appPlugin,
      cjsInterop({
        dependencies: ["@argos/sdk", "@argos/sdk/**"],
        client: true,
      }),
      ...(sentry ? [sentry] : []),
    ] as any,
    publicDir: "../../../app/public",
    root: "src/renderer",
    build: {
      sourcemap: true,
      // Emite cada SVG como asset independiente (íconos on-demand).
      assetsInlineLimit: 0,
      rollupOptions: {
        input: {
          main: "src/renderer/index.html",
        },
      },
    },
  },
})

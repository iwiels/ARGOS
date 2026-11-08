import { readFileSync } from "node:fs"
import solidPlugin from "vite-plugin-solid"
import tailwindcss from "@tailwindcss/vite"
import { fileURLToPath } from "url"

const theme = fileURLToPath(new URL("./public/argos-theme-preload.js", import.meta.url))

const channel = (() => {
  const raw = process.env.ARGOS_CHANNEL ?? process.env.OPENCODE_CHANNEL
  if (raw === "dev" || raw === "beta" || raw === "prod") return raw
  if (raw === "latest") return "prod"
  return "dev"
})()

/**
 * @type {import("vite").PluginOption}
 */
export default [
  {
    name: "argos-desktop:config",
    config() {
      return {
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
        resolve: {
          alias: {
            "@": fileURLToPath(new URL("./src", import.meta.url)),
          },
        },
        define: {
          "import.meta.env.VITE_ARGOS_CHANNEL": JSON.stringify(channel),
          "import.meta.env.ARGOS_CHANNEL": JSON.stringify(channel),
          "import.meta.env.VITE_OPENCODE_CHANNEL": JSON.stringify(channel),
        },
        worker: {
          format: "es",
        },
      }
    },
  },
  {
    name: "argos-desktop:theme-preload",
    transformIndexHtml(html) {
      // packages/app/index.html (web, served over HTTP) uses an absolute src;
      // packages/desktop's renderer index.html (loaded via file://, where an
      // absolute "/" path would resolve to the filesystem root) uses a
      // relative "./" src instead — match either so both builds get inlined.
      return html.replace(
        /<script id="argos-theme-preload-script" src="\.?\/argos-theme-preload\.js"><\/script>/,
        `<script id="argos-theme-preload-script">${readFileSync(theme, "utf8")}</script>`,
      )
    },
  },
  tailwindcss(),
  solidPlugin(),
]

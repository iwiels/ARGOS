"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const vite_1 = require("vite");
const vite_plugin_solid_1 = __importDefault(require("vite-plugin-solid"));
const fs_1 = __importDefault(require("fs"));
// Nota: los sprites (file-icons/provider-icons) se eliminaron en favor de
// import.meta.glob con ?url en FileIcon/ProviderIcon (íconos on-demand).
// Al añadir un SVG nuevo a src/assets/icons/* actualiza manualmente el
// types.ts correspondiente (ya no se regenera con vite-plugin-icons-spritesheet).
exports.default = (0, vite_1.defineConfig)({
    plugins: [
        (0, vite_plugin_solid_1.default)(),
        providerIconsPlugin(),
    ],
    server: { port: 3001 },
    build: {
        target: "esnext",
    },
    worker: {
        format: "es",
    },
});
function providerIconsPlugin() {
    return {
        name: "provider-icons-plugin",
        configureServer() {
            void fetchProviderIcons();
        },
        buildStart() {
            void fetchProviderIcons();
        },
    };
}
async function fetchProviderIcons() {
    const url = process.env.ARGOS_MODELS_URL || process.env.OPENCODE_MODELS_URL || "https://models.dev";
    const providers = await fetch(`${url}/api.json`)
        .then((res) => res.json())
        .then((json) => Object.keys(json));
    await Promise.all(providers.map((provider) => fetch(`${url}/logos/${provider}.svg`)
        .then((res) => res.text())
        .then((svg) => fs_1.default.writeFileSync(`./src/assets/icons/provider/${provider}.svg`, svg))));
}

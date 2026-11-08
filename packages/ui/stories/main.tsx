/**
 * Minimal stories harness (Vite + solid plugin).
 *
 * Revives the 63 *.stories.tsx files that nothing compiled or rendered:
 * - dev:      bun --cwd packages/ui vite serve stories --port 3002
 * - CI smoke: bun --cwd packages/ui vite build stories --outDir .artifacts/stories
 *
 * Stories are plain CSF-ish modules: default export = { title, component,
 * args? }, named exports = stories ({ render?, args? } | empty for Basic).
 */
import { ErrorBoundary, For, createSignal, onMount, Show } from "solid-js"
import { Dynamic, render } from "solid-js/web"
import type { JSX, ValidComponent } from "solid-js"
import "../src/styles/index.css"

type StoryFn = (args: Record<string, unknown>) => JSX.Element

type LoadedStoryModule = {
  default?: {
    title?: string
    component?: ValidComponent
    args?: Record<string, unknown>
    parameters?: { frameBackground?: string }
  }
  [name: string]: unknown
}

const modules = import.meta.glob("../src/components/*.stories.tsx")

const prettyName = (path: string) => {
  const file = path.split("/").pop() ?? path
  return file.replace(".stories.tsx", "").replace(/(^|-)([a-z])/g, (_, sep, ch) => (sep ? " " : "") + ch.toUpperCase())
}

const resolveRender = (mod: LoadedStoryModule, name: string): StoryFn => {
  const meta = mod.default ?? {}
  const story = mod[name] as { render?: StoryFn; args?: Record<string, unknown> } | undefined
  const args = { ...(meta.args ?? {}), ...(story?.args ?? {}) }

  if (typeof story?.render === "function") return () => story.render!(args)

  const component = meta.component
  if (!component) {
    return () => <pre data-component="storybook-error">No component/render for {name}</pre>
  }
  return () => <Dynamic component={component} {...args} />
}

function App() {
  const paths = Object.keys(modules).sort()
  const [selected, setSelected] = createSignal<string>()
  const [storyName, setStoryName] = createSignal<string>()
  const [mod, setMod] = createSignal<LoadedStoryModule>()

  const load = async (path: string) => {
    setSelected(path)
    setMod((await modules[path]()) as LoadedStoryModule)
    const loaded = mod()
    const names = Object.keys(loaded ?? {}).filter((k) => k !== "default")
    setStoryName(names[0])
  }

  const canvas = () => {
    const current = mod()
    if (!current || !selected() || !storyName()) return null
    const meta = current.default
    const background = meta?.parameters?.frameBackground
    const Render = resolveRender(current, storyName()!)
    return (
      <div data-component="storybook-canvas" style={{ background, padding: "24px" }}>
        <ErrorBoundary
          fallback={(err) => <pre data-component="storybook-error">{String(err)}</pre>}
        >
          <Render />
        </ErrorBoundary>
      </div>
    )
  }

  const storyNames = () => Object.keys(mod() ?? {}).filter((k) => k !== "default")
  const docs = () => (mod()?.default?.title ? String(mod()!.default!.title) : prettyName(selected() ?? ""))

  onMount(() => {
    if (paths.length > 0) void load(paths[0]!)
  })

  return (
    <div data-component="storybook-shell" style={{ display: "flex", height: "100vh", "font-family": "system-ui" }}>
      <nav
        style={{
          width: "260px",
          "overflow-y": "auto",
          "border-right": "1px solid #ddd",
          padding: "12px",
        }}
      >
        <h1 style={{ "font-size": "13px", margin: "0 0 8px" }}>Argos UI · Stories</h1>
        <For each={paths}>
          {(path) => (
            <div>
              <button
                type="button"
                onClick={() => void load(path)}
                style={{
                  display: "block",
                  width: "100%",
                  "text-align": "left",
                  padding: "6px 8px",
                  "font-size": "13px",
                  cursor: "pointer",
                  background: selected() === path ? "#eef" : "transparent",
                  border: "none",
                  "border-radius": "6px",
                }}
              >
                {prettyName(path)}
              </button>
              <Show when={selected() === path}>
                <For each={storyNames()}>
                  {(name) => (
                    <button
                      type="button"
                      onClick={() => setStoryName(name)}
                      style={{
                        display: "block",
                        width: "100%",
                        "text-align": "left",
                        padding: "4px 16px",
                        "font-size": "12px",
                        cursor: "pointer",
                        color: storyName() === name ? "#05f" : "#555",
                        background: "transparent",
                        border: "none",
                      }}
                    >
                      {name}
                    </button>
                  )}
                </For>
              </Show>
            </div>
          )}
        </For>
      </nav>
      <main style={{ flex: "1", "overflow-y": "auto" }}>
        <header style={{ padding: "10px 24px", "border-bottom": "1px solid #eee" }}>
          <strong style={{ "font-size": "14px" }}>{docs()}</strong>
          <span style={{ "margin-left": "12px", color: "#888", "font-size": "12px" }}>{storyName()}</span>
        </header>
        {canvas()}
      </main>
    </div>
  )
}

const root = document.getElementById("root")!
render(() => <App />, root)

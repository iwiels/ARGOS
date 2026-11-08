import { Button } from "@argos/ui/button"
import { useDialog } from "@argos/ui/context/dialog"
import { Dialog, DialogFooter } from "@argos/ui/dialog"
import { Select } from "@argos/ui/select"
import { Switch } from "@argos/ui/switch"
import { TextField } from "@argos/ui/text-field"
import { useMutation } from "@tanstack/solid-query"
import { Icon } from "@argos/ui/icon"
import { PixelIcon } from "@argos/ui/pixel-icon"
import { createMemo, createSignal, For, Show } from "solid-js"
import { createStore } from "solid-js/store"
import { type LocalProject, getAvatarColors } from "@/context/layout"
import { getFilename } from "@/core/path"
import { Avatar } from "@argos/ui/avatar"
import { useLanguage } from "@/context/language"
import { getProjectAvatarSource } from "@/pages/layout/helpers"
import { ServerConnection } from "@/context/server"
import { useGlobal } from "@/context/global"
import { testProjectWebhook, updateProjectWebhook, type ProjectWebhookConfig } from "./settings/project-webhook-api"

const WEBHOOK_FORMATS: ProjectWebhookConfig["format"][] = ["generic", "slack", "jira"]
const AVATAR_COLOR_KEYS = ["pink", "mint", "orange", "purple", "cyan", "lime"] as const
const RPS_PRESETS = [5, 10, 20, 50, 0] as const
const CONCURRENCY_PRESETS = [1, 2, 4, 8, 16] as const

type TabKey = "scope" | "traffic" | "general" | "webhook"

export function DialogEditProject(props: { project: LocalProject; server: ServerConnection.Any }) {
  const dialog = useDialog()
  const global = useGlobal()
  const language = useLanguage()
  const serverCtx = createMemo(() => global.createServerCtx(props.server))
  const serverSDK = () => serverCtx().sdk
  const serverSync = () => serverCtx().sync
  const projectRequest = (path: string, init?: RequestInit) =>
    serverCtx().sdk.request(path, init, props.project.worktree)

  const folderName = createMemo(() => getFilename(props.project.worktree))
  const defaultName = createMemo(() => props.project.name || folderName())

  const [activeTab, setActiveTab] = createSignal<TabKey>("scope")

  // Fallback to projectMeta scope if props.project.scope is empty
  const initialScope = createMemo(() => {
    if (
      props.project.scope &&
      ((props.project.scope.domains?.length ?? 0) > 0 ||
        (props.project.scope.cidrs?.length ?? 0) > 0 ||
        (props.project.scope.excluded?.length ?? 0) > 0)
    ) {
      return props.project.scope
    }
    try {
      const [child] = serverSync().child(props.project.worktree, { bootstrap: false })
      if (child.projectMeta?.scope) return child.projectMeta.scope
    } catch {}
    return props.project.scope
  })

  const [store, setStore] = createStore({
    name: defaultName(),
    color: props.project.icon?.color,
    iconOverride: props.project.icon?.override,
    // Scope parameters
    domains: (initialScope()?.domains ?? []).join("\n"),
    excluded: (initialScope()?.excluded ?? []).join("\n"),
    cidrs: (initialScope()?.cidrs ?? []).join("\n"),
    // Traffic & Safety
    maxRPS: initialScope()?.maxRPS ?? 10,
    maxConcurrency: initialScope()?.maxConcurrency ?? 4,
    customHeader: initialScope()?.customHeader ?? "X-Auditor-Engagement: ARGOS-SEC-OPS",
    safeMode: initialScope()?.safeMode ?? true,
    modality: initialScope()?.modality ?? "black-box",
    // Webhook parameters
    webhookUrl: props.project.webhook?.url ?? "",
    webhookSecret: props.project.webhook?.secret ?? "",
    webhookFormat: props.project.webhook?.format ?? "generic",
    webhookEnabled: props.project.webhook?.enabled ?? false,
    dragOver: false,
    iconHover: false,
  })

  const [testing, setTesting] = createSignal(false)
  const [testResult, setTestResult] = createSignal<{ ok: boolean; message: string }>()

  const isRealProject = createMemo(() => !!props.project.id && props.project.id !== "global")

  function sanitizeDomain(d: string): string {
    let s = d.trim()
    if (s.includes("://")) {
      try {
        s = new URL(s).hostname
      } catch {
        s = s.replace(/^[a-z]+:\/\//i, "").split("/")[0]
      }
    }
    if (s.endsWith("/")) s = s.slice(0, -1)
    return s
  }

  function isValidCidrOrIp(entry: string): boolean {
    const trimmed = entry.trim()
    if (!trimmed) return true
    const [ip, mask] = trimmed.split("/")
    const ipv4Parts = ip.split(".")
    if (ipv4Parts.length === 4) {
      const allOctetsValid = ipv4Parts.every((p) => {
        if (!/^\d+$/.test(p)) return false
        const n = Number(p)
        return n >= 0 && n <= 255
      })
      if (!allOctetsValid) return false
      if (mask !== undefined) {
        if (!/^\d+$/.test(mask)) return false
        const m = Number(mask)
        return m < 0 || m > 32
      }
      return true
    }
    if (ip.includes(":")) {
      if (mask !== undefined) {
        if (!/^\d+$/.test(mask)) return false
        const m = Number(mask)
        return m < 0 || m > 128
      }
      return true
    }
    return false
  }

  function parseList(text: string): string[] {
    return Array.from(
      new Set(
        text
          .split(/[\n,]/)
          .map((s) => s.trim())
          .filter((s) => s.length > 0),
      ),
    )
  }

  const parsedDomains = createMemo(() => parseList(store.domains).map(sanitizeDomain))
  const parsedExcluded = createMemo(() => parseList(store.excluded))
  const parsedCidrs = createMemo(() => parseList(store.cidrs))
  const invalidCidrs = createMemo(() => parsedCidrs().filter((c) => !isValidCidrOrIp(c)))

  function removeItem(type: "domains" | "excluded" | "cidrs", itemToRemove: string) {
    const current = parseList(store[type])
    const next = current.filter((x) => x !== itemToRemove)
    setStore(type, next.join("\n"))
  }

  const testWebhook = async () => {
    const url = store.webhookUrl.trim()
    if (!url) return
    setTesting(true)
    setTestResult(undefined)
    try {
      const result = await testProjectWebhook(projectRequest, props.project.id!, {
        url,
        secret: store.webhookSecret.trim() || undefined,
        format: store.webhookFormat,
      })
      if (!result) {
        setTestResult({ ok: false, message: language.t("dialog.project.edit.webhook.test.unavailable") })
        return
      }
      setTestResult({
        ok: result.ok,
        message: result.ok
          ? language.t("dialog.project.edit.webhook.test.success", { status: result.statusCode })
          : language.t("dialog.project.edit.webhook.test.failure", { status: result.statusCode }),
      })
    } catch {
      setTestResult({ ok: false, message: language.t("dialog.project.edit.webhook.test.failure", { status: 0 }) })
    } finally {
      setTesting(false)
    }
  }

  let iconInput: HTMLInputElement | undefined

  function handleFileSelect(file: File) {
    if (!file.type.startsWith("image/")) return
    const reader = new FileReader()
    reader.onload = (e) => {
      setStore("iconOverride", e.target?.result as string)
      setStore("iconHover", false)
    }
    reader.readAsDataURL(file)
  }

  function handleDrop(e: DragEvent) {
    e.preventDefault()
    setStore("dragOver", false)
    const file = e.dataTransfer?.files[0]
    if (file) handleFileSelect(file)
  }

  function handleDragOver(e: DragEvent) {
    e.preventDefault()
    setStore("dragOver", true)
  }

  function handleDragLeave() {
    setStore("dragOver", false)
  }

  function handleInputChange(e: Event) {
    const input = e.target as HTMLInputElement
    const file = input.files?.[0]
    if (file) handleFileSelect(file)
  }

  function clearIcon() {
    setStore("iconOverride", "")
  }

  const saveMutation = useMutation(() => ({
    mutationFn: async () => {
      const name = store.name.trim() === folderName() ? "" : store.name.trim()
      const scopeData = {
        domains: parsedDomains(),
        excluded: parsedExcluded(),
        cidrs: parsedCidrs(),
        maxRPS: Math.max(0, store.maxRPS || 0),
        maxConcurrency: Math.max(1, store.maxConcurrency || 4),
        customHeader: store.customHeader.trim() || undefined,
        safeMode: store.safeMode,
        modality: store.modality,
      }

      const targetProjectID = props.project.id || "global"

      // 1. Update project on server (updates ProjectTable, argos.json, SessionTable, and auth memories)
      try {
        await serverSDK().client.project.update({
          projectID: targetProjectID,
          directory: props.project.worktree,
          name,
          icon: { color: store.color || "", override: store.iconOverride || "" },
          scope: scopeData,
        })
      } catch (err) {
        console.warn("Could not update project on server, saving locally:", err)
      }

      // 2. Webhook update (if real project ID)
      if (props.project.id && props.project.id !== "global") {
        const url = store.webhookUrl.trim()
        await updateProjectWebhook(
          projectRequest,
          props.project.id,
          url
            ? {
                url,
                secret: store.webhookSecret.trim() || undefined,
                format: store.webhookFormat,
                enabled: store.webhookEnabled,
              }
            : null,
        ).catch(() => {})
      }

      // 3. Update local sync caches (child store & localStorage projectMeta)
      serverSync().project.icon(props.project.worktree, store.iconOverride || undefined)
      serverSync().project.meta(props.project.worktree, {
        name,
        icon: { color: store.color || undefined, override: store.iconOverride || undefined },
        scope: scopeData,
      })

      dialog.close()
    },
  }))

  function handleSubmit(e: SubmitEvent) {
    e.preventDefault()
    if (saveMutation.isPending) return
    if (invalidCidrs().length > 0) {
      setActiveTab("scope")
      return
    }
    saveMutation.mutate()
  }

  const totalScopeTargets = createMemo(
    () => parsedDomains().length + parsedExcluded().length + parsedCidrs().length,
  )

  return (
    <Dialog
      size="x-large"
      title={language.t("dialog.project.edit.title")}
      description={language.t("dialog.project.edit.subtitle")}
    >
      <form onSubmit={handleSubmit} class="flex flex-col flex-1 min-h-0 w-full overflow-hidden">
        {/* Navigation Tabs */}
        <div class="flex items-center gap-1 px-5 border-b border-border-base bg-bg-surface shrink-0">
          <button
            type="button"
            onClick={() => setActiveTab("scope")}
            class="flex items-center gap-2 px-3 py-2.5 text-xs font-medium border-b-2 transition-colors relative"
            classList={{
              "border-accent text-text-primary font-semibold": activeTab() === "scope",
              "border-transparent text-text-tertiary hover:text-text-secondary": activeTab() !== "scope",
            }}
          >
            <PixelIcon name="radar" size={14} class={activeTab() === "scope" ? "text-accent" : "text-text-tertiary"} />
            <span>{language.t("dialog.project.edit.tab.scope")}</span>
            <Show when={totalScopeTargets() > 0}>
              <span class="px-1.5 py-0.2 rounded-full text-[10px] font-mono tabular-nums leading-tight bg-accent/20 text-accent">
                {totalScopeTargets()}
              </span>
            </Show>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab("traffic")}
            class="flex items-center gap-2 px-3 py-2.5 text-xs font-medium border-b-2 transition-colors relative"
            classList={{
              "border-accent text-text-primary font-semibold": activeTab() === "traffic",
              "border-transparent text-text-tertiary hover:text-text-secondary": activeTab() !== "traffic",
            }}
          >
            <PixelIcon name="terminal" size={14} class={activeTab() === "traffic" ? "text-accent" : "text-text-tertiary"} />
            <span>{language.t("dialog.project.edit.tab.traffic")}</span>
            <span class="px-1.5 py-0.2 rounded-full text-[10px] font-mono text-text-tertiary bg-surface-raised-stronger-non-alpha">
              {store.maxRPS > 0 ? `${store.maxRPS} req/s` : "∞"}
            </span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab("general")}
            class="flex items-center gap-2 px-3 py-2.5 text-xs font-medium border-b-2 transition-colors relative"
            classList={{
              "border-accent text-text-primary font-semibold": activeTab() === "general",
              "border-transparent text-text-tertiary hover:text-text-secondary": activeTab() !== "general",
            }}
          >
            <PixelIcon name="folder" size={14} class={activeTab() === "general" ? "text-accent" : "text-text-tertiary"} />
            <span>{language.t("dialog.project.edit.tab.general")}</span>
          </button>

          <Show when={isRealProject()}>
            <button
              type="button"
              onClick={() => setActiveTab("webhook")}
              class="flex items-center gap-2 px-3 py-2.5 text-xs font-medium border-b-2 transition-colors relative"
              classList={{
                "border-accent text-text-primary font-semibold": activeTab() === "webhook",
                "border-transparent text-text-tertiary hover:text-text-secondary": activeTab() !== "webhook",
              }}
            >
              <Icon name="link" size="small" class={activeTab() === "webhook" ? "text-accent" : "text-text-tertiary"} />
              <span>{language.t("dialog.project.edit.tab.webhook")}</span>
              <Show when={store.webhookEnabled}>
                <span class="size-1.5 rounded-full bg-severity-fg-low" />
              </Show>
            </button>
          </Show>
        </div>

        {/* Tab Body - Scrollable content area */}
        <div class="p-5 overflow-y-auto flex-1 flex flex-col gap-5">
          {/* TAB 1: SCOPE */}
          <Show when={activeTab() === "scope"}>
            <div class="flex flex-col gap-4">
              {/* Authorized Domains */}
              <div class="flex flex-col gap-2">
                <div class="flex items-center justify-between">
                  <label class="text-xs font-medium text-text-primary">
                    {language.t("dialog.project.edit.scope.domains")}
                  </label>
                  <span class="text-11-regular text-text-tertiary font-mono">
                    {language.t("dialog.project.edit.itemsCount", { count: parsedDomains().length })}
                  </span>
                </div>
                <p class="text-11-regular text-text-tertiary">
                  {language.t("dialog.project.edit.scope.domains.hint")}
                </p>
                <TextField
                  multiline
                  placeholder={language.t("dialog.project.edit.scope.domains.placeholder")}
                  value={store.domains}
                  onChange={(v) => setStore("domains", v)}
                  spellcheck={false}
                  class="min-h-24 font-mono text-xs w-full"
                />
                <Show when={parsedDomains().length > 0}>
                  <div class="flex flex-wrap gap-1.5 pt-1">
                    <For each={parsedDomains()}>
                      {(domain) => (
                        <span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-[3px] text-xs font-mono bg-bg-surface-elevated text-text-primary border border-border-base">
                          <span>{domain}</span>
                          <button
                            type="button"
                            onClick={() => removeItem("domains", domain)}
                            class="text-text-tertiary hover:text-severity-fg-critical text-xs leading-none"
                            title={language.t("dialog.project.edit.scope.removeItem")}
                            aria-label={language.t("dialog.project.edit.scope.removeItem")}
                          >
                            ×
                          </button>
                        </span>
                      )}
                    </For>
                  </div>
                </Show>
              </div>

              <div class="flex flex-col gap-2 pt-2 border-t border-border-weaker-base">
                <div class="flex items-center justify-between">
                  <label class="text-xs font-medium text-text-primary">
                    {language.t("dialog.project.edit.scope.excluded")}
                  </label>
                  <span class="text-11-regular text-text-tertiary font-mono">
                    {language.t("dialog.project.edit.itemsCount", { count: parsedExcluded().length })}
                  </span>
                </div>
                <p class="text-11-regular text-text-tertiary">
                  {language.t("dialog.project.edit.scope.excluded.hint")}
                </p>
                <TextField
                  multiline
                  placeholder={language.t("dialog.project.edit.scope.excluded.placeholder")}
                  value={store.excluded}
                  onChange={(v) => setStore("excluded", v)}
                  spellcheck={false}
                  class="min-h-20 font-mono text-xs w-full"
                />
                <Show when={parsedExcluded().length > 0}>
                  <div class="flex flex-wrap gap-1.5 pt-1">
                    <For each={parsedExcluded()}>
                      {(target) => (
                        <span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-[3px] text-xs font-mono bg-bg-surface-elevated text-text-secondary border border-border-base">
                          <span>{target}</span>
                          <button
                            type="button"
                            onClick={() => removeItem("excluded", target)}
                            class="text-text-tertiary hover:text-severity-fg-critical text-xs leading-none"
                            title={language.t("dialog.project.edit.scope.removeItem")}
                            aria-label={language.t("dialog.project.edit.scope.removeItem")}
                          >
                            ×
                          </button>
                        </span>
                      )}
                    </For>
                  </div>
                </Show>
              </div>

              <div class="flex flex-col gap-2 pt-2 border-t border-border-weaker-base">
                <div class="flex items-center justify-between">
                  <label class="text-xs font-medium text-text-primary">
                    {language.t("dialog.project.edit.scope.cidrs")}
                  </label>
                  <span class="text-11-regular text-text-tertiary font-mono">
                    {language.t("dialog.project.edit.itemsCount", { count: parsedCidrs().length })}
                  </span>
                </div>
                <p class="text-11-regular text-text-tertiary">
                  {language.t("dialog.project.edit.scope.cidrs.hint")}
                </p>
                <TextField
                  multiline
                  placeholder={language.t("dialog.project.edit.scope.cidrs.placeholder")}
                  value={store.cidrs}
                  onChange={(v) => setStore("cidrs", v)}
                  spellcheck={false}
                  class="min-h-18 font-mono text-xs w-full"
                />
                <Show when={invalidCidrs().length > 0}>
                  <p class="text-11-regular text-severity-fg-critical font-mono">
                    {language.t("dialog.project.edit.scope.cidrs.invalid", { items: invalidCidrs().join(", ") })}
                  </p>
                </Show>
                <Show when={parsedCidrs().length > 0}>
                  <div class="flex flex-wrap gap-1.5 pt-1">
                    <For each={parsedCidrs()}>
                      {(cidr) => (
                        <span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-[3px] text-xs font-mono bg-bg-surface-elevated text-text-primary border border-border-base">
                          <span>{cidr}</span>
                          <button
                            type="button"
                            onClick={() => removeItem("cidrs", cidr)}
                            class="text-text-tertiary hover:text-severity-fg-critical text-xs leading-none"
                            title={language.t("dialog.project.edit.scope.removeItem")}
                            aria-label={language.t("dialog.project.edit.scope.removeItem")}
                          >
                            ×
                          </button>
                        </span>
                      )}
                    </For>
                  </div>
                </Show>
              </div>
            </div>
          </Show>

          <Show when={activeTab() === "traffic"}>
            <div class="flex flex-col gap-5">
              <div class="flex flex-col gap-2">
                <label class="text-xs font-medium text-text-primary">
                  {language.t("dialog.project.edit.traffic.rateLimit")}
                </label>
                <p class="text-11-regular text-text-tertiary">
                  {language.t("dialog.project.edit.traffic.rateLimit.hint")}
                </p>
                <div class="flex items-center gap-3">
                  <input
                    type="number"
                    min="0"
                    max="1000"
                    value={store.maxRPS}
                    onInput={(e) => setStore("maxRPS", Number(e.currentTarget.value) || 0)}
                    class="h-8 w-24 px-2.5 rounded-[3px] border border-border-base bg-bg-surface text-text-primary font-mono text-xs focus:outline-none focus:border-accent"
                  />
                  <div class="flex items-center gap-1">
                    <For each={RPS_PRESETS}>
                      {(preset) => (
                        <button
                          type="button"
                          onClick={() => setStore("maxRPS", preset)}
                          class="px-2 py-1 text-xs font-mono rounded-[3px] border transition-colors"
                          classList={{
                            "border-accent bg-accent/15 text-accent font-semibold": store.maxRPS === preset,
                            "border-border-base text-text-secondary hover:border-border-strong": store.maxRPS !== preset,
                          }}
                        >
                          {preset === 0 ? language.t("dialog.project.edit.traffic.unlimited") : `${preset} req/s`}
                        </button>
                      )}
                    </For>
                  </div>
                </div>
              </div>

              <div class="flex flex-col gap-2 pt-2 border-t border-border-weaker-base">
                <label class="text-xs font-medium text-text-primary">
                  {language.t("dialog.project.edit.traffic.concurrency")}
                </label>
                <p class="text-11-regular text-text-tertiary">
                  {language.t("dialog.project.edit.traffic.concurrency.hint")}
                </p>
                <div class="flex items-center gap-3">
                  <input
                    type="number"
                    min="1"
                    max="64"
                    value={store.maxConcurrency}
                    onInput={(e) => setStore("maxConcurrency", Math.max(1, Number(e.currentTarget.value) || 1))}
                    class="h-8 w-24 px-2.5 rounded-[3px] border border-border-base bg-bg-surface text-text-primary font-mono text-xs focus:outline-none focus:border-accent"
                  />
                  <div class="flex items-center gap-1">
                    <For each={CONCURRENCY_PRESETS}>
                      {(preset) => (
                        <button
                          type="button"
                          onClick={() => setStore("maxConcurrency", preset)}
                          class="px-2 py-1 text-xs font-mono rounded-[3px] border transition-colors"
                          classList={{
                            "border-accent bg-accent/15 text-accent font-semibold": store.maxConcurrency === preset,
                            "border-border-base text-text-secondary hover:border-border-strong":
                              store.maxConcurrency !== preset,
                          }}
                        >
                          {preset}{" "}
                          {preset === 1
                            ? language.t("dialog.project.edit.traffic.thread")
                            : language.t("dialog.project.edit.traffic.threads")}
                        </button>
                      )}
                    </For>
                  </div>
                </div>
              </div>

              <div class="flex flex-col gap-2 pt-2 border-t border-border-weaker-base">
                <label class="text-xs font-medium text-text-primary">
                  {language.t("dialog.project.edit.traffic.customHeader")}
                </label>
                <p class="text-11-regular text-text-tertiary">
                  {language.t("dialog.project.edit.traffic.customHeader.hint")}
                </p>
                <TextField
                  type="text"
                  placeholder={language.t("dialog.project.edit.traffic.customHeader.placeholder")}
                  value={store.customHeader}
                  onChange={(v) => setStore("customHeader", v)}
                  class="font-mono text-xs w-full"
                />
              </div>

              {/* Safe Mode Toggle */}
              <div class="flex items-center justify-between p-3 rounded-[3px] border border-border-base bg-bg-surface-elevated mt-1">
                <div class="flex flex-col gap-0.5">
                  <span class="text-xs font-medium text-text-primary">
                    {language.t("dialog.project.edit.traffic.safeMode")}
                  </span>
                  <span class="text-11-regular text-text-tertiary">
                    {language.t("dialog.project.edit.traffic.safeMode.desc")}
                  </span>
                </div>
                <Switch checked={store.safeMode} onChange={(v) => setStore("safeMode", v)} />
              </div>
            </div>
          </Show>

          <Show when={activeTab() === "general"}>
            <div class="flex flex-col gap-5">
              <TextField
                autofocus
                type="text"
                label={language.t("dialog.project.edit.name")}
                placeholder={folderName()}
                value={store.name}
                onChange={(v) => setStore("name", v)}
              />

              <div class="flex flex-col gap-2">
                <label class="text-xs font-medium text-text-primary">
                  {language.t("dialog.project.edit.modality.title")}
                </label>
                <div class="grid grid-cols-1 sm:grid-cols-3 gap-2">
                  {/* Black-Box */}
                  <div
                    role="button"
                    tabIndex={0}
                    onClick={() => setStore("modality", "black-box")}
                    class="p-3 rounded-[3px] border cursor-pointer transition-colors flex flex-col justify-between gap-2"
                    classList={{
                      "border-accent bg-accent/10": store.modality === "black-box",
                      "border-border-base hover:border-border-strong bg-bg-surface": store.modality !== "black-box",
                    }}
                  >
                    <div class="flex items-center justify-between">
                      <span class="text-xs font-medium text-text-primary">
                        {language.t("dialog.project.edit.modality.blackbox")}
                      </span>
                      <Show when={store.modality === "black-box"}>
                        <span class="size-2 rounded-full bg-accent" />
                      </Show>
                    </div>
                    <p class="text-[11px] text-text-tertiary leading-normal">
                      {language.t("dialog.project.edit.modality.blackbox.desc")}
                    </p>
                  </div>

                  <div
                    role="button"
                    tabIndex={0}
                    onClick={() => setStore("modality", "grey-box")}
                    class="p-3 rounded-[3px] border cursor-pointer transition-colors flex flex-col justify-between gap-2"
                    classList={{
                      "border-accent bg-accent/10": store.modality === "grey-box",
                      "border-border-base hover:border-border-strong bg-bg-surface": store.modality !== "grey-box",
                    }}
                  >
                    <div class="flex items-center justify-between">
                      <span class="text-xs font-medium text-text-primary">
                        {language.t("dialog.project.edit.modality.greybox")}
                      </span>
                      <Show when={store.modality === "grey-box"}>
                        <span class="size-2 rounded-full bg-accent" />
                      </Show>
                    </div>
                    <p class="text-[11px] text-text-tertiary leading-normal">
                      {language.t("dialog.project.edit.modality.greybox.desc")}
                    </p>
                  </div>

                  <div
                    role="button"
                    tabIndex={0}
                    onClick={() => setStore("modality", "white-box")}
                    class="p-3 rounded-[3px] border cursor-pointer transition-colors flex flex-col justify-between gap-2"
                    classList={{
                      "border-accent bg-accent/10": store.modality === "white-box",
                      "border-border-base hover:border-border-strong bg-bg-surface": store.modality !== "white-box",
                    }}
                  >
                    <div class="flex items-center justify-between">
                      <span class="text-xs font-medium text-text-primary">
                        {language.t("dialog.project.edit.modality.whitebox")}
                      </span>
                      <Show when={store.modality === "white-box"}>
                        <span class="size-2 rounded-full bg-accent" />
                      </Show>
                    </div>
                    <p class="text-[11px] text-text-tertiary leading-normal">
                      {language.t("dialog.project.edit.modality.whitebox.desc")}
                    </p>
                  </div>
                </div>
              </div>

              <div class="flex flex-col gap-2 pt-2 border-t border-border-weaker-base">
                <label class="text-xs font-medium text-text-weak">{language.t("dialog.project.edit.icon")}</label>
                <div class="flex gap-4 items-start">
                  <div
                    class="relative"
                    onMouseEnter={() => setStore("iconHover", true)}
                    onMouseLeave={() => setStore("iconHover", false)}
                  >
                    <div
                      class="relative size-14 rounded-[3px] transition-colors cursor-pointer border"
                      classList={{
                        "border-accent bg-accent/15": store.dragOver,
                        "border-border-base hover:border-border-strong": !store.dragOver,
                        "overflow-hidden": !!store.iconOverride,
                      }}
                      onDrop={handleDrop}
                      onDragOver={handleDragOver}
                      onDragLeave={handleDragLeave}
                      onClick={() => {
                        if (store.iconOverride && store.iconHover) {
                          clearIcon()
                        } else {
                          iconInput?.click()
                        }
                      }}
                    >
                      <Show
                        when={getProjectAvatarSource(props.project.id, {
                          color: store.color,
                          url: props.project.icon?.url,
                          override: store.iconOverride,
                        })}
                        fallback={
                          <div class="size-full flex items-center justify-center">
                            <Avatar
                              fallback={store.name || defaultName()}
                              {...getAvatarColors(store.color)}
                              class="size-full text-xl"
                            />
                          </div>
                        }
                      >
                        {(src) => (
                          <img
                            src={src()}
                            alt={language.t("dialog.project.edit.icon.alt")}
                            class="size-full object-cover"
                          />
                        )}
                      </Show>
                    </div>
                    <div
                      class="absolute inset-0 size-14 bg-surface-raised-stronger-non-alpha/90 rounded-[3px] z-10 pointer-events-none flex items-center justify-center transition-opacity"
                      classList={{
                        "opacity-100": store.iconHover && !store.iconOverride,
                        "opacity-0": !(store.iconHover && !store.iconOverride),
                      }}
                    >
                      <Icon name="cloud-upload" size="small" class="text-icon-on-interactive-base" />
                    </div>
                    <div
                      class="absolute inset-0 size-14 bg-surface-raised-stronger-non-alpha/90 rounded-[3px] z-10 pointer-events-none flex items-center justify-center transition-opacity"
                      classList={{
                        "opacity-100": store.iconHover && !!store.iconOverride,
                        "opacity-0": !(store.iconHover && !!store.iconOverride),
                      }}
                    >
                      <Icon name="trash" size="small" class="text-icon-on-interactive-base" />
                    </div>
                  </div>
                  <input
                    id="icon-upload"
                    ref={(el) => {
                      iconInput = el
                    }}
                    type="file"
                    accept="image/*"
                    class="hidden"
                    onChange={handleInputChange}
                  />
                  <div class="flex flex-col gap-1 text-11-regular text-text-weak self-center">
                    <span>{language.t("dialog.project.edit.icon.hint")}</span>
                    <span>{language.t("dialog.project.edit.icon.recommended")}</span>
                  </div>
                </div>
              </div>

              <Show when={!store.iconOverride}>
                <div class="flex flex-col gap-2">
                  <label class="text-xs font-medium text-text-weak">{language.t("dialog.project.edit.color")}</label>
                  <div class="flex gap-2">
                    <For each={AVATAR_COLOR_KEYS}>
                      {(color) => (
                        <button
                          type="button"
                          aria-label={language.t("dialog.project.edit.color.select", { color })}
                          aria-pressed={store.color === color}
                          classList={{
                            "flex items-center justify-center size-8 p-0.5 rounded-[3px] overflow-hidden transition-colors cursor-pointer": true,
                            "border-2 border-accent": store.color === color,
                            "border border-border-base hover:border-border-strong": store.color !== color,
                          }}
                          onClick={() => {
                            if (store.color === color && !props.project.icon?.url) return
                            setStore("color", store.color === color ? undefined : color)
                          }}
                        >
                          <Avatar
                            fallback={store.name || defaultName()}
                            {...getAvatarColors(color)}
                            class="size-full rounded-[2px]"
                          />
                        </button>
                      )}
                    </For>
                  </div>
                </div>
              </Show>

              <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 border-t border-border-weaker-base">
                <div class="flex flex-col gap-1 p-2.5 rounded-[3px] bg-bg-surface-elevated border border-border-weaker-base">
                  <span class="text-[10px] uppercase font-mono tracking-wider text-text-tertiary">
                    {language.t("dialog.project.edit.worktree")}
                  </span>
                  <span class="text-xs font-mono text-text-secondary truncate" title={props.project.worktree}>
                    {props.project.worktree}
                  </span>
                </div>
                <div class="flex flex-col gap-1 p-2.5 rounded-[3px] bg-bg-surface-elevated border border-border-weaker-base">
                  <span class="text-[10px] uppercase font-mono tracking-wider text-text-tertiary">
                    {language.t("dialog.project.edit.id")}
                  </span>
                  <span class="text-xs font-mono text-text-secondary truncate" title={props.project.id ?? "global"}>
                    {props.project.id ?? "global"}
                  </span>
                </div>
              </div>
            </div>
          </Show>

          <Show when={activeTab() === "webhook" && isRealProject()}>
            <div class="flex flex-col gap-4">
              <div class="flex items-center justify-between p-3 rounded-[3px] border border-border-base bg-bg-surface-elevated">
                <div class="flex flex-col gap-0.5">
                  <label class="text-xs font-medium text-text-primary">
                    {language.t("dialog.project.edit.webhook.title")}
                  </label>
                  <span class="text-11-regular text-text-tertiary max-w-md">
                    {language.t("dialog.project.edit.webhook.description")}
                  </span>
                </div>
                <Switch checked={store.webhookEnabled} onChange={(v) => setStore("webhookEnabled", v)} />
              </div>

              <Show when={store.webhookEnabled}>
                <TextField
                  type="text"
                  label={language.t("dialog.project.edit.webhook.url")}
                  placeholder={language.t("dialog.project.edit.webhook.url.placeholder")}
                  value={store.webhookUrl}
                  onChange={(v) => setStore("webhookUrl", v)}
                />
                <TextField
                  type="password"
                  label={language.t("dialog.project.edit.webhook.secret")}
                  value={store.webhookSecret}
                  onChange={(v) => setStore("webhookSecret", v)}
                />
                <div class="flex flex-col gap-1.5">
                  <label class="text-xs font-medium text-text-weak">{language.t("dialog.project.edit.webhook.format")}</label>
                  <Select
                    appearance="inline"
                    options={WEBHOOK_FORMATS}
                    current={store.webhookFormat}
                    value={(o) => o ?? "generic"}
                    label={(o) => language.t(`dialog.project.edit.webhook.format.${o ?? "generic"}` as const)}
                    onSelect={(option) => option && setStore("webhookFormat", option)}
                  />
                </div>
                <div class="flex items-center gap-2 pt-1">
                  <Button
                    type="button"
                    variant="secondary"
                    size="small"
                    disabled={testing() || !store.webhookUrl.trim()}
                    onClick={() => void testWebhook()}
                  >
                    {testing() ? language.t("dialog.project.edit.webhook.testing") : language.t("dialog.project.edit.webhook.test")}
                  </Button>
                  <Show when={testResult()}>
                    {(result) => (
                      <span
                        class={`text-11-regular ${result().ok ? "text-severity-fg-low" : "text-severity-fg-critical"}`}
                      >
                        {result().message}
                      </span>
                    )}
                  </Show>
                </div>
              </Show>
            </div>
          </Show>
        </div>

        {/* Standard DialogFooter */}
        <DialogFooter>
          <div class="flex items-center justify-end w-full">
            <div class="flex items-center gap-2">
              <Button type="button" variant="ghost" size="normal" onClick={() => dialog.close()}>
                {language.t("common.cancel")}
              </Button>
              <Button
                type="submit"
                variant="contrast"
                size="normal"
                disabled={saveMutation.isPending || invalidCidrs().length > 0}
              >
                {saveMutation.isPending ? language.t("common.saving") : language.t("common.save")}
              </Button>
            </div>
          </div>
        </DialogFooter>
      </form>
    </Dialog>
  )
}

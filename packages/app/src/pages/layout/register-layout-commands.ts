import { useParams } from "@solidjs/router"
import type { Session } from "@argos/sdk/client"
import { type ColorScheme, useTheme } from "@argos/ui/theme/context"
import { useCommand, type CommandOption } from "@/context/command"
import { useLayout, type LocalProject } from "@/context/layout"
import { usePlatform } from "@/context/platform"
import { useLanguage, type Locale } from "@/context/language"
import { showToast } from "@/utils/toast"

export type RegisterLayoutCommandsContext = {
  language: ReturnType<typeof useLanguage>
  platform: ReturnType<typeof usePlatform>
  layout: ReturnType<typeof useLayout>
  theme: ReturnType<typeof useTheme>
  params: ReturnType<typeof useParams>
  currentSessions: () => Session[]
  currentProject: () => LocalProject | undefined
  workspaceSetting: () => boolean
  colorSchemeOrder: ColorScheme[]
  colorSchemeLabel: (scheme: ColorScheme) => string
  chooseProject: () => void
  editProject?: (project: LocalProject) => void
  connectProvider: () => void
  openServer: () => void
  openSettings: () => void
  archiveSession: (session: Session) => Promise<void>
  createWorkspace: (project: LocalProject) => Promise<void>
  cycleColorScheme: (direction?: number) => void
  cycleLanguage: (direction?: number) => void
  setLocale: (next: Locale) => void
  navigateProjectByOffset: (offset: number) => void
  navigateSessionByOffset: (offset: number) => void
  navigateSessionByUnseen: (offset: number) => void
}

export function registerLayoutCommands(command: ReturnType<typeof useCommand>, ctx: RegisterLayoutCommandsContext) {
  command.register("layout", () => {
    const { language, platform, layout, theme, params, colorSchemeOrder, colorSchemeLabel } = ctx

    const commands: CommandOption[] = [
      {
        id: "sidebar.toggle",
        title: language.t("command.sidebar.toggle"),
        category: language.t("command.category.view"),
        keybind: "mod+b",
        onSelect: () => layout.sidebar.toggle(),
      },
      {
        id: "project.open",
        title: language.t("command.project.open"),
        category: language.t("command.category.project"),
        keybind: "mod+o",
        onSelect: () => ctx.chooseProject(),
      },
      {
        id: "project.scope",
        title: language.t("dialog.project.edit.title"),
        category: language.t("command.category.project"),
        keybind: "mod+shift+g",
        disabled: !ctx.currentProject(),
        onSelect: () => {
          const proj = ctx.currentProject()
          if (proj) ctx.editProject?.(proj)
        },
      },
      {
        id: "project.previous",
        title: language.t("command.project.previous"),
        category: language.t("command.category.project"),
        keybind: "mod+alt+arrowup",
        onSelect: () => ctx.navigateProjectByOffset(-1),
      },
      {
        id: "project.next",
        title: language.t("command.project.next"),
        category: language.t("command.category.project"),
        keybind: "mod+alt+arrowdown",
        onSelect: () => ctx.navigateProjectByOffset(1),
      },
      {
        id: "provider.connect",
        title: language.t("command.provider.connect"),
        category: language.t("command.category.provider"),
        onSelect: () => ctx.connectProvider(),
      },
      {
        id: "server.switch",
        title: language.t("command.server.switch"),
        category: language.t("command.category.server"),
        onSelect: () => ctx.openServer(),
      },
      {
        id: "settings.open",
        title: language.t("command.settings.open"),
        category: language.t("command.category.settings"),
        keybind: "mod+comma",
        onSelect: () => ctx.openSettings(),
      },
      ...(platform.platform === "desktop" && platform.exportDebugLogs
        ? [
            {
              id: "logs.export",
              title: "Export logs",
              category: language.t("command.category.settings"),
              onSelect: () => {
                void platform.exportDebugLogs?.()
              },
            },
          ]
        : []),
      {
        id: "session.previous",
        title: language.t("command.session.previous"),
        category: language.t("command.category.session"),
        keybind: "alt+arrowup",
        onSelect: () => ctx.navigateSessionByOffset(-1),
      },
      {
        id: "session.next",
        title: language.t("command.session.next"),
        category: language.t("command.category.session"),
        keybind: "alt+arrowdown",
        onSelect: () => ctx.navigateSessionByOffset(1),
      },
      {
        id: "session.previous.unseen",
        title: language.t("command.session.previous.unseen"),
        category: language.t("command.category.session"),
        keybind: "shift+alt+arrowup",
        onSelect: () => ctx.navigateSessionByUnseen(-1),
      },
      {
        id: "session.next.unseen",
        title: language.t("command.session.next.unseen"),
        category: language.t("command.category.session"),
        keybind: "shift+alt+arrowdown",
        onSelect: () => ctx.navigateSessionByUnseen(1),
      },
      {
        id: "session.archive",
        title: language.t("command.session.archive"),
        category: language.t("command.category.session"),
        keybind: "mod+shift+backspace",
        disabled: !params.dir || !params.id,
        onSelect: () => {
          const session = ctx.currentSessions().find((s) => s.id === params.id)
          if (session) void ctx.archiveSession(session)
        },
      },
      {
        id: "workspace.new",
        title: language.t("workspace.new"),
        category: language.t("command.category.workspace"),
        keybind: "mod+shift+w",
        disabled: !ctx.workspaceSetting(),
        onSelect: () => {
          const project = ctx.currentProject()
          if (!project) return
          return ctx.createWorkspace(project)
        },
      },
      {
        id: "workspace.toggle",
        title: language.t("command.workspace.toggle"),
        description: language.t("command.workspace.toggle.description"),
        category: language.t("command.category.workspace"),
        slash: "workspace",
        disabled: !ctx.currentProject() || ctx.currentProject()?.vcs !== "git",
        onSelect: () => {
          const project = ctx.currentProject()
          if (!project) return
          if (project.vcs !== "git") return
          const wasEnabled = layout.sidebar.workspaces(project.worktree)()
          layout.sidebar.toggleWorkspaces(project.worktree)
          showToast({
            title: wasEnabled
              ? language.t("toast.workspace.disabled.title")
              : language.t("toast.workspace.enabled.title"),
            description: wasEnabled
              ? language.t("toast.workspace.disabled.description")
              : language.t("toast.workspace.enabled.description"),
          })
        },
      },
      {
        id: "theme.cycle",
        title: language.t("command.theme.cycle"),
        category: language.t("command.category.theme"),
        keybind: "mod+shift+t",
        onSelect: () => ctx.cycleColorScheme(1),
      },
    ]

    commands.push({
      id: "theme.scheme.cycle",
      title: language.t("command.theme.scheme.cycle"),
      category: language.t("command.category.theme"),
      keybind: "mod+shift+c",
      onSelect: () => ctx.cycleColorScheme(1),
    })

    for (const scheme of colorSchemeOrder) {
      commands.push({
        id: `theme.scheme.${scheme}`,
        title: language.t("command.theme.scheme.set", { scheme: colorSchemeLabel(scheme) }),
        category: language.t("command.category.theme"),
        onSelect: () => theme.setColorScheme(scheme),
        onHighlight: () => {
          theme.previewColorScheme(scheme)
          return () => theme.cancelPreview()
        },
      })
    }

    commands.push({
      id: "language.cycle",
      title: language.t("command.language.cycle"),
      category: language.t("command.category.language"),
      onSelect: () => ctx.cycleLanguage(1),
    })

    for (const locale of language.locales) {
      commands.push({
        id: `language.set.${locale}`,
        title: language.t("command.language.set", { language: language.label(locale) }),
        category: language.t("command.category.language"),
        onSelect: () => ctx.setLocale(locale),
      })
    }

    return commands
  })
}

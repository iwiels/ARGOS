import { Component } from "solid-js"
import { Dialog } from "@argos/ui/dialog"
import { Tabs } from "@argos/ui/tabs"
import { Icon } from "@argos/ui/icon"
import { useLanguage } from "@/context/language"
import { usePlatform } from "@/context/platform"
import { SettingsGeneral } from "./general"
import { SettingsKeybinds } from "../settings-keybinds"
import { SettingsProviders } from "./providers"
import { SettingsModels } from "./models"
import "./settings.css"
import { SettingsServers } from "./servers"

export const DialogSettings: Component = () => {
  const language = useLanguage()
  const platform = usePlatform()

  return (
    <Dialog label={language.t("sidebar.settings")} size="x-large" variant="settings" class="settings-dialog">
      <Tabs orientation="vertical" variant="settings" defaultValue="general" class="settings">
        <Tabs.List>
          <div class="flex flex-col justify-between h-full w-full">
            <div class="flex flex-col gap-3 w-full">
              <div class="flex flex-col gap-3">
                <div class="flex flex-col gap-1.5">
                  <Tabs.SectionTitle>{language.t("settings.section.desktop")}</Tabs.SectionTitle>
                  <div class="flex flex-col gap-1.5 w-full">
                    <Tabs.Trigger value="general">
                      <Icon name="sliders" />
                      {language.t("settings.tab.general")}
                    </Tabs.Trigger>
                    <Tabs.Trigger value="shortcuts">
                      <Icon name="keyboard" />
                      {language.t("settings.tab.shortcuts")}
                    </Tabs.Trigger>
                  </div>
                </div>

                <div class="flex flex-col gap-1.5">
                  <Tabs.SectionTitle>{language.t("settings.section.server")}</Tabs.SectionTitle>
                  <div class="flex flex-col gap-1.5 w-full">
                    <Tabs.Trigger value="servers">
                      <Icon name="server" />
                      {language.t("status.popover.tab.servers")}
                    </Tabs.Trigger>
                    <Tabs.Trigger value="providers">
                      <Icon name="link" />
                      {language.t("settings.providers.title")}
                    </Tabs.Trigger>
                    <Tabs.Trigger value="models">
                      <Icon name="brain" />
                      {language.t("settings.models.title")}
                    </Tabs.Trigger>
                  </div>
                </div>
              </div>
            </div>
            <div class="settings-nav-footer">
              <span>{language.t("app.name.desktop")}</span>
              <span class="text-xs font-normal text-text-tertiary">v{platform.version}</span>
            </div>
          </div>
        </Tabs.List>
        <Tabs.Content value="general" class="settings-panel">
          <SettingsGeneral />
        </Tabs.Content>
        <Tabs.Content value="shortcuts" class="settings-panel">
          <SettingsKeybinds />
        </Tabs.Content>
        <Tabs.Content value="servers" class="settings-panel">
          <SettingsServers />
        </Tabs.Content>
        <Tabs.Content value="providers" class="settings-panel">
          <SettingsProviders />
        </Tabs.Content>
        <Tabs.Content value="models" class="settings-panel">
          <SettingsModels />
        </Tabs.Content>
      </Tabs>
    </Dialog>
  )
}



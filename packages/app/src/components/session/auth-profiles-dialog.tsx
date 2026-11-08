import { Button } from "@argos/ui/button"
import { Dialog, DialogFooter } from "@argos/ui/dialog"
import { TextInput } from "@argos/ui/text-input"
import { useDialog } from "@argos/ui/context/dialog"
import { For, Show, onMount } from "solid-js"
import { createStore } from "solid-js/store"
import { useLanguage } from "@/context/language"
import { showToast } from "@/utils/toast"

type AuthProfile = { id: string; name: string; username: string; hasBrowserSession: boolean }

export function AuthProfilesDialog(props: { sessionID: string }) {
  const dialog = useDialog()
  const language = useLanguage()
  const [state, setState] = createStore({
    profiles: [] as AuthProfile[],
    name: "",
    username: "",
    password: "",
    userSelector: "",
    passwordSelector: "",
    submitSelector: "",
    successSelector: "",
    loading: true,
    saving: false,
    error: "",
  })

  const refresh = async () => {
    const api = window.api?.authProfiles
    if (!api) {
      setState({ loading: false, error: language.t("session.authProfiles.unavailable") })
      return
    }
    try {
      setState({ profiles: await api.list(props.sessionID), loading: false, error: "" })
    } catch {
      setState({ loading: false, error: language.t("session.authProfiles.storageUnavailable") })
    }
  }

  onMount(() => void refresh())

  const save = async (event: SubmitEvent) => {
    event.preventDefault()
    if (state.saving) return
    setState("saving", true)
    setState("error", "")
    try {
      const api = window.api?.authProfiles
      if (!api) throw new Error("unavailable")
      const profile = await api.save({
        sessionID: props.sessionID,
        name: state.name,
        username: state.username,
        password: state.password,
        userSelector: state.userSelector || undefined,
        passwordSelector: state.passwordSelector || undefined,
        submitSelector: state.submitSelector || undefined,
        successSelector: state.successSelector || undefined,
      })
      setState("profiles", (profiles) => [...profiles, profile].sort((a, b) => a.name.localeCompare(b.name)))
      setState({ name: "", username: "", password: "", userSelector: "", passwordSelector: "", submitSelector: "", successSelector: "" })
    } catch {
      setState("error", language.t("session.authProfiles.saveFailed"))
    } finally {
      setState("saving", false)
    }
  }

  const remove = async (profile: AuthProfile) => {
    if (!window.confirm(language.t("session.authProfiles.deleteConfirm"))) return
    try {
      await window.api?.authProfiles?.delete(props.sessionID, profile.id)
      setState("profiles", (profiles) => profiles.filter((item) => item.id !== profile.id))
    } catch {
      setState("error", language.t("session.authProfiles.deleteFailed"))
    }
  }

  return (
    <Dialog title={language.t("session.authProfiles.title")} description={language.t("session.authProfiles.description")} size="large" class="auth-profiles-dialog">
      <div class="flex w-full min-w-0 flex-1 flex-col gap-5 px-5 py-4">
        <section class="flex flex-col gap-2" aria-label={language.t("session.authProfiles.savedProfiles")}>
          <h3 class="text-13-medium text-text-primary">{language.t("session.authProfiles.savedProfiles")}</h3>
          <Show when={!state.loading} fallback={<p class="text-12-regular text-text-tertiary">{language.t("session.authProfiles.loading")}</p>}>
            <Show when={state.profiles.length > 0} fallback={<p class="text-12-regular text-text-tertiary">{language.t("session.authProfiles.empty")}</p>}>
              <div class="flex flex-col divide-y divide-border-weaker-base rounded-md border border-border-weaker-base">
                <For each={state.profiles}>
                  {(profile) => (
                    <div class="flex items-center justify-between gap-3 px-3 py-2.5">
                      <div class="min-w-0">
                        <div class="truncate text-13-medium text-text-primary">{profile.name}</div>
                        <div class="truncate text-11-regular text-text-tertiary">
                          {profile.username} · {profile.hasBrowserSession ? language.t("session.authProfiles.sessionReady") : language.t("session.authProfiles.loginRequired")}
                        </div>
                        <div class="truncate font-mono text-10-regular text-text-tertiary">{profile.id}</div>
                      </div>
                      <div class="flex shrink-0 items-center gap-1">
                        <Button
                          type="button"
                          variant="ghost"
                          size="small"
                          onClick={() =>
                            void navigator.clipboard.writeText(profile.id).then(() =>
                              showToast({ title: language.t("session.authProfiles.idCopied") }),
                            )
                          }
                        >
                          {language.t("session.authProfiles.copyID")}
                        </Button>
                        <Button type="button" variant="ghost" size="small" disabled={state.saving} onClick={() => void remove(profile)}>
                          {language.t("common.delete")}
                        </Button>
                      </div>
                    </div>
                  )}
                </For>
              </div>
            </Show>
          </Show>
        </section>

        <form class="flex flex-col gap-3 border-t border-border-weaker-base pt-4" onSubmit={save}>
          <h3 class="text-13-medium text-text-primary">{language.t("session.authProfiles.add")}</h3>
          <div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <label class="flex min-w-0 flex-col gap-1.5 text-12-medium text-text-secondary">
              {language.t("session.authProfiles.name")}
              <TextInput value={state.name} required maxlength={120} autocomplete="off" onInput={(event) => setState("name", event.currentTarget.value)} />
            </label>
            <label class="flex min-w-0 flex-col gap-1.5 text-12-medium text-text-secondary">
              {language.t("session.authProfiles.username")}
              <TextInput value={state.username} required maxlength={4096} autocomplete="username" onInput={(event) => setState("username", event.currentTarget.value)} />
            </label>
            <label class="flex min-w-0 flex-col gap-1.5 text-12-medium text-text-secondary sm:col-span-2">
              {language.t("session.authProfiles.password")}
              <TextInput type="password" value={state.password} required maxlength={4096} autocomplete="new-password" onInput={(event) => setState("password", event.currentTarget.value)} />
            </label>
            <label class="flex min-w-0 flex-col gap-1.5 text-12-medium text-text-secondary">
              {language.t("session.authProfiles.userSelector")}
              <TextInput value={state.userSelector} maxlength={512} autocomplete="off" onInput={(event) => setState("userSelector", event.currentTarget.value)} />
            </label>
            <label class="flex min-w-0 flex-col gap-1.5 text-12-medium text-text-secondary">
              {language.t("session.authProfiles.passwordSelector")}
              <TextInput value={state.passwordSelector} maxlength={512} autocomplete="off" onInput={(event) => setState("passwordSelector", event.currentTarget.value)} />
            </label>
            <label class="flex min-w-0 flex-col gap-1.5 text-12-medium text-text-secondary">
              {language.t("session.authProfiles.submitSelector")}
              <TextInput value={state.submitSelector} maxlength={512} autocomplete="off" onInput={(event) => setState("submitSelector", event.currentTarget.value)} />
            </label>
            <label class="flex min-w-0 flex-col gap-1.5 text-12-medium text-text-secondary">
              {language.t("session.authProfiles.successSelector")}
              <TextInput value={state.successSelector} maxlength={512} autocomplete="off" onInput={(event) => setState("successSelector", event.currentTarget.value)} />
            </label>
          </div>
          <Show when={state.error}>
            <p class="text-12-regular text-severity-fg-critical" role="alert">{state.error}</p>
          </Show>
          <p class="text-11-regular text-text-tertiary">{language.t("session.authProfiles.protectedNotice")}</p>
          <DialogFooter>
            <div class="flex w-full justify-end gap-2">
              <Button type="button" variant="neutral" disabled={state.saving} onClick={() => dialog.close()}>
                {language.t("common.close")}
              </Button>
              <Button type="submit" variant="contrast" disabled={state.saving}>
                {state.saving ? language.t("session.authProfiles.saving") : language.t("session.authProfiles.save")}
              </Button>
            </div>
          </DialogFooter>
        </form>
      </div>
    </Dialog>
  )
}

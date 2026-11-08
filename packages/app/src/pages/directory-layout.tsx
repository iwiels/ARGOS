import { DataProvider } from "@argos/ui/context"
import { showToast } from "@/utils/toast"
import { base64Encode } from "@/core/encode"
import { useLocation, useNavigate, useParams } from "@solidjs/router"
import { createEffect, createMemo, createResource, createSignal, type ParentProps, Show } from "solid-js"
import { RouteErrorBoundary } from "@/components/route-error-boundary"
import { useLanguage } from "@/context/language"
import { LocalProvider } from "@/context/local"
import { SDKProvider } from "@/context/sdk"
import { useSync } from "@/context/sync"
import { decode64 } from "@/utils/base64"
import { Schema } from "effect"

function DirectoryDataProvider(props: ParentProps<{ directory: string }>) {
  const location = useLocation()
  const navigate = useNavigate()
  const params = useParams()
  const sync = useSync()
  const slug = createMemo(() => base64Encode(props.directory))

  createEffect(() => {
    const next = sync.data.path.directory
    if (!next || next === props.directory) return
    const path = location.pathname.slice(slug().length + 1)
    navigate(`/${base64Encode(next)}${path}${location.search}${location.hash}`, { replace: true })
  })

  createResource(
    () => params.id,
    (id) => sync.session.sync(id).catch(() => {}),
  )

  return (
    <DataProvider
      data={sync.data}
      directory={props.directory}
      onNavigateToSession={(sessionID: string) => navigate(`/${slug()}/session/${sessionID}`)}
      onSessionHref={(sessionID: string) => `/${slug()}/session/${sessionID}`}
    >
      <LocalProvider>{props.children}</LocalProvider>
    </DataProvider>
  )
}

export const ProjectDirString = Schema.String.pipe(Schema.brand("ProjectDirString"))
export type ProjectDirString = Schema.Schema.Type<typeof ProjectDirString>

export function decodeDirectory(dir: string): ProjectDirString | undefined {
  const decoded = decode64(dir)
  if (!decoded) return
  return ProjectDirString.make(decoded)
}

export default function Layout(props: ParentProps) {
  const params = useParams()
  const language = useLanguage()
  const navigate = useNavigate()
  const [invalid, setInvalid] = createSignal("")

  const resolved = createMemo(() => {
    const raw = params.dir ?? params.auditId
    if (!raw) return ""
    return decodeDirectory(raw) ?? (raw ? ProjectDirString.make(raw) : "")
  })

  createEffect(() => {
    const dir = params.dir
    if (!dir) return
    if (resolved()) {
      setInvalid("")
      return
    }
    if (invalid() === dir) return
    setInvalid(dir)
    showToast({
      title: language.t("common.requestFailed"),
      description: language.t("directory.error.invalidUrl"),
    })
    navigate("/", { replace: true })
  })

  return (
    <Show when={resolved()} keyed>
      {(resolved) => (
        <RouteErrorBoundary>
          <SDKProvider directory={resolved}>
            <DirectoryDataProvider directory={resolved}>{props.children}</DirectoryDataProvider>
          </SDKProvider>
        </RouteErrorBoundary>
      )}
    </Show>
  )
}



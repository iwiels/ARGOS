import { Show } from "solid-js"
import { NewSessionDesignView } from "@/components/session"
import { PromptInput } from "@/components/prompt-input"
import { SDKProvider } from "@/context/sdk"
import { LocalProvider } from "@/context/local"
import { FileProvider } from "@/context/file"
import { CommentsProvider } from "@/context/comments"
import { PromptProvider } from "@/context/prompt"
import { AuditListView } from "@/components/audit/audit-list-view"
import { useHomeData } from "./home/use-home-data"

export default function Home() {
  return <HomeDesign />
}

function HomePromptInput(props: { directory?: string }) {
  return (
    <SDKProvider directory={props.directory ?? ""}>
      <LocalProvider>
        <FileProvider>
          <CommentsProvider>
            <PromptProvider>
              <NewSessionDesignView worktree={props.directory}>
                <PromptInput variant="new-session" newSessionWorktree={props.directory} />
              </NewSessionDesignView>
            </PromptProvider>
          </CommentsProvider>
        </FileProvider>
      </LocalProvider>
    </SDKProvider>
  )
}

function HomeDesign() {
  const { isHome, isAuditList, search, onSearch, records, isLoading, openSession, newSessionProject } =
    useHomeData()

  return (
    <div class="rounded-lg border border-border-weaker-base m-2 min-h-0 lg:overflow-hidden bg-bg-base self-stretch flex-1 relative flex flex-col">
      <Show when={isHome()}>
        <HomePromptInput directory={newSessionProject()?.worktree} />
      </Show>

      <Show when={isAuditList()}>
        <AuditListView
          records={records()}
          isLoading={isLoading()}
          search={search()}
          onSearch={onSearch}
          onOpenSession={openSession}
        />
      </Show>
    </div>
  )
}

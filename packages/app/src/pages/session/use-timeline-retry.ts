import { createSignal, type Accessor } from "solid-js"
import type { Message as MessageType, Part as PartType } from "@argos/sdk/client"
import { showToast } from "@/utils/toast"
import { sendFollowupDraft, type FollowupDraft } from "@/components/prompt-input/submit"
import { extractPromptFromParts } from "@/utils/prompt"
import { useLanguage } from "@/context/language"
import { useSDK } from "@/context/sdk"
import { useServerSync } from "@/context/server-sync"
import { useSync } from "@/context/sync"

export function useTimelineRetry(options: {
  sessionID: Accessor<string | undefined>
  messageByID: Accessor<Map<string, MessageType>>
  getMsgParts: (messageID: string) => PartType[]
}) {
  const { sessionID, messageByID, getMsgParts } = options
  const sdk = useSDK()
  const sync = useSync()
  const serverSync = useServerSync()
  const language = useLanguage()

  const [retrying, setRetrying] = createSignal(false)

  const errorMessage = (err: unknown) => {
    if (err && typeof err === "object" && "data" in err) {
      const data = (err as { data?: { message?: string } }).data
      if (data?.message) return data.message
    }
    if (err instanceof Error) return err.message
    return language.t("common.requestFailed")
  }

  const retryFailedTurn = async (userMessageID: string) => {
    const id = sessionID()
    const userMessage = messageByID().get(userMessageID)
    if (!id || !userMessage || userMessage.role !== "user") return
    const prompt = extractPromptFromParts(getMsgParts(userMessage.id), { directory: sdk.directory })
    const draft: FollowupDraft = {
      sessionID: id,
      sessionDirectory: sdk.directory,
      prompt,
      context: [],
      agent: userMessage.agent,
      model: { providerID: userMessage.model.providerID, modelID: userMessage.model.modelID },
    }
    setRetrying(true)
    try {
      await sendFollowupDraft({ client: sdk.client, sync, serverSync, draft, optimisticBusy: true })
    } catch (err) {
      showToast({
        title: language.t("common.requestFailed"),
        description: errorMessage(err),
      })
    } finally {
      setRetrying(false)
    }
  }

  return { retrying, retryFailedTurn, errorMessage }
}

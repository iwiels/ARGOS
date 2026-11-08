export const deepLinkEvent = "opencode:deep-link"

export const DEEP_LINK_SCHEMES = ["argos"] as const

const isDeepLink = (input: string) => DEEP_LINK_SCHEMES.some((scheme) => input.startsWith(`${scheme}://`))

const parseUrl = (input: string) => {
  if (!isDeepLink(input)) return
  if (typeof URL.canParse === "function" && !URL.canParse(input)) return
  try {
    return new URL(input)
  } catch {
    return
  }
}

export const parseDeepLink = (input: string) => {
  const url = parseUrl(input)
  if (!url) return
  if (url.hostname !== "open-project") return
  const directory = url.searchParams.get("directory")
  if (!directory) return
  return directory
}

export const parseNewSessionDeepLink = (input: string) => {
  const url = parseUrl(input)
  if (!url) return
  if (url.hostname !== "new-session") return
  const directory = url.searchParams.get("directory")
  if (!directory) return
  const prompt = url.searchParams.get("prompt") || undefined
  if (!prompt) return { directory }
  return { directory, prompt }
}

export const collectOpenProjectDeepLinks = (urls: string[]) =>
  urls.map(parseDeepLink).filter((directory): directory is string => !!directory)

export const collectNewSessionDeepLinks = (urls: string[]) =>
  urls.map(parseNewSessionDeepLink).filter((link): link is { directory: string; prompt?: string } => !!link)

type ArgosWindow = Window & {
  __ARGOS__?: {
    deepLinks?: string[]
  }
}

export const drainPendingDeepLinks = (target: ArgosWindow) => {
  const pending = target.__ARGOS__?.deepLinks
  if (!pending || pending.length === 0) return []
  target.__ARGOS__!.deepLinks = []
  return pending
}



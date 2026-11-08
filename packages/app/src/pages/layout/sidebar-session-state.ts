export type SessionInteraction =
  | { type: "idle" }
  | { type: "menu"; sessionID: string }
  | { type: "rename"; sessionID: string }

export type SessionInteractionEvent =
  | { type: "open-menu"; sessionID: string }
  | { type: "close-menu"; sessionID: string }
  | { type: "start-rename"; sessionID: string }
  | { type: "finish-rename"; sessionID: string }

export function focusSessionTitleEditor(input: HTMLInputElement): void {
  input.focus()
  input.select()
}

export function transitionSessionInteraction(
  current: SessionInteraction,
  event: SessionInteractionEvent,
): SessionInteraction {
  switch (event.type) {
    case "open-menu":
      return { type: "menu", sessionID: event.sessionID }
    case "close-menu":
      return current.type === "menu" && current.sessionID === event.sessionID ? { type: "idle" } : current
    case "start-rename":
      return { type: "rename", sessionID: event.sessionID }
    case "finish-rename":
      return current.type === "rename" && current.sessionID === event.sessionID ? { type: "idle" } : current
  }
}

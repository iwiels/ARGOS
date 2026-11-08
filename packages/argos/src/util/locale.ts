export class Locale {
  static truncate(text: string, width: number): string {
    if (text.length <= width) return text
    return text.slice(0, Math.max(0, width - 1)) + "…"
  }

  static todayTimeOrDateTime(value: number | string | Date): string {
    const date = value instanceof Date ? value : new Date(value)
    const now = new Date()
    const isToday = date.toDateString() === now.toDateString()
    return isToday
      ? date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })
      : date.toLocaleDateString()
  }
}

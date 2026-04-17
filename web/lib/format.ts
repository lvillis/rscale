import type { ConsoleLocale } from "@/lib/console-i18n"

const UPTIME_UNITS: Record<ConsoleLocale, { day: string; hour: string; minute: string }> = {
  zh: {
    day: "天",
    hour: "小时",
    minute: "分钟",
  },
  en: {
    day: "d",
    hour: "h",
    minute: "m",
  },
  de: {
    day: "Tg",
    hour: "Std",
    minute: "Min",
  },
}

export type FormatLocale = ConsoleLocale
export type FormatTimeZone = "local" | "utc"

function resolveLocale(locale: FormatLocale) {
  if (locale === "zh") {
    return "zh-CN"
  }

  if (locale === "de") {
    return "de-DE"
  }

  return "en-US"
}

function resolveTimeZone(timezone: FormatTimeZone) {
  return timezone === "utc" ? "UTC" : undefined
}

export function formatDateTime(
  unixSeconds?: number | null,
  locale: FormatLocale = "zh",
  timezone: FormatTimeZone = "local"
) {
  if (!unixSeconds) {
    return "—"
  }

  return new Intl.DateTimeFormat(resolveLocale(locale), {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: resolveTimeZone(timezone),
  }).format(new Date(unixSeconds * 1000))
}

export function formatClockTime(
  value?: number | Date | null,
  locale: FormatLocale = "zh",
  timezone: FormatTimeZone = "local"
) {
  if (value === null || value === undefined) {
    return "—"
  }

  const date = value instanceof Date ? value : new Date(value)
  if (Number.isNaN(date.getTime())) {
    return "—"
  }

  return new Intl.DateTimeFormat(resolveLocale(locale), {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    timeZone: resolveTimeZone(timezone),
  }).format(date)
}

export function formatUptime(totalSeconds: number, locale: FormatLocale = "zh") {
  const days = Math.floor(totalSeconds / 86_400)
  const hours = Math.floor((totalSeconds % 86_400) / 3_600)
  const minutes = Math.floor((totalSeconds % 3_600) / 60)

  const units = UPTIME_UNITS[locale]
  const parts = [
    days > 0 ? `${days} ${units.day}` : null,
    hours > 0 ? `${hours} ${units.hour}` : null,
    `${minutes} ${units.minute}`,
  ]

  return parts.join(" ")
}

export function truncateMiddle(value: string, head = 8, tail = 6) {
  if (value.length <= head + tail + 1) {
    return value
  }

  return `${value.slice(0, head)}…${value.slice(-tail)}`
}

export function joinTags(tags: string[], emptyLabel = "—") {
  if (tags.length === 0) {
    return emptyLabel
  }

  return tags.join(", ")
}

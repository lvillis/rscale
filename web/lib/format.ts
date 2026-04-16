type FormatLocale = "zh" | "en"

function resolveLocale(locale: FormatLocale) {
  return locale === "zh" ? "zh-CN" : "en-US"
}

export function formatDateTime(unixSeconds?: number | null, locale: FormatLocale = "zh") {
  if (!unixSeconds) {
    return "—"
  }

  return new Intl.DateTimeFormat(resolveLocale(locale), {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(unixSeconds * 1000))
}

export function formatUptime(totalSeconds: number, locale: FormatLocale = "zh") {
  const days = Math.floor(totalSeconds / 86_400)
  const hours = Math.floor((totalSeconds % 86_400) / 3_600)
  const minutes = Math.floor((totalSeconds % 3_600) / 60)

  const parts =
    locale === "zh"
      ? [
          days > 0 ? `${days} 天` : null,
          hours > 0 ? `${hours} 小时` : null,
          `${minutes} 分钟`,
        ]
      : [
          days > 0 ? `${days}d` : null,
          hours > 0 ? `${hours}h` : null,
          `${minutes}m`,
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

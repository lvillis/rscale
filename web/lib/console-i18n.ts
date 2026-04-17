export const CONSOLE_LOCALES = ["zh", "en", "de"] as const

export type ConsoleLocale = (typeof CONSOLE_LOCALES)[number]

export const DEFAULT_CONSOLE_LOCALE: ConsoleLocale = "zh"

export const CONSOLE_LOCALE_META: Record<
  ConsoleLocale,
  {
    label: string
    nativeLabel: string
    htmlLang: string
  }
> = {
  zh: {
    label: "中文",
    nativeLabel: "简体中文",
    htmlLang: "zh-CN",
  },
  en: {
    label: "English",
    nativeLabel: "English",
    htmlLang: "en",
  },
  de: {
    label: "Deutsch",
    nativeLabel: "Deutsch",
    htmlLang: "de-DE",
  },
}

export function isConsoleLocale(value: string | null | undefined): value is ConsoleLocale {
  return Boolean(value && CONSOLE_LOCALES.includes(value as ConsoleLocale))
}

export function resolveConsoleLocale(value: string | null | undefined): ConsoleLocale | null {
  if (!value) {
    return null
  }

  const normalized = value.trim().toLowerCase()

  if (normalized.startsWith("zh")) {
    return "zh"
  }

  if (normalized.startsWith("de")) {
    return "de"
  }

  if (normalized.startsWith("en")) {
    return "en"
  }

  return null
}

export function resolveConsoleHtmlLang(locale: ConsoleLocale) {
  return CONSOLE_LOCALE_META[locale].htmlLang
}

export function detectBrowserConsoleLocale(
  navigatorLike?: Pick<Navigator, "language" | "languages">
): ConsoleLocale {
  const languages = navigatorLike?.languages ?? []

  for (const language of languages) {
    const resolved = resolveConsoleLocale(language)
    if (resolved) {
      return resolved
    }
  }

  return (
    resolveConsoleLocale(navigatorLike?.language) ??
    DEFAULT_CONSOLE_LOCALE
  )
}

export function resolveInitialConsoleLocale(
  persistedLocale?: string | null,
  navigatorLike?: Pick<Navigator, "language" | "languages">
) {
  return (
    resolveConsoleLocale(persistedLocale) ??
    detectBrowserConsoleLocale(navigatorLike) ??
    DEFAULT_CONSOLE_LOCALE
  )
}

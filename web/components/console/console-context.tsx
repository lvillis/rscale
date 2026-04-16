"use client"

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  useTransition,
  type Dispatch,
  type ReactNode,
  type SetStateAction,
} from "react"
import { useQueryClient } from "@tanstack/react-query"

import {
  CONSOLE_AUTH_EXPIRED_EVENT,
  ConsoleApiError,
  type ConsoleConnectionSettings,
} from "@/lib/api"
import {
  clearConnectionSettings,
  DEFAULT_CONNECTION_SETTINGS,
  loadConnectionSettings,
  saveConnectionSettings,
} from "@/lib/connection"
import type { ConsoleLocale } from "./strings"

type ConsoleTheme = "dark" | "light"
type ConsoleToastTone = "success" | "info" | "error"

type ConsoleToast = {
  id: string
  tone: ConsoleToastTone
  message: string
}

type ConsoleConfirmState = {
  title?: string
  message: string
  confirmLabel?: string
  tone?: "default" | "danger"
}

type ConsoleContextValue = {
  hydrated: boolean
  theme: ConsoleTheme
  locale: ConsoleLocale
  toggleTheme: () => void
  toggleLocale: () => void
  settings: ConsoleConnectionSettings
  draftSettings: ConsoleConnectionSettings
  setDraftSettings: Dispatch<SetStateAction<ConsoleConnectionSettings>>
  useCustomApiBaseUrl: boolean
  setUseCustomApiBaseUrl: Dispatch<SetStateAction<boolean>>
  connectionReady: boolean
  runtimeOrigin: string
  connectionLabel: string
  lastSyncAt: number | null
  saveConnection: () => void
  clearConnection: () => void
  isRefreshing: boolean
  refreshAll: () => void
  queryScope: readonly [string, number, string]
  toasts: ConsoleToast[]
  pushToast: (input: { message: string; tone?: ConsoleToastTone }) => void
  dismissToast: (id: string) => void
  confirmAction: (options: ConsoleConfirmState) => Promise<boolean>
  confirmState: ConsoleConfirmState | null
  resolveConfirm: (accepted: boolean) => void
}

const THEME_KEY = "rscale.console.theme"
const LOCALE_KEY = "rscale.console.locale"

const ConsoleContext = createContext<ConsoleContextValue | null>(null)

function resolveConnectionLabel(settings: ConsoleConnectionSettings) {
  return settings.apiBaseUrl.trim() || "current-origin"
}

function resolveRuntimeOrigin() {
  if (typeof window === "undefined") {
    return ""
  }

  return window.location.origin
}

function resolveNextPath(nextPath: string) {
  if (!nextPath.startsWith("/") || nextPath.startsWith("/login")) {
    return "/overview/"
  }

  return nextPath
}

export function getConsoleErrorMessage(error: unknown, fallback = "Unknown error") {
  if (error instanceof ConsoleApiError) {
    return error.message
  }

  if (error instanceof Error) {
    return error.message
  }

  return fallback
}

export function ConsoleProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient()
  const [hydrated, setHydrated] = useState(false)
  const [theme, setTheme] = useState<ConsoleTheme>("dark")
  const [locale, setLocale] = useState<ConsoleLocale>("zh")
  const [isRefreshing, startRefreshing] = useTransition()
  const [connectionVersion, setConnectionVersion] = useState(0)
  const [settings, setSettings] = useState<ConsoleConnectionSettings>(
    DEFAULT_CONNECTION_SETTINGS
  )
  const [lastSyncAt, setLastSyncAt] = useState<number | null>(null)
  const [draftSettings, setDraftSettings] = useState<ConsoleConnectionSettings>(
    DEFAULT_CONNECTION_SETTINGS
  )
  const [useCustomApiBaseUrl, setUseCustomApiBaseUrl] = useState(false)
  const [toasts, setToasts] = useState<ConsoleToast[]>([])
  const [confirmState, setConfirmState] = useState<ConsoleConfirmState | null>(null)
  const confirmResolverRef = useRef<((accepted: boolean) => void) | null>(null)
  const toastTimersRef = useRef(new Map<string, number>())

  useEffect(() => {
    const persistedSettings = loadConnectionSettings()
    const persistedTheme =
      typeof window !== "undefined"
        ? (window.localStorage.getItem(THEME_KEY) as ConsoleTheme | null)
        : null
    const persistedLocale =
      typeof window !== "undefined"
        ? (window.localStorage.getItem(LOCALE_KEY) as ConsoleLocale | null)
        : null

    const timer = window.setTimeout(() => {
      setSettings(persistedSettings)
      setDraftSettings(persistedSettings)
      setUseCustomApiBaseUrl(Boolean(persistedSettings.apiBaseUrl.trim()))
      setTheme(persistedTheme === "light" ? "light" : "dark")
      setLocale(persistedLocale === "en" ? "en" : "zh")
      setLastSyncAt(null)
      setConnectionVersion(Date.now())
      setHydrated(true)
    }, 0)

    return () => window.clearTimeout(timer)
  }, [])

  useEffect(() => {
    if (!hydrated || typeof window === "undefined") {
      return
    }

    window.localStorage.setItem(THEME_KEY, theme)
    document.documentElement.dataset.theme = theme
    document.documentElement.style.colorScheme = theme
  }, [hydrated, theme])

  useEffect(() => {
    if (!hydrated || typeof window === "undefined") {
      return
    }

    window.localStorage.setItem(LOCALE_KEY, locale)
    document.documentElement.lang = locale === "zh" ? "zh-CN" : "en"
  }, [hydrated, locale])

  useEffect(() => {
    const toastTimers = toastTimersRef.current

    return () => {
      confirmResolverRef.current?.(false)
      toastTimers.forEach((timer) => {
        window.clearTimeout(timer)
      })
      toastTimers.clear()
    }
  }, [])

  useEffect(() => {
    if (!hydrated || typeof window === "undefined") {
      return
    }

    const onStorage = (event: StorageEvent) => {
      if (event.storageArea !== window.localStorage) {
        return
      }

      if (event.key !== "rscale.console.connection") {
        return
      }

      const nextSettings = loadConnectionSettings()
      setSettings(nextSettings)
      setDraftSettings(nextSettings)
      setUseCustomApiBaseUrl(Boolean(nextSettings.apiBaseUrl.trim()))
      setLastSyncAt(null)
      setConnectionVersion(Date.now())
      queryClient.clear()
    }

    window.addEventListener("storage", onStorage)
    return () => window.removeEventListener("storage", onStorage)
  }, [hydrated, queryClient])

  useEffect(() => {
    return queryClient.getQueryCache().subscribe((event) => {
      if (event?.type !== "updated") {
        return
      }

      const queryKey = event.query.queryKey
      if (!Array.isArray(queryKey) || queryKey[0] !== "console") {
        return
      }

      const updatedAt = event.query.state.dataUpdatedAt
      if (!updatedAt || event.query.state.status !== "success") {
        return
      }

      setLastSyncAt((current) => (current && current >= updatedAt ? current : updatedAt))
    })
  }, [queryClient])

  const resetConnection = useCallback(() => {
    clearConnectionSettings()
    setSettings(DEFAULT_CONNECTION_SETTINGS)
    setDraftSettings(DEFAULT_CONNECTION_SETTINGS)
    setUseCustomApiBaseUrl(false)
    setLastSyncAt(null)
    setConnectionVersion(Date.now())
    queryClient.clear()
  }, [queryClient])

  useEffect(() => {
    if (!hydrated || typeof window === "undefined") {
      return
    }

    const onAuthExpired = () => {
      resetConnection()
      const nextPath = resolveNextPath(`${window.location.pathname}${window.location.search}`)
      if (!window.location.pathname.startsWith("/login")) {
        window.location.replace(
          `/login/?reason=expired&next=${encodeURIComponent(nextPath)}`
        )
      }
    }

    window.addEventListener(CONSOLE_AUTH_EXPIRED_EVENT, onAuthExpired)
    return () => window.removeEventListener(CONSOLE_AUTH_EXPIRED_EVENT, onAuthExpired)
  }, [hydrated, resetConnection])

  const connectionReady = hydrated && settings.adminToken.trim().length > 0
  const connectionLabel = resolveConnectionLabel(settings)
  const runtimeOrigin = resolveRuntimeOrigin()
  const queryScope = useMemo(
    () => ["console", connectionVersion, connectionLabel] as const,
    [connectionVersion, connectionLabel]
  )

  const refreshAll = () => {
    startRefreshing(() => {
      void queryClient.invalidateQueries({ queryKey: queryScope })
    })
  }

  const dismissToast = useCallback((id: string) => {
    const timer = toastTimersRef.current.get(id)
    if (timer) {
      window.clearTimeout(timer)
      toastTimersRef.current.delete(id)
    }
    setToasts((current) => current.filter((toast) => toast.id !== id))
  }, [])

  const pushToast = useCallback(
    ({ message, tone = "info" }: { message: string; tone?: ConsoleToastTone }) => {
      const id = `${Date.now()}-${Math.random().toString(16).slice(2)}`
      setToasts((current) => [...current, { id, tone, message }])
      if (typeof window !== "undefined") {
        const timer = window.setTimeout(() => {
          dismissToast(id)
        }, 3200)
        toastTimersRef.current.set(id, timer)
      }
    },
    [dismissToast]
  )

  const resolveConfirm = useCallback((accepted: boolean) => {
    confirmResolverRef.current?.(accepted)
    confirmResolverRef.current = null
    setConfirmState(null)
  }, [])

  const confirmAction = useCallback((options: ConsoleConfirmState) => {
    confirmResolverRef.current?.(false)
    setConfirmState(options)
    return new Promise<boolean>((resolve) => {
      confirmResolverRef.current = resolve
    })
  }, [])

  const saveConnection = () => {
    const nextSettings = {
      ...draftSettings,
      apiBaseUrl: useCustomApiBaseUrl ? draftSettings.apiBaseUrl.trim() : "",
      adminToken: draftSettings.adminToken.trim(),
    }

    saveConnectionSettings(nextSettings)
    setSettings(nextSettings)
    setDraftSettings(nextSettings)
    setLastSyncAt(null)
    setConnectionVersion(Date.now())
    queryClient.clear()
  }

  const value: ConsoleContextValue = {
    hydrated,
    theme,
    locale,
    toggleTheme: () => setTheme((current) => (current === "dark" ? "light" : "dark")),
    toggleLocale: () => setLocale((current) => (current === "zh" ? "en" : "zh")),
    settings,
    draftSettings,
    setDraftSettings,
    useCustomApiBaseUrl,
    setUseCustomApiBaseUrl,
    connectionReady,
    runtimeOrigin,
    connectionLabel,
    lastSyncAt,
    saveConnection,
    clearConnection: resetConnection,
    isRefreshing,
    refreshAll,
    queryScope,
    toasts,
    pushToast,
    dismissToast,
    confirmAction,
    confirmState,
    resolveConfirm,
  }

  return <ConsoleContext.Provider value={value}>{children}</ConsoleContext.Provider>
}

export function useConsole() {
  const context = useContext(ConsoleContext)

  if (!context) {
    throw new Error("useConsole must be used within ConsoleProvider")
  }

  return context
}

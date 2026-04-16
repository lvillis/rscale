import type { ConsoleConnectionSettings } from "@/lib/api"

const STORAGE_KEY = "rscale.console.connection"

export const DEFAULT_CONNECTION_SETTINGS: ConsoleConnectionSettings = {
  apiBaseUrl: "",
  adminToken: "",
}

export function loadConnectionSettings(): ConsoleConnectionSettings {
  if (typeof window === "undefined") {
    return DEFAULT_CONNECTION_SETTINGS
  }

  const raw = window.localStorage.getItem(STORAGE_KEY)
  if (!raw) {
    return DEFAULT_CONNECTION_SETTINGS
  }

  try {
    const parsed = JSON.parse(raw) as Partial<ConsoleConnectionSettings>

    return {
      apiBaseUrl: parsed.apiBaseUrl ?? "",
      adminToken: parsed.adminToken ?? "",
    }
  } catch {
    return DEFAULT_CONNECTION_SETTINGS
  }
}

export function saveConnectionSettings(settings: ConsoleConnectionSettings) {
  if (typeof window === "undefined") {
    return
  }

  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(settings))
}

export function clearConnectionSettings() {
  if (typeof window === "undefined") {
    return
  }

  window.localStorage.removeItem(STORAGE_KEY)
}

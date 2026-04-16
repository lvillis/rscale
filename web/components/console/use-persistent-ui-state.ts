"use client"

import { useEffect, useState } from "react"

const UI_STATE_VERSION = "v2"

function storageKey(key: string) {
  return `rscale.console.ui.${UI_STATE_VERSION}.${key}`
}

export function usePersistentUiState<T>(key: string, fallback: T) {
  const namespacedKey = storageKey(key)
  const [state, setState] = useState<T>(() => {
    if (typeof window === "undefined") {
      return fallback
    }

    const raw = window.localStorage.getItem(namespacedKey)
    if (!raw) {
      return fallback
    }

    try {
      return JSON.parse(raw) as T
    } catch {
      return fallback
    }
  })

  useEffect(() => {
    if (typeof window === "undefined") {
      return
    }

    window.localStorage.setItem(namespacedKey, JSON.stringify(state))
  }, [namespacedKey, state])

  return [state, setState] as const
}

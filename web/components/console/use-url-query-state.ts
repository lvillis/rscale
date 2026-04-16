"use client"

import { functionalUpdate, type OnChangeFn, type SortingState } from "@tanstack/react-table"
import { usePathname, useSearchParams } from "next/navigation"
import { useEffect, useMemo, useState } from "react"

export function useUrlQueryState(key: string) {
  const pathname = usePathname()
  const searchParams = useSearchParams()
  const [value, setValue] = useState<string | null>(null)
  const resolvedValue = value ?? searchParams.get(key) ?? ""

  useEffect(() => {
    if (typeof window === "undefined") {
      return
    }

    const url = new URL(window.location.href)
    if (resolvedValue.trim()) {
      url.searchParams.set(key, resolvedValue)
    } else {
      url.searchParams.delete(key)
    }

    const nextUrl = `${url.pathname}${url.search}${url.hash}`
    window.history.replaceState(window.history.state, "", nextUrl)
  }, [key, pathname, resolvedValue])

  return [resolvedValue, setValue] as const
}

function parseSortingState(value: string, fallback: SortingState) {
  if (!value) {
    return fallback
  }

  const [id, direction] = value.split(":")
  if (!id) {
    return fallback
  }

  return [{ id, desc: direction !== "asc" }]
}

function serializeSortingState(value: SortingState) {
  const first = value[0]
  if (!first?.id) {
    return ""
  }

  return `${first.id}:${first.desc ? "desc" : "asc"}`
}

export function useUrlSortingState(key: string, defaultState: SortingState) {
  const [rawValue, setRawValue] = useUrlQueryState(key)
  const sorting = useMemo(
    () => parseSortingState(rawValue, defaultState),
    [defaultState, rawValue]
  )

  const setSorting: OnChangeFn<SortingState> = (updater) => {
    const next = functionalUpdate(updater, sorting)
    setRawValue(serializeSortingState(next))
  }

  return [sorting, setSorting] as const
}

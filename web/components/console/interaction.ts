"use client"

export function focusCollectionItem(
  current: HTMLElement,
  selector: string,
  target: "previous" | "next" | "first" | "last"
) {
  if (typeof window === "undefined") {
    return
  }

  const items = Array.from(
    window.document.querySelectorAll<HTMLElement>(selector)
  ).filter((item) => item.tabIndex >= 0)

  if (items.length === 0) {
    return
  }

  if (target === "first") {
    items[0]?.focus()
    return
  }

  if (target === "last") {
    items[items.length - 1]?.focus()
    return
  }

  const currentIndex = items.findIndex((item) => item === current)
  if (currentIndex < 0) {
    items[0]?.focus()
    return
  }

  const nextIndex =
    target === "previous"
      ? Math.max(0, currentIndex - 1)
      : Math.min(items.length - 1, currentIndex + 1)

  items[nextIndex]?.focus()
}

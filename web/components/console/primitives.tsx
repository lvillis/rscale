"use client"

import type { ComponentType, ReactNode, RefObject } from "react"
import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import {
  AlertCircle,
  ArrowRight,
  CheckCircle2,
  Command,
  Info,
  LoaderCircle,
  RefreshCcw,
  Search,
  X,
} from "lucide-react"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"

function getFocusableElements(container: HTMLElement | null) {
  if (!container) {
    return []
  }

  return Array.from(
    container.querySelectorAll<HTMLElement>(
      'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
    )
  ).filter((element) => !element.hasAttribute("disabled") && element.getAttribute("aria-hidden") !== "true")
}

function trapFocusWithin(container: HTMLElement | null, event: KeyboardEvent) {
  if (event.key !== "Tab") {
    return false
  }

  const focusableElements = getFocusableElements(container)
  if (focusableElements.length === 0) {
    event.preventDefault()
    return true
  }

  const first = focusableElements[0]
  const last = focusableElements[focusableElements.length - 1]
  const activeElement = document.activeElement as HTMLElement | null

  if (event.shiftKey) {
    if (!activeElement || activeElement === first || !container?.contains(activeElement)) {
      event.preventDefault()
      last.focus()
      return true
    }
    return false
  }

  if (!activeElement || activeElement === last || !container?.contains(activeElement)) {
    event.preventDefault()
    first.focus()
    return true
  }

  return false
}

function useOverlayInteraction(open: boolean, containerRef: RefObject<HTMLElement | null>) {
  const restoreFocusRef = useRef<HTMLElement | null>(null)

  useEffect(() => {
    if (typeof window === "undefined" || !open) {
      return
    }

    restoreFocusRef.current =
      document.activeElement instanceof HTMLElement ? document.activeElement : null

    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = "hidden"

    return () => {
      document.body.style.overflow = previousOverflow
    }
  }, [open])

  useEffect(() => {
    if (open || typeof window === "undefined") {
      return
    }

    const target = restoreFocusRef.current
    restoreFocusRef.current = null
    if (target && document.contains(target)) {
      window.requestAnimationFrame(() => {
        target.focus()
      })
    }
  }, [open])

  useEffect(() => {
    if (!open || typeof window === "undefined") {
      return
    }

    const onKeyDown = (event: KeyboardEvent) => {
      trapFocusWithin(containerRef.current, event)
    }

    window.addEventListener("keydown", onKeyDown)
    return () => window.removeEventListener("keydown", onKeyDown)
  }, [containerRef, open])
}

export function StatusPill({
  label,
  healthy,
}: {
  label: string
  healthy: boolean
}) {
  return (
    <div className="console-surface-soft inline-flex items-center gap-2 rounded-full px-2.5 py-1 text-[11px] font-[510] tracking-[0.14em] text-secondary-foreground uppercase">
      <span
        className={`size-1.5 rounded-full ${healthy ? "bg-emerald-400" : "bg-rose-400"}`}
      />
      <span>{label}</span>
    </div>
  )
}

export function MetricTile({
  label,
  value,
  icon: Icon,
}: {
  label: string
  value: string
  icon: ComponentType<{ className?: string }>
}) {
  return (
    <Card className="shadow-none">
      <CardContent className="flex items-start justify-between gap-4 p-5">
        <div className="space-y-2">
          <div className="console-eyebrow text-[11px] font-[510] tracking-[0.18em] uppercase">
            {label}
          </div>
          <div className="text-[28px] leading-none font-[510] tracking-[-0.56px] text-foreground">
            {value}
          </div>
        </div>
        <div className="console-surface-soft flex size-10 items-center justify-center rounded-[12px] text-secondary-foreground">
          <Icon className="size-4" />
        </div>
      </CardContent>
    </Card>
  )
}

export function Panel({
  title,
  eyebrow,
  action,
  children,
  className,
  contentClassName,
}: {
  title?: string
  eyebrow?: string
  action?: ReactNode
  children: ReactNode
  className?: string
  contentClassName?: string
}) {
  const hasHeader = Boolean(title || eyebrow || action)

  return (
    <Card className={`shadow-none ${className ?? ""}`}>
      {hasHeader ? (
        <CardHeader className="flex flex-row items-start justify-between gap-4 space-y-0 border-b border-border pb-4">
          <div className="space-y-1">
            {eyebrow ? (
              <div className="console-eyebrow text-[11px] font-[510] tracking-[0.18em] uppercase">
                {eyebrow}
              </div>
            ) : null}
            {title ? (
              <CardTitle className="text-[16px] font-[510] tracking-[-0.22px] text-foreground">
                {title}
              </CardTitle>
            ) : null}
          </div>
          {action}
        </CardHeader>
      ) : null}
      <CardContent className={`p-5 ${contentClassName ?? ""}`}>{children}</CardContent>
    </Card>
  )
}

export function PanelRefreshAction({
  label,
  refreshingLabel,
  refreshing,
  onRefresh,
}: {
  label: string
  refreshingLabel: string
  refreshing: boolean
  onRefresh: () => void
}) {
  return (
    <Button variant="outline" size="sm" onClick={onRefresh} disabled={refreshing}>
      <RefreshCcw className={`size-3.5 ${refreshing ? "animate-spin" : ""}`} />
      {refreshing ? refreshingLabel : label}
    </Button>
  )
}

export function KeyValueGrid({
  items,
}: {
  items: Array<{ label: string; value: string }>
}) {
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      {items.map((item) => (
        <div
          key={item.label}
          className="console-surface-soft rounded-[12px] p-4"
        >
          <div className="console-eyebrow text-[11px] font-[510] tracking-[0.16em] uppercase">
            {item.label}
          </div>
          <div className="console-kv-value mt-2 break-all font-mono text-[12px]">
            {item.value}
          </div>
        </div>
      ))}
    </div>
  )
}

export function InlineAlert({
  tone = "error",
  children,
  action,
}: {
  tone?: "error" | "success" | "info"
  children: ReactNode
  action?: ReactNode
}) {
  const icon =
    tone === "success" ? (
      <CheckCircle2 className="mt-0.5 size-4 shrink-0" />
    ) : tone === "info" ? (
      <Info className="mt-0.5 size-4 shrink-0" />
    ) : (
      <AlertCircle className="mt-0.5 size-4 shrink-0" />
    )
  const className =
    tone === "success"
      ? "border-emerald-500/25 bg-emerald-500/10 text-emerald-700 dark:text-emerald-200"
      : tone === "info"
        ? "border-primary/18 bg-primary/10 text-secondary-foreground"
        : "console-alert-error"

  return (
    <div className={`${className} flex items-start justify-between gap-3 rounded-[12px] px-3 py-2 text-[13px]`}>
      <div className="flex min-w-0 items-start gap-2">
        {icon}
        <div className="min-w-0">{children}</div>
      </div>
      {action ? <div className="shrink-0">{action}</div> : null}
    </div>
  )
}

export function PanelState({
  mode,
  message,
  actionLabel,
  onAction,
}: {
  mode: "loading" | "error" | "empty"
  message: string
  actionLabel?: string
  onAction?: () => void
}) {
  return (
    <div className="console-surface-dashed flex min-h-[220px] flex-col items-center justify-center gap-4 rounded-[14px] px-6 py-8 text-center">
      <div
        className={`flex size-11 items-center justify-center rounded-full ${
          mode === "error"
            ? "bg-destructive/10 text-destructive-foreground"
            : "bg-[var(--surface-soft)] text-secondary-foreground"
        }`}
      >
        {mode === "loading" ? (
          <LoaderCircle className="size-5 animate-spin" />
        ) : (
          <AlertCircle className="size-5" />
        )}
      </div>
      <div className="space-y-1">
        <div className="text-[14px] font-[510] tracking-[-0.16px] text-foreground">
          {message}
        </div>
      </div>
      {actionLabel && onAction ? (
        <Button variant="outline" size="sm" onClick={onAction}>
          {actionLabel}
        </Button>
      ) : null}
    </div>
  )
}

export function SearchField({
  value,
  onChange,
  onClear,
  placeholder,
  clearLabel,
  focusLabel,
  className = "",
}: {
  value: string
  onChange: (value: string) => void
  onClear: () => void
  placeholder: string
  clearLabel: string
  focusLabel: string
  className?: string
}) {
  return (
    <div className={`relative ${className}`}>
      <Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
      <Input
        data-console-search="true"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        onKeyDown={(event) => {
          if (event.key !== "Escape") {
            return
          }

          event.preventDefault()
          if (value.trim()) {
            onClear()
            return
          }

          event.currentTarget.blur()
        }}
        placeholder={placeholder}
        autoComplete="off"
        className="pr-12 pl-9"
      />
      <div className="absolute top-1/2 right-2 flex -translate-y-1/2 items-center gap-1">
        {value ? (
          <button
            type="button"
            onClick={onClear}
            className="rounded-[8px] p-1 text-muted-foreground transition hover:bg-[var(--surface-soft)] hover:text-foreground"
            aria-label={clearLabel}
          >
            <X className="size-4" />
          </button>
        ) : (
          <div
            aria-label={focusLabel}
            className="console-surface-soft hidden h-7 min-w-7 items-center justify-center rounded-[8px] px-2 font-mono text-[11px] text-muted-foreground sm:inline-flex"
          >
            /
          </div>
        )}
      </div>
    </div>
  )
}

export function ShellLoadingState() {
  return (
    <main className="min-h-screen bg-background text-foreground">
      <div className="flex min-h-screen w-full">
        <aside className="console-shell-sidebar hidden h-screen w-[286px] shrink-0 lg:block">
          <div className="space-y-3 p-4">
            {Array.from({ length: 6 }).map((_, index) => (
              <Skeleton key={index} className="h-11 w-full" />
            ))}
          </div>
        </aside>
        <div className="min-w-0 flex-1">
          <div className="console-shell-topbar h-16" />
          <section className="space-y-6 p-4 sm:p-6 lg:p-8">
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
              {Array.from({ length: 5 }).map((_, index) => (
                <Skeleton key={index} className="h-[108px] w-full rounded-[16px]" />
              ))}
            </div>
            <div className="grid gap-6 xl:grid-cols-[1.08fr_0.92fr]">
              <Skeleton className="h-[420px] w-full rounded-[18px]" />
              <Skeleton className="h-[420px] w-full rounded-[18px]" />
            </div>
          </section>
        </div>
      </div>
    </main>
  )
}

export function ToastViewport({
  toasts,
  onDismiss,
}: {
  toasts: Array<{ id: string; tone: "success" | "info" | "error"; message: string }>
  onDismiss: (id: string) => void
}) {
  if (toasts.length === 0) {
    return null
  }

  return (
    <div className="pointer-events-none fixed top-4 right-4 z-[100] flex w-[min(360px,calc(100vw-2rem))] flex-col gap-2">
      {toasts.map((toast) => {
        const icon =
          toast.tone === "success" ? (
            <CheckCircle2 className="mt-0.5 size-4 shrink-0" />
          ) : toast.tone === "info" ? (
            <Info className="mt-0.5 size-4 shrink-0" />
          ) : (
            <AlertCircle className="mt-0.5 size-4 shrink-0" />
          )
        const className =
          toast.tone === "success"
            ? "border-emerald-500/25 bg-emerald-500/12 text-emerald-700 dark:text-emerald-200"
            : toast.tone === "info"
              ? "border-primary/18 bg-primary/10 text-secondary-foreground"
              : "console-alert-error"

        return (
          <div
            key={toast.id}
            className={`${className} pointer-events-auto flex items-start justify-between gap-3 rounded-[14px] border px-3 py-3 text-[13px] shadow-[0_24px_60px_rgba(0,0,0,0.22)] backdrop-blur-xl`}
          >
            <div className="flex min-w-0 items-start gap-2">
              {icon}
              <div className="min-w-0">{toast.message}</div>
            </div>
            <button
              type="button"
              onClick={() => onDismiss(toast.id)}
              className="shrink-0 text-muted-foreground transition hover:text-foreground"
              aria-label="dismiss toast"
            >
              <X className="size-4" />
            </button>
          </div>
        )
      })}
    </div>
  )
}

export function ConfirmDialog({
  open,
  title,
  message,
  confirmLabel,
  cancelLabel,
  tone = "default",
  onConfirm,
  onCancel,
}: {
  open: boolean
  title: string
  message: string
  confirmLabel: string
  cancelLabel: string
  tone?: "default" | "danger"
  onConfirm: () => void
  onCancel: () => void
}) {
  const dialogRef = useRef<HTMLDivElement | null>(null)
  const cancelButtonRef = useRef<HTMLButtonElement | null>(null)

  useOverlayInteraction(open, dialogRef)

  useEffect(() => {
    if (!open || typeof window === "undefined") {
      return
    }

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        onCancel()
        return
      }

      if ((event.metaKey || event.ctrlKey) && event.key === "Enter") {
        event.preventDefault()
        onConfirm()
      }
    }

    window.addEventListener("keydown", onKeyDown)
    return () => window.removeEventListener("keydown", onKeyDown)
  }, [onCancel, onConfirm, open])

  useEffect(() => {
    if (!open || typeof window === "undefined") {
      return
    }

    window.requestAnimationFrame(() => {
      cancelButtonRef.current?.focus()
    })
  }, [open])

  if (!open) {
    return null
  }

  return (
    <div className="fixed inset-0 z-[110] flex items-center justify-center bg-black/50 px-4 backdrop-blur-sm">
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="console-confirm-title"
        className="console-surface w-full max-w-[420px] rounded-[18px] p-5 shadow-[0_32px_80px_rgba(0,0,0,0.35)]"
      >
        <div className="space-y-2">
          <div id="console-confirm-title" className="text-[18px] font-[510] tracking-[-0.28px] text-foreground">
            {title}
          </div>
          <p className="text-[14px] leading-6 text-muted-foreground">{message}</p>
        </div>
        <div className="mt-5 flex justify-end gap-2">
          <Button ref={cancelButtonRef} variant="outline" onClick={onCancel}>
            {cancelLabel}
          </Button>
          <Button
            variant={tone === "danger" ? "destructive" : "default"}
            onClick={onConfirm}
          >
            {confirmLabel}
          </Button>
        </div>
      </div>
    </div>
  )
}

export function DetailSheet({
  open,
  title,
  subtitle,
  headerActions,
  canPrevious,
  canNext,
  onPrevious,
  onNext,
  children,
  onClose,
}: {
  open: boolean
  title: string
  subtitle?: string
  headerActions?: ReactNode
  canPrevious?: boolean
  canNext?: boolean
  onPrevious?: () => void
  onNext?: () => void
  children: ReactNode
  onClose: () => void
}) {
  const sheetRef = useRef<HTMLElement | null>(null)
  const closeButtonRef = useRef<HTMLButtonElement | null>(null)
  const bodyRef = useRef<HTMLDivElement | null>(null)

  useOverlayInteraction(open, sheetRef)

  useEffect(() => {
    if (!open || typeof window === "undefined") {
      return
    }

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        onClose()
        return
      }

      if (event.key === "ArrowLeft" && canPrevious && onPrevious) {
        event.preventDefault()
        onPrevious()
        return
      }

      if (event.key === "ArrowRight" && canNext && onNext) {
        event.preventDefault()
        onNext()
      }
    }

    window.addEventListener("keydown", onKeyDown)
    return () => window.removeEventListener("keydown", onKeyDown)
  }, [canNext, canPrevious, onClose, onNext, onPrevious, open])

  useEffect(() => {
    if (!open || typeof window === "undefined") {
      return
    }

    window.requestAnimationFrame(() => {
      closeButtonRef.current?.focus()
      if (bodyRef.current) {
        bodyRef.current.scrollTop = 0
      }
    })
  }, [open, title, subtitle])

  if (!open) {
    return null
  }

  return (
    <div className="fixed inset-0 z-[115] flex justify-end bg-black/38 backdrop-blur-[2px]">
      <button
        type="button"
        aria-label="close detail sheet"
        className="h-full flex-1 cursor-default"
        onClick={onClose}
      />
      <aside
        ref={sheetRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="console-detail-title"
        className="console-surface flex h-full w-full max-w-[520px] flex-col border-l border-border shadow-[-24px_0_72px_rgba(0,0,0,0.28)]"
      >
        <div className="flex items-start justify-between gap-4 border-b border-border px-5 py-4">
          <div className="min-w-0 flex-1 space-y-1">
            <div id="console-detail-title" className="text-[17px] font-[510] tracking-[-0.24px] text-foreground">
              {title}
            </div>
            {subtitle ? (
              <div className="text-[13px] text-muted-foreground">{subtitle}</div>
            ) : null}
          </div>
          {headerActions ? <div className="flex items-center gap-2">{headerActions}</div> : null}
          <button
            ref={closeButtonRef}
            type="button"
            onClick={onClose}
            className="rounded-[10px] p-2 text-muted-foreground transition hover:bg-[var(--surface-soft)] hover:text-foreground"
            aria-label="close"
          >
            <X className="size-4" />
          </button>
        </div>
        <div ref={bodyRef} className="console-scrollbar flex-1 overflow-y-auto p-5">{children}</div>
      </aside>
    </div>
  )
}

export function CommandPalette({
  open,
  title,
  placeholder,
  emptyLabel,
  items,
  onClose,
}: {
  open: boolean
  title: string
  placeholder: string
  emptyLabel: string
  items: Array<{
    id: string
    label: string
    hint?: string
    keywords?: string[]
    group?: string
    icon?: ComponentType<{ className?: string }>
    onSelect: () => void
  }>
  onClose: () => void
}) {
  const [query, setQuery] = useState("")
  const [selectedIndex, setSelectedIndex] = useState(0)
  const paletteRef = useRef<HTMLDivElement | null>(null)
  const inputRef = useRef<HTMLInputElement | null>(null)

  useOverlayInteraction(open, paletteRef)

  const handleClose = useCallback(() => {
    setQuery("")
    setSelectedIndex(0)
    onClose()
  }, [onClose])

  const filteredItems = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase()
    if (!normalizedQuery) {
      return items
    }

    return items.filter((item) => {
      const haystack = [item.label, ...(item.keywords ?? [])].join(" ").toLowerCase()
      return haystack.includes(normalizedQuery)
    })
  }, [items, query])

  const activeIndex =
    filteredItems.length === 0 ? -1 : Math.min(selectedIndex, filteredItems.length - 1)

  useEffect(() => {
    if (!open || typeof window === "undefined") {
      return
    }

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        handleClose()
        return
      }

      if (event.key === "ArrowDown") {
        event.preventDefault()
        setSelectedIndex((current) =>
          filteredItems.length === 0 ? 0 : Math.min(current + 1, filteredItems.length - 1)
        )
        return
      }

      if (event.key === "ArrowUp") {
        event.preventDefault()
        setSelectedIndex((current) => Math.max(current - 1, 0))
        return
      }

      if (event.key === "Enter" && activeIndex >= 0) {
        event.preventDefault()
        filteredItems[activeIndex]?.onSelect()
        handleClose()
      }
    }

    window.addEventListener("keydown", onKeyDown)
    return () => window.removeEventListener("keydown", onKeyDown)
  }, [activeIndex, filteredItems, handleClose, open])

  useEffect(() => {
    if (!open || typeof window === "undefined") {
      return
    }

    window.requestAnimationFrame(() => {
      inputRef.current?.focus()
      inputRef.current?.select()
    })
  }, [open])

  if (!open) {
    return null
  }

  return (
    <div className="fixed inset-0 z-[120] flex items-start justify-center bg-black/45 px-4 py-[10vh] backdrop-blur-sm">
      <div
        ref={paletteRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="console-command-title"
        className="console-surface w-full max-w-[640px] rounded-[20px] shadow-[0_40px_120px_rgba(0,0,0,0.38)]"
      >
        <div className="flex items-center gap-3 border-b border-border px-4 py-3">
          <div className="console-surface-soft flex size-9 items-center justify-center rounded-[12px] text-secondary-foreground">
            <Command className="size-4" />
          </div>
          <div className="min-w-0 flex-1">
            <div id="console-command-title" className="text-[15px] font-[510] tracking-[-0.18px] text-foreground">
              {title}
            </div>
          </div>
          <button
            type="button"
            onClick={handleClose}
            className="rounded-[10px] p-2 text-muted-foreground transition hover:bg-[var(--surface-soft)] hover:text-foreground"
            aria-label="close command palette"
          >
            <X className="size-4" />
          </button>
        </div>

        <div className="border-b border-border px-4 py-3">
          <div className="relative">
            <Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              ref={inputRef}
              value={query}
              onChange={(event) => {
                setQuery(event.target.value)
                setSelectedIndex(0)
              }}
              placeholder={placeholder}
              className="pl-9"
            />
          </div>
        </div>

        <div className="max-h-[50vh] overflow-y-auto p-2">
          {filteredItems.length === 0 ? (
            <div className="console-surface-dashed flex min-h-[180px] items-center justify-center rounded-[14px] px-6 text-center text-[14px] text-muted-foreground">
              {emptyLabel}
            </div>
          ) : (
            <div className="space-y-4">
              {Array.from(new Set(filteredItems.map((item) => item.group).filter(Boolean))).map(
                (group) => (
                  <div key={group} className="space-y-2">
                    <div className="console-eyebrow px-2 text-[11px] font-[510] tracking-[0.16em] uppercase">
                      {group}
                    </div>
                    <div className="space-y-1">
                      {filteredItems
                        .filter((item) => item.group === group)
                        .map((item) => {
                          const Icon = item.icon
                          const isActive =
                            activeIndex >= 0 && filteredItems[activeIndex]?.id === item.id
                          return (
                            <button
                              key={item.id}
                              type="button"
                              onMouseEnter={() => {
                                const index = filteredItems.findIndex((entry) => entry.id === item.id)
                                if (index >= 0) {
                                  setSelectedIndex(index)
                                }
                              }}
                              onClick={() => {
                                item.onSelect()
                                handleClose()
                              }}
                              className={`flex w-full items-center justify-between gap-3 rounded-[12px] px-3 py-2.5 text-left transition ${
                                isActive
                                  ? "bg-[var(--surface-soft)]"
                                  : "hover:bg-[var(--surface-soft)]"
                              }`}
                            >
                              <div className="flex min-w-0 items-center gap-3">
                                <div className="console-surface-soft flex size-8 items-center justify-center rounded-[10px] text-secondary-foreground">
                                  {Icon ? <Icon className="size-4" /> : <Command className="size-4" />}
                                </div>
                                <div className="min-w-0 text-[14px] font-[510] tracking-[-0.16px] text-foreground">
                                  {item.label}
                                </div>
                              </div>
                              <div className="flex items-center gap-2 text-[12px] text-muted-foreground">
                                {item.hint ? <span>{item.hint}</span> : null}
                                <ArrowRight className="size-3.5" />
                              </div>
                            </button>
                          )
                        })}
                    </div>
                  </div>
                )
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

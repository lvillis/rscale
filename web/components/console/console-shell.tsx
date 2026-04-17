"use client"

import Image from "next/image"
import Link from "next/link"
import { usePathname, useRouter } from "next/navigation"
import {
  Check,
  Clock3,
  Command,
  Globe2,
  LogOut,
  Moon,
  RefreshCcw,
  Settings2,
  Sun,
} from "lucide-react"
import { useEffect, useRef, useState, type ReactNode } from "react"

import { Button } from "@/components/ui/button"
import {
  CONSOLE_LOCALES,
  CONSOLE_LOCALE_META,
  type ConsoleLocale,
} from "@/lib/console-i18n"
import { formatClockTime } from "@/lib/format"
import {
  CommandPalette,
  ConfirmDialog,
  ShellLoadingState,
  ToastViewport,
} from "./primitives"
import { CONSOLE_COPY, CONSOLE_NAV_ITEMS, type ConsoleRouteKey } from "./strings"
import { useConsole } from "./console-context"

function getRouteKey(pathname: string): ConsoleRouteKey {
  if (pathname.startsWith("/monitoring")) return "monitoring"
  if (pathname.startsWith("/nodes")) return "nodes"
  if (pathname.startsWith("/access")) return "access"
  if (pathname.startsWith("/network")) return "network"
  if (pathname.startsWith("/audit")) return "audit"
  return "overview"
}

function buildLoginHref(nextPath: string) {
  const normalizedNextPath =
    nextPath && nextPath.startsWith("/") && !nextPath.startsWith("/login")
      ? nextPath
      : "/overview/"

  return `/login/?next=${encodeURIComponent(normalizedNextPath)}`
}

export function ConsoleShell({ children }: { children: ReactNode }) {
  const router = useRouter()
  const pathname = usePathname()
  const currentRoute = getRouteKey(pathname)
  const [navigatingTo, setNavigatingTo] = useState<string | null>(null)
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false)
  const [preferencesOpen, setPreferencesOpen] = useState(false)
  const preferencesRef = useRef<HTMLDivElement | null>(null)
  const {
    hydrated,
    theme,
    locale,
    timezone,
    toggleTheme,
    setTheme,
    setLocale,
    toggleTimezone,
    setTimezone,
    connectionReady,
    lastSyncAt,
    clearConnection,
    isRefreshing,
    refreshAll,
    toasts,
    dismissToast,
    confirmState,
    resolveConfirm,
  } = useConsole()

  const copy = CONSOLE_COPY[locale]

  useEffect(() => {
    if (hydrated && !connectionReady && typeof window !== "undefined") {
      const nextPath = `${window.location.pathname}${window.location.search}`
      router.replace(buildLoginHref(nextPath))
    }
  }, [hydrated, connectionReady, router])

  useEffect(() => {
    CONSOLE_NAV_ITEMS.forEach((item) => {
      router.prefetch(item.href)
    })
    router.prefetch("/login/")
  }, [router])

  useEffect(() => {
    if (typeof window === "undefined") {
      return
    }

    const onKeyDown = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null
      const isEditableTarget =
        target instanceof HTMLInputElement ||
        target instanceof HTMLTextAreaElement ||
        target instanceof HTMLSelectElement ||
        target?.isContentEditable === true

      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault()
        setCommandPaletteOpen((current) => !current)
        return
      }

      if (!isEditableTarget && event.key === "/") {
        const searchInput = window.document.querySelector<HTMLInputElement>(
          '[data-console-search="true"]'
        )
        if (searchInput) {
          event.preventDefault()
          searchInput.focus()
          searchInput.select()
        }
        return
      }

      if (
        !isEditableTarget &&
        !commandPaletteOpen &&
        !event.metaKey &&
        !event.ctrlKey &&
        !event.altKey &&
        !event.shiftKey &&
        event.key.toLowerCase() === "r"
      ) {
        event.preventDefault()
        if (!isRefreshing) {
          refreshAll()
        }
      }
    }

    window.addEventListener("keydown", onKeyDown)
    return () => window.removeEventListener("keydown", onKeyDown)
  }, [commandPaletteOpen, isRefreshing, refreshAll])

  useEffect(() => {
    if (!preferencesOpen || typeof window === "undefined") {
      return
    }

    const onPointerDown = (event: PointerEvent) => {
      if (!preferencesRef.current?.contains(event.target as globalThis.Node)) {
        setPreferencesOpen(false)
      }
    }

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setPreferencesOpen(false)
      }
    }

    window.addEventListener("pointerdown", onPointerDown)
    window.addEventListener("keydown", onKeyDown)
    return () => {
      window.removeEventListener("pointerdown", onPointerDown)
      window.removeEventListener("keydown", onKeyDown)
    }
  }, [preferencesOpen])

  if (!hydrated || !connectionReady) {
    return <ShellLoadingState />
  }

  const resolvedLastSync =
    lastSyncAt && Number.isFinite(lastSyncAt)
      ? formatClockTime(lastSyncAt, locale, timezone)
      : copy.common.never
  const timezoneHint =
    timezone === "local" ? copy.common.localTime : copy.common.utcTime
  const isRouteTransitioning = navigatingTo !== null && navigatingTo !== pathname

  const onSignOut = () => {
    clearConnection()
    if (typeof window !== "undefined") {
      const nextPath = `${window.location.pathname}${window.location.search}`
      setNavigatingTo("/login/")
      router.replace(buildLoginHref(nextPath))
    }
  }

  const beginNavigation = (href: string) => {
    if (href !== pathname) {
      setNavigatingTo(href)
    }
  }

  const localeActionLabels = Object.fromEntries(
    CONSOLE_LOCALES.map((targetLocale) => [
      targetLocale,
      `${copy.language}: ${CONSOLE_LOCALE_META[targetLocale].nativeLabel}`,
    ])
  ) as Record<ConsoleLocale, string>

  const commandItems = [
    ...CONSOLE_NAV_ITEMS.map((item) => ({
      id: `route:${item.key}`,
      label: copy.commands.actions[item.key],
      group: copy.commands.groups.navigate,
      hint: item.href.replace(/\/$/, ""),
      keywords: [copy.nav[item.key], item.key],
      icon: item.icon,
      onSelect: () => {
        beginNavigation(item.href)
        router.push(item.href)
      },
    })),
    {
      id: "action:refresh",
      label: copy.commands.actions.refresh,
      group: copy.commands.groups.actions,
      hint: "R",
      keywords: [copy.refresh, "reload", "sync"],
      icon: RefreshCcw,
      onSelect: () => refreshAll(),
    },
    {
      id: "action:theme",
      label: copy.commands.actions.theme,
      group: copy.commands.groups.actions,
      hint: theme === "dark" ? copy.themeLight : copy.themeDark,
      keywords: [copy.themeDark, copy.themeLight, "theme"],
      icon: theme === "dark" ? Sun : Moon,
      onSelect: () => toggleTheme(),
    },
    ...CONSOLE_LOCALES.map((targetLocale) => ({
      id: `action:locale:${targetLocale}`,
      label: localeActionLabels[targetLocale],
      group: copy.commands.groups.actions,
      hint:
        locale === targetLocale
          ? copy.common.enabled
          : CONSOLE_LOCALE_META[targetLocale].nativeLabel,
      keywords: [
        copy.language,
        "language",
        "locale",
        CONSOLE_LOCALE_META[targetLocale].label,
        CONSOLE_LOCALE_META[targetLocale].nativeLabel,
      ],
      icon: Globe2,
      onSelect: () => setLocale(targetLocale),
    })),
    {
      id: "action:timezone",
      label: copy.commands.actions.timezone,
      group: copy.commands.groups.actions,
      hint: timezoneHint,
      keywords: [copy.timezone, copy.common.localTime, copy.common.utcTime, "timezone", "utc"],
      icon: Clock3,
      onSelect: () => toggleTimezone(),
    },
    {
      id: "action:signout",
      label: copy.commands.actions.signOut,
      group: copy.commands.groups.actions,
      keywords: [copy.signOut, "logout"],
      icon: LogOut,
      onSelect: () => onSignOut(),
    },
  ]

  return (
    <main className="min-h-screen bg-background text-foreground lg:pl-[286px]">
      <ToastViewport toasts={toasts} onDismiss={dismissToast} />
      <CommandPalette
        open={commandPaletteOpen}
        title={copy.commands.title}
        placeholder={copy.commands.placeholder}
        emptyLabel={copy.commands.empty}
        items={commandItems}
        onClose={() => setCommandPaletteOpen(false)}
      />
      <ConfirmDialog
        open={Boolean(confirmState)}
        title={confirmState?.title ?? copy.common.confirm}
        message={confirmState?.message ?? ""}
        confirmLabel={confirmState?.confirmLabel ?? copy.common.confirm}
        cancelLabel={copy.common.cancel}
        tone={confirmState?.tone ?? "default"}
        onConfirm={() => resolveConfirm(true)}
        onCancel={() => resolveConfirm(false)}
      />
      <div className="min-h-screen w-full">
        <aside className="console-shell-sidebar fixed inset-y-0 left-0 z-50 hidden w-[286px] lg:block">
          <div className="flex h-full flex-col gap-6 overflow-y-auto px-4 py-5">
            <Link
              prefetch
              href="/overview/"
              onClick={() => beginNavigation("/overview/")}
              className="console-shell-logo flex items-center gap-3 rounded-[16px] px-4 py-3"
            >
              <div className="console-shell-logo-mark flex size-10 items-center justify-center">
                <Image
                  src="/brand/rscale-mark.svg"
                  alt="rscale"
                  className="size-10"
                  width={40}
                  height={40}
                  priority
                />
              </div>
              <div>
                <div className="console-eyebrow text-[11px] font-[510] tracking-[0.18em] uppercase">
                  rscale
                </div>
                <div className="text-[14px] font-[510] tracking-[-0.16px] text-foreground">
                  {copy.appName}
                </div>
                <div className="mt-1 text-[12px] text-muted-foreground">{copy.projectTagline}</div>
              </div>
            </Link>

            <nav className="space-y-1.5">
              {CONSOLE_NAV_ITEMS.map((item) => {
                const Icon = item.icon
                const active = currentRoute === item.key

                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    prefetch
                    onClick={() => beginNavigation(item.href)}
                    className={`flex h-10 w-full items-center gap-3 rounded-[10px] px-3 text-[13px] font-[510] tracking-[-0.13px] transition ${
                      active
                        ? "console-shell-nav-item-active"
                        : "console-shell-nav-item"
                    }`}
                  >
                    <Icon className="size-4" />
                    <span>{copy.nav[item.key]}</span>
                  </Link>
                )
              })}
            </nav>

            <div className="mt-auto px-3 pb-1">
              <div className="console-surface-soft rounded-[14px] border border-border/70 px-3 py-3">
                <div className="console-eyebrow text-[10px] font-[510] tracking-[0.14em] uppercase text-muted-foreground">
                  {copy.lastSync}
                </div>
                <div className="mt-2 font-mono text-[13px] text-foreground whitespace-nowrap">
                  {resolvedLastSync}
                </div>
                <div className="mt-2 text-[11px] text-muted-foreground">{timezoneHint}</div>
              </div>
            </div>
          </div>
        </aside>

        <div className="min-w-0">
          <header className="console-shell-topbar sticky top-0 z-40 backdrop-blur-xl">
            <div className="flex h-16 w-full items-center justify-between gap-4 px-4 sm:px-6 lg:px-8">
              <div className="space-y-1">
                <div className="console-shell-breadcrumb flex items-center gap-2 text-[12px]">
                  <span className="console-shell-breadcrumb-root font-[510]">{copy.breadcrumbRoot}</span>
                  <span>/</span>
                  <span>{copy.nav[currentRoute]}</span>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <div className="relative" ref={preferencesRef}>
                  <Button
                    variant="outline"
                    size="sm"
                    className="gap-2"
                    onClick={() => setPreferencesOpen((current) => !current)}
                    aria-expanded={preferencesOpen}
                    aria-label={copy.preferences}
                  >
                    <Settings2 className="size-4" />
                    <span className="hidden xl:inline">{copy.preferences}</span>
                  </Button>
                  {preferencesOpen ? (
                    <div className="console-surface-elevated absolute top-full right-0 z-30 mt-2 w-[340px] rounded-[16px] border border-border p-3 shadow-[0_18px_40px_rgba(0,0,0,0.18)]">
                      <div className="space-y-4">
                        <div className="border-b border-border/70 px-1 pb-2">
                          <div className="console-eyebrow text-[11px] font-[510] tracking-[0.14em] uppercase text-muted-foreground">
                            {copy.preferences}
                          </div>
                        </div>
                        <div className="space-y-2">
                          <div className="px-1 text-[12px] text-muted-foreground">
                            {copy.commands.actions.theme}
                          </div>
                          <div className="space-y-1">
                            <Button
                              variant="ghost"
                              size="sm"
                              className="flex h-10 w-full items-center justify-between rounded-[10px] px-3"
                              onClick={() => setTheme("dark")}
                            >
                              <span className="flex items-center gap-3">
                                <Moon className="size-4" />
                                {copy.themeDark}
                              </span>
                              {theme === "dark" ? <Check className="size-4 text-primary" /> : null}
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              className="flex h-10 w-full items-center justify-between rounded-[10px] px-3"
                              onClick={() => setTheme("light")}
                            >
                              <span className="flex items-center gap-3">
                                <Sun className="size-4" />
                                {copy.themeLight}
                              </span>
                              {theme === "light" ? <Check className="size-4 text-primary" /> : null}
                            </Button>
                          </div>
                        </div>
                        <div className="space-y-2">
                          <div className="px-1 text-[12px] text-muted-foreground">{copy.language}</div>
                          <div className="space-y-1">
                            {CONSOLE_LOCALES.map((targetLocale) => (
                              <Button
                                key={targetLocale}
                                variant="ghost"
                                size="sm"
                                className="flex h-10 w-full items-center justify-between rounded-[10px] px-3"
                                onClick={() => setLocale(targetLocale)}
                              >
                                <span className="flex items-center gap-3">
                                  <span className="font-medium">
                                    {CONSOLE_LOCALE_META[targetLocale].label}
                                  </span>
                                  <span className="text-[12px] text-muted-foreground">
                                    {CONSOLE_LOCALE_META[targetLocale].nativeLabel}
                                  </span>
                                </span>
                                {locale === targetLocale ? (
                                  <Check className="size-4 text-primary" />
                                ) : null}
                              </Button>
                            ))}
                          </div>
                        </div>
                        <div className="space-y-2">
                          <div className="px-1 text-[12px] text-muted-foreground">{copy.timezone}</div>
                          <div className="space-y-1">
                            <Button
                              variant="ghost"
                              size="sm"
                              className="flex h-10 w-full items-center justify-between rounded-[10px] px-3"
                              onClick={() => setTimezone("local")}
                            >
                              <span className="flex items-center gap-3">
                                <Clock3 className="size-4" />
                                {copy.timezoneLocal}
                              </span>
                              {timezone === "local" ? <Check className="size-4 text-primary" /> : null}
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              className="flex h-10 w-full items-center justify-between rounded-[10px] px-3"
                              onClick={() => setTimezone("utc")}
                            >
                              <span className="flex items-center gap-3">
                                <Globe2 className="size-4" />
                                {copy.timezoneUtc}
                              </span>
                              {timezone === "utc" ? <Check className="size-4 text-primary" /> : null}
                            </Button>
                          </div>
                        </div>
                      </div>
                    </div>
                  ) : null}
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  className="px-2.5"
                  onClick={() => setCommandPaletteOpen(true)}
                  aria-label={copy.commandPalette}
                >
                  <Command className="size-4" />
                  <span className="ml-1 hidden font-mono text-[11px] text-muted-foreground xl:inline">
                    {copy.commandPaletteHint}
                  </span>
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className="px-2.5"
                  onClick={onSignOut}
                  aria-label={copy.signOut}
                >
                  <LogOut className="size-4" />
                </Button>
              </div>
            </div>
            {isRouteTransitioning ? (
              <div className="console-shell-route-progress">
                <div className="console-shell-route-progress-bar" />
              </div>
            ) : null}
          </header>

          <section className="space-y-6 p-4 sm:p-6 lg:p-8">{children}</section>
        </div>
      </div>
    </main>
  )
}

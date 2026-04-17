"use client"

import Image from "next/image"
import { useRouter, useSearchParams } from "next/navigation"
import { Eye, EyeOff, LockKeyhole } from "lucide-react"
import { useEffect, useState, type FormEvent } from "react"

import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { adminApi } from "@/lib/api"
import { getConsoleErrorMessage, useConsole } from "./console-context"
import { CONSOLE_COPY } from "./strings"

function resolveNextPath(nextPath: string | null) {
  if (!nextPath || !nextPath.startsWith("/") || nextPath.startsWith("/login")) {
    return "/overview/"
  }

  return nextPath
}

export function LoginPage() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const {
    hydrated,
    locale,
    connectionReady,
    draftSettings,
    setDraftSettings,
    useCustomApiBaseUrl,
    setUseCustomApiBaseUrl,
    runtimeOrigin,
    saveConnection,
    pushToast,
  } = useConsole()
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [showToken, setShowToken] = useState(false)

  const copy = CONSOLE_COPY[locale]
  const reason = searchParams.get("reason")
  const nextPath = resolveNextPath(searchParams.get("next"))
  const canSubmit =
    draftSettings.adminToken.trim().length > 0 &&
    (!useCustomApiBaseUrl || draftSettings.apiBaseUrl.trim().length > 0)

  useEffect(() => {
    if (hydrated && connectionReady && typeof window !== "undefined") {
      router.replace(nextPath)
    }
  }, [hydrated, connectionReady, nextPath, router])

  const onSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setSubmitting(true)
    setError(null)

    try {
      const nextSettings = {
        ...draftSettings,
        apiBaseUrl: useCustomApiBaseUrl ? draftSettings.apiBaseUrl.trim() : "",
        adminToken: draftSettings.adminToken.trim(),
      }

      await adminApi.getHealth(nextSettings)
      saveConnection()
      pushToast({ tone: "success", message: copy.loginSuccess })
      if (typeof window !== "undefined") {
        router.replace(nextPath)
      }
    } catch (submitError) {
      setError(getConsoleErrorMessage(submitError, locale, copy.errorUnknown))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center px-4 py-10 sm:px-6">
      <Card className="w-full max-w-[480px] shadow-none">
        <CardHeader className="space-y-4">
          <div className="flex items-center gap-3">
            <div className="console-shell-logo-mark flex size-11 items-center justify-center rounded-[14px]">
              <Image
                src="/brand/rscale-mark.svg"
                alt="rscale"
                className="size-11"
                width={44}
                height={44}
                priority
              />
            </div>
            <div>
              <div className="console-eyebrow text-[11px] font-[510] tracking-[0.18em] uppercase">
                rscale
              </div>
              <CardTitle className="text-[20px] font-[510] tracking-[-0.28px] text-foreground">
                {copy.loginTitle}
              </CardTitle>
              <p className="mt-1 text-[12px] text-muted-foreground">{copy.projectTagline}</p>
            </div>
          </div>
          <p className="console-muted text-[13px] tracking-[-0.13px]">
            {copy.loginSubtitle}
          </p>
        </CardHeader>
        <CardContent>
          <form className="space-y-5" onSubmit={onSubmit}>
            {reason === "expired" ? (
              <div className="console-surface-soft rounded-[12px] px-3 py-2 text-[13px] text-secondary-foreground">
                {copy.sessionExpired}
              </div>
            ) : null}
            <div className="space-y-2">
              <div className="flex items-center justify-between gap-3">
                <label className="console-eyebrow text-[12px] font-[510] tracking-[0.14em] uppercase">
                  {copy.api}
                </label>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="h-7 px-2 text-[11px]"
                  onClick={() =>
                    setUseCustomApiBaseUrl((current) => {
                      const next = !current
                      if (!next) {
                        setDraftSettings((value) => ({
                          ...value,
                          apiBaseUrl: "",
                        }))
                      }
                      return next
                    })
                  }
                >
                  {useCustomApiBaseUrl ? copy.backToOrigin : copy.customApi}
                </Button>
              </div>

              {useCustomApiBaseUrl ? (
                <Input
                  value={draftSettings.apiBaseUrl}
                  onChange={(event) =>
                    setDraftSettings((current) => ({
                      ...current,
                      apiBaseUrl: event.target.value,
                    }))
                  }
                  onInput={() => setError(null)}
                  placeholder="https://vpn.example.com"
                />
              ) : (
                <div className="console-surface-soft rounded-[12px] px-3 py-2 font-mono text-[12px] text-secondary-foreground">
                  {runtimeOrigin || copy.sameOrigin}
                </div>
              )}
            </div>

            <div className="space-y-2">
              <label className="console-eyebrow flex items-center gap-2 text-[12px] font-[510] tracking-[0.14em] uppercase">
                <LockKeyhole className="size-3.5" />
                {copy.token}
              </label>
              <div className="relative">
                <Input
                  type={showToken ? "text" : "password"}
                  value={draftSettings.adminToken}
                  onChange={(event) =>
                    setDraftSettings((current) => ({
                      ...current,
                      adminToken: event.target.value,
                    }))
                  }
                  onInput={() => setError(null)}
                  placeholder="break_glass_token"
                  autoFocus
                  className="pr-12"
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="absolute top-1/2 right-1 h-8 -translate-y-1/2 px-2"
                  onClick={() => setShowToken((current) => !current)}
                  aria-label={showToken ? copy.common.hide : copy.common.show}
                >
                  {showToken ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
                </Button>
              </div>
            </div>

            {error ? (
              <div className="console-alert-error rounded-[12px] px-3 py-2 text-[13px]">
                {error}
              </div>
            ) : null}

            <Button type="submit" className="w-full" disabled={submitting || !canSubmit}>
              {submitting ? copy.refreshing : copy.loginSubmit}
            </Button>
          </form>
          <p className="mt-5 text-[12px] leading-5 text-muted-foreground">
            {copy.independenceNotice}
          </p>
        </CardContent>
      </Card>
    </main>
  )
}

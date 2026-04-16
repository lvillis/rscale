"use client"

import { useEffect } from "react"
import { useRouter } from "next/navigation"

import { useConsole } from "@/components/console/console-context"

export default function Home() {
  const router = useRouter()
  const { hydrated, connectionReady } = useConsole()

  useEffect(() => {
    if (!hydrated || typeof window === "undefined") {
      return
    }

    router.replace(connectionReady ? "/overview/" : "/login/")
  }, [connectionReady, hydrated, router])

  return null
}

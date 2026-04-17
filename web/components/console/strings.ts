import {
  Activity,
  Database,
  KeyRound,
  Network,
  Router,
  ShieldCheck,
  type LucideIcon,
} from "lucide-react"

import type { ConsoleLocale } from "@/lib/console-i18n"

import { deConsoleCopy } from "./locales/de"
import { enConsoleCopy } from "./locales/en"
import { zhConsoleCopy, type ConsoleCopy } from "./locales/zh"

export type ConsoleRouteKey =
  | "overview"
  | "monitoring"
  | "nodes"
  | "access"
  | "network"
  | "audit"

export const CONSOLE_NAV_ITEMS: Array<{
  key: ConsoleRouteKey
  href: string
  icon: LucideIcon
}> = [
  { key: "overview", href: "/overview/", icon: Database },
  { key: "monitoring", href: "/monitoring/", icon: Activity },
  { key: "nodes", href: "/nodes/", icon: Router },
  { key: "access", href: "/access/", icon: KeyRound },
  { key: "network", href: "/network/", icon: Network },
  { key: "audit", href: "/audit/", icon: ShieldCheck },
]

export const CONSOLE_COPY: Record<ConsoleLocale, ConsoleCopy> = {
  zh: zhConsoleCopy,
  en: enConsoleCopy,
  de: deConsoleCopy,
}

export type { ConsoleCopy }

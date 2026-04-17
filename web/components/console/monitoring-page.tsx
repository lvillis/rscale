"use client"

import { useQuery } from "@tanstack/react-query"
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  PolarAngleAxis,
  RadialBar,
  RadialBarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts"

import { Badge } from "@/components/ui/badge"
import { adminApi } from "@/lib/api"
import { formatDateTime, formatUptime } from "@/lib/format"
import { getConsoleErrorMessage, useConsole } from "./console-context"
import { Panel, PanelState, StatusPill } from "./primitives"
import { CONSOLE_COPY } from "./strings"

type ChartDatum = {
  label: string
  value: number
  color: string
}

type EventBucket = {
  label: string
  value: number
}

type SignalTone = "healthy" | "warning" | "danger" | "neutral"

const CHART_COLORS = {
  emerald: "#10b981",
  amber: "#f59e0b",
  rose: "#f43f5e",
  sky: "#38bdf8",
  violet: "#8b5cf6",
  slate: "#94a3b8",
  primary: "#4f46e5",
}

const CHART_GRID = "rgba(148, 163, 184, 0.12)"
const CHART_AXIS = "rgba(100, 116, 139, 0.88)"
const TOOLTIP_STYLE = {
  background: "rgba(8, 9, 10, 0.92)",
  border: "1px solid rgba(255,255,255,0.08)",
  borderRadius: "12px",
  boxShadow: "0 18px 44px rgba(0,0,0,0.24)",
}
const TOOLTIP_TEXT_STYLE = {
  color: "#f8fafc",
  fontSize: "12px",
}

function formatRatio(part: number, total: number) {
  if (total <= 0) {
    return "0%"
  }

  return `${Math.round((part / total) * 100)}%`
}

function buildEventBuckets(values: number[], bucketCount = 12): EventBucket[] {
  if (bucketCount <= 0) {
    return []
  }

  if (values.length === 0) {
    return Array.from({ length: bucketCount }, (_, index) => ({
      label: `${index + 1}`,
      value: 0,
    }))
  }

  const sorted = [...values].sort((left, right) => left - right)
  const start = sorted[0]
  const end = Math.max(sorted[sorted.length - 1], start + bucketCount)
  const span = Math.max(end - start, bucketCount)
  const step = span / bucketCount
  const buckets = Array.from({ length: bucketCount }, (_, index) => ({
    label: `${index + 1}`,
    value: 0,
  }))

  for (const value of sorted) {
    const offset = value - start
    const index = Math.min(Math.floor(offset / step), bucketCount - 1)
    buckets[index].value += 1
  }

  return buckets
}

function signalToneClass(tone: SignalTone) {
  switch (tone) {
    case "healthy":
      return "bg-emerald-500"
    case "warning":
      return "bg-amber-500"
    case "danger":
      return "bg-rose-500"
    default:
      return "bg-border"
  }
}

function CompactStat({
  label,
  value,
}: {
  label: string
  value: string
}) {
  return (
    <div className="min-w-0 rounded-[12px] border border-border/70 px-3 py-3">
      <div className="truncate text-[11px] font-[510] tracking-[0.14em] text-muted-foreground uppercase">
        {label}
      </div>
      <div className="mt-2 truncate text-[18px] leading-none font-[540] tracking-[-0.28px] text-foreground">
        {value}
      </div>
    </div>
  )
}

function PieLegend({
  items,
  total,
}: {
  items: ChartDatum[]
  total: number
}) {
  return (
    <div className="space-y-3">
      {items.map((item) => (
        <div key={item.label} className="flex items-center justify-between gap-3">
          <div className="flex min-w-0 items-center gap-2">
            <span
              className="size-2.5 shrink-0 rounded-full"
              style={{ backgroundColor: item.color }}
            />
            <span className="truncate text-[13px] text-foreground">{item.label}</span>
          </div>
          <div className="shrink-0 font-mono text-[12px] text-muted-foreground">
            {item.value}
            <span className="ml-2">{formatRatio(item.value, total)}</span>
          </div>
        </div>
      ))}
    </div>
  )
}

function PieBoard({
  title,
  centerLabel,
  centerValue,
  leftStatLabel,
  leftStatValue,
  rightStatLabel,
  rightStatValue,
  data,
}: {
  title: string
  centerLabel: string
  centerValue: string
  leftStatLabel: string
  leftStatValue: string
  rightStatLabel: string
  rightStatValue: string
  data: ChartDatum[]
}) {
  const total = data.reduce((sum, item) => sum + item.value, 0)

  return (
    <Panel title={title} className="h-full" contentClassName="flex h-full flex-col">
      <div className="grid min-h-[380px] gap-5 xl:grid-cols-[220px_minmax(0,1fr)]">
        <div className="relative h-[260px] xl:h-full">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                dataKey="value"
                nameKey="label"
                innerRadius={68}
                outerRadius={96}
                stroke="none"
                paddingAngle={2}
              >
                {data.map((item) => (
                  <Cell key={item.label} fill={item.color} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={TOOLTIP_STYLE}
                itemStyle={TOOLTIP_TEXT_STYLE}
                labelStyle={TOOLTIP_TEXT_STYLE}
              />
            </PieChart>
          </ResponsiveContainer>
          <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
            <div className="text-center">
              <div className="text-[36px] leading-none font-[560] tracking-[-0.96px] text-foreground">
                {centerValue}
              </div>
              <div className="mt-2 text-[11px] font-[510] tracking-[0.18em] text-muted-foreground uppercase">
                {centerLabel}
              </div>
            </div>
          </div>
        </div>
        <div className="flex min-h-0 flex-col justify-between gap-5">
          <div className="grid gap-3 sm:grid-cols-2">
            <CompactStat label={leftStatLabel} value={leftStatValue} />
            <CompactStat label={rightStatLabel} value={rightStatValue} />
          </div>
          <PieLegend items={data} total={total} />
        </div>
      </div>
    </Panel>
  )
}

function EventVolumeBoard({
  title,
  bucketLabel,
  totalLabel,
  totalValue,
  onlineLabel,
  onlineValue,
  unhealthyLabel,
  unhealthyValue,
  buckets,
  topKinds,
}: {
  title: string
  bucketLabel: string
  totalLabel: string
  totalValue: string
  onlineLabel: string
  onlineValue: string
  unhealthyLabel: string
  unhealthyValue: string
  buckets: EventBucket[]
  topKinds: ChartDatum[]
}) {
  return (
    <Panel
      title={title}
      action={<Badge variant="outline">{bucketLabel}</Badge>}
      className="h-full"
      contentClassName="flex h-full flex-col"
    >
      <div className="flex h-full flex-col gap-5">
        <div className="grid gap-3 md:grid-cols-3">
          <CompactStat label={totalLabel} value={totalValue} />
          <CompactStat label={onlineLabel} value={onlineValue} />
          <CompactStat label={unhealthyLabel} value={unhealthyValue} />
        </div>
        <div className="h-[320px] rounded-[16px] border border-border/70 p-3">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={buckets} margin={{ top: 12, right: 12, bottom: 0, left: -12 }}>
              <defs>
                <linearGradient id="activityFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={CHART_COLORS.sky} stopOpacity={0.72} />
                  <stop offset="100%" stopColor={CHART_COLORS.primary} stopOpacity={0.08} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke={CHART_GRID} vertical={false} />
              <XAxis
                dataKey="label"
                axisLine={false}
                tickLine={false}
                tick={{ fill: CHART_AXIS, fontSize: 11 }}
              />
              <YAxis
                allowDecimals={false}
                axisLine={false}
                tickLine={false}
                tick={{ fill: CHART_AXIS, fontSize: 11 }}
              />
              <Tooltip
                contentStyle={TOOLTIP_STYLE}
                itemStyle={TOOLTIP_TEXT_STYLE}
                labelStyle={TOOLTIP_TEXT_STYLE}
              />
              <Area
                type="monotone"
                dataKey="value"
                stroke={CHART_COLORS.sky}
                strokeWidth={2}
                fill="url(#activityFill)"
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
        {topKinds.length > 0 ? (
          <div className="flex flex-wrap gap-2">
            {topKinds.map((item) => (
              <Badge key={item.label} variant="outline" className="gap-2">
                <span
                  className="size-2 rounded-full"
                  style={{ backgroundColor: item.color }}
                />
                <span>{item.label}</span>
                <span className="font-mono text-[11px] text-muted-foreground">{item.value}</span>
              </Badge>
            ))}
          </div>
        ) : null}
      </div>
    </Panel>
  )
}

function RouteBoard({
  title,
  subtitle,
  exitNodesLabel,
  autoApprovedLabel,
  data,
  totalRoutes,
  exitNodes,
  autoApproved,
}: {
  title: string
  subtitle: string
  exitNodesLabel: string
  autoApprovedLabel: string
  data: ChartDatum[]
  totalRoutes: number
  exitNodes: number
  autoApproved: number
}) {
  return (
    <Panel
      title={title}
      action={<Badge variant="outline">{subtitle}</Badge>}
      className="h-full"
      contentClassName="flex h-full flex-col"
    >
      <div className="flex h-full flex-col gap-5">
        <div className="h-[320px] rounded-[16px] border border-border/70 p-3">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} margin={{ top: 12, right: 12, bottom: 0, left: -16 }}>
              <CartesianGrid stroke={CHART_GRID} vertical={false} />
              <XAxis
                dataKey="label"
                axisLine={false}
                tickLine={false}
                tick={{ fill: CHART_AXIS, fontSize: 12 }}
              />
              <YAxis
                allowDecimals={false}
                axisLine={false}
                tickLine={false}
                tick={{ fill: CHART_AXIS, fontSize: 11 }}
              />
              <Tooltip
                contentStyle={TOOLTIP_STYLE}
                itemStyle={TOOLTIP_TEXT_STYLE}
                labelStyle={TOOLTIP_TEXT_STYLE}
              />
              <Bar dataKey="value" radius={[10, 10, 0, 0]}>
                {data.map((item) => (
                  <Cell key={item.label} fill={item.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
        <div className="grid gap-3 md:grid-cols-3">
          <CompactStat label={subtitle} value={String(totalRoutes)} />
          <CompactStat label={exitNodesLabel} value={String(exitNodes)} />
          <CompactStat label={autoApprovedLabel} value={String(autoApproved)} />
        </div>
      </div>
    </Panel>
  )
}

function DerpBoard({
  title,
  healthy,
  score,
  scoreLabel,
  healthyLabel,
  attentionLabel,
  regionCountLabel,
  failureCountLabel,
  lastSuccessLabel,
  lastAttemptLabel,
  regionCount,
  failureCount,
  lastSuccess,
  lastAttempt,
  regionCodes,
}: {
  title: string
  healthy: boolean
  score: number
  scoreLabel: string
  healthyLabel: string
  attentionLabel: string
  regionCountLabel: string
  failureCountLabel: string
  lastSuccessLabel: string
  lastAttemptLabel: string
  regionCount: number
  failureCount: number
  lastSuccess: string
  lastAttempt: string
  regionCodes: string[]
}) {
  const chartData = [
    {
      name: "score",
      value: score,
      fill: healthy ? CHART_COLORS.emerald : CHART_COLORS.rose,
    },
  ]

  return (
    <Panel
      title={title}
      action={
        <StatusPill
          label={healthy ? healthyLabel : attentionLabel}
          healthy={healthy}
        />
      }
      className="h-full"
      contentClassName="flex h-full flex-col"
    >
      <div className="flex h-full flex-col gap-5">
        <div className="grid min-h-[380px] gap-5 xl:grid-cols-[200px_minmax(0,1fr)]">
          <div className="relative h-[240px] xl:h-full">
            <ResponsiveContainer width="100%" height="100%">
              <RadialBarChart
                data={chartData}
                innerRadius="68%"
                outerRadius="100%"
                startAngle={210}
                endAngle={-30}
                barSize={18}
              >
                <PolarAngleAxis type="number" domain={[0, 100]} tick={false} />
                <RadialBar
                  background={{ fill: "rgba(148, 163, 184, 0.12)" }}
                  cornerRadius={12}
                  dataKey="value"
                />
                <Tooltip
                  contentStyle={TOOLTIP_STYLE}
                  itemStyle={TOOLTIP_TEXT_STYLE}
                  labelStyle={TOOLTIP_TEXT_STYLE}
                />
              </RadialBarChart>
            </ResponsiveContainer>
            <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
              <div className="text-center">
                <div className="text-[34px] leading-none font-[560] tracking-[-0.9px] text-foreground">
                  {score}
                </div>
                <div className="mt-2 text-[11px] font-[510] tracking-[0.18em] text-muted-foreground uppercase">
                  {scoreLabel}
                </div>
              </div>
            </div>
          </div>
          <div className="grid min-h-0 gap-3 sm:grid-cols-2">
            <CompactStat label={regionCountLabel} value={String(regionCount)} />
            <CompactStat label={failureCountLabel} value={String(failureCount)} />
            <div className="rounded-[12px] border border-border/70 px-3 py-3">
              <div className="text-[11px] font-[510] tracking-[0.14em] text-muted-foreground uppercase">
                {lastSuccessLabel}
              </div>
              <div className="mt-2 text-[13px] text-foreground">{lastSuccess}</div>
            </div>
            <div className="rounded-[12px] border border-border/70 px-3 py-3">
              <div className="text-[11px] font-[510] tracking-[0.14em] text-muted-foreground uppercase">
                {lastAttemptLabel}
              </div>
              <div className="mt-2 text-[13px] text-foreground">{lastAttempt}</div>
            </div>
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          {regionCodes.map((regionCode) => (
            <Badge key={regionCode} variant="outline">
              {regionCode}
            </Badge>
          ))}
        </div>
      </div>
    </Panel>
  )
}

function SignalCard({
  label,
  value,
  tone,
}: {
  label: string
  value: string
  tone: SignalTone
}) {
  return (
    <div className="console-surface-soft rounded-[14px] p-4">
      <div className="flex items-center gap-2">
        <span className={`size-2.5 rounded-full ${signalToneClass(tone)}`} />
        <span className="truncate text-[12px] text-muted-foreground">{label}</span>
      </div>
      <div className="mt-3 text-[18px] leading-snug font-[520] tracking-[-0.2px] text-foreground">
        {value}
      </div>
    </div>
  )
}

export function MonitoringPage() {
  const { settings, connectionReady, queryScope, locale, timezone, refreshAll } = useConsole()
  const copy = CONSOLE_COPY[locale]

  const healthQuery = useQuery({
    queryKey: [...queryScope, "health"],
    queryFn: () => adminApi.getHealth(settings),
    refetchInterval: 15_000,
    enabled: connectionReady,
  })
  const configQuery = useQuery({
    queryKey: [...queryScope, "config"],
    queryFn: () => adminApi.getConfig(settings),
    refetchInterval: 30_000,
    enabled: connectionReady,
  })
  const derpQuery = useQuery({
    queryKey: [...queryScope, "derp"],
    queryFn: () => adminApi.getDerp(settings),
    refetchInterval: 20_000,
    enabled: connectionReady,
  })
  const nodesQuery = useQuery({
    queryKey: [...queryScope, "nodes"],
    queryFn: () => adminApi.getNodes(settings),
    refetchInterval: 15_000,
    enabled: connectionReady,
  })
  const authKeysQuery = useQuery({
    queryKey: [...queryScope, "auth-keys"],
    queryFn: () => adminApi.getAuthKeys(settings),
    refetchInterval: 20_000,
    enabled: connectionReady,
  })
  const routesQuery = useQuery({
    queryKey: [...queryScope, "routes"],
    queryFn: () => adminApi.getRoutes(settings),
    refetchInterval: 20_000,
    enabled: connectionReady,
  })
  const auditQuery = useQuery({
    queryKey: [...queryScope, "monitoring-audit-events"],
    queryFn: () => adminApi.getAuditEvents(settings, 40),
    refetchInterval: 20_000,
    enabled: connectionReady,
  })

  const health = healthQuery.data
  const config = configQuery.data
  const derp = derpQuery.data
  const nodes = nodesQuery.data ?? []
  const authKeys = authKeysQuery.data ?? []
  const routes = routesQuery.data ?? []
  const auditEvents = auditQuery.data ?? []

  const dataLoadFailed =
    (!health && Boolean(healthQuery.error)) ||
    (!config && Boolean(configQuery.error)) ||
    (!derp && Boolean(derpQuery.error))

  if (
    healthQuery.isPending &&
    configQuery.isPending &&
    derpQuery.isPending &&
    nodesQuery.isPending &&
    authKeysQuery.isPending &&
    routesQuery.isPending &&
    auditQuery.isPending
  ) {
    return <PanelState mode="loading" message={copy.common.loading} />
  }

  if (dataLoadFailed) {
    return (
        <PanelState
          mode="error"
          message={getConsoleErrorMessage(
            healthQuery.error ?? configQuery.error ?? derpQuery.error,
            locale,
            copy.common.loadFailed
          )}
          actionLabel={copy.common.retry}
        onAction={refreshAll}
      />
    )
  }

  const totalNodes = nodes.length
  const onlineNodes = nodes.filter((node) => node.status === "online").length
  const totalKeys = authKeys.length
  const activeKeys = authKeys.filter((authKey) => authKey.state === "active").length
  const routeExitNodes = routes.filter((route) => route.is_exit_node).length
  const autoApprovedRoutes = routes.filter((route) => route.approved_by_policy).length

  const nodeData: ChartDatum[] = [
    {
      label: copy.status.node.online,
      value: nodes.filter((node) => node.status === "online").length,
      color: CHART_COLORS.emerald,
    },
    {
      label: copy.status.node.offline,
      value: nodes.filter((node) => node.status === "offline").length,
      color: CHART_COLORS.amber,
    },
    {
      label: copy.status.node.pending,
      value: nodes.filter((node) => node.status === "pending").length,
      color: CHART_COLORS.sky,
    },
    {
      label: copy.status.node.expired,
      value: nodes.filter((node) => node.status === "expired").length,
      color: CHART_COLORS.rose,
    },
    {
      label: copy.status.node.disabled,
      value: nodes.filter((node) => node.status === "disabled").length,
      color: CHART_COLORS.slate,
    },
  ]

  const authKeyData: ChartDatum[] = [
    {
      label: copy.status.authKey.active,
      value: authKeys.filter((authKey) => authKey.state === "active").length,
      color: CHART_COLORS.emerald,
    },
    {
      label: copy.status.authKey.revoked,
      value: authKeys.filter((authKey) => authKey.state === "revoked").length,
      color: CHART_COLORS.amber,
    },
    {
      label: copy.status.authKey.expired,
      value: authKeys.filter((authKey) => authKey.state === "expired").length,
      color: CHART_COLORS.rose,
    },
  ]

  const routeData: ChartDatum[] = [
    {
      label: copy.status.routeApproval.pending,
      value: routes.filter((route) => route.approval === "pending").length,
      color: CHART_COLORS.amber,
    },
    {
      label: copy.status.routeApproval.approved,
      value: routes.filter((route) => route.approval === "approved").length,
      color: CHART_COLORS.emerald,
    },
    {
      label: copy.status.routeApproval.rejected,
      value: routes.filter((route) => route.approval === "rejected").length,
      color: CHART_COLORS.rose,
    },
  ]

  const eventBuckets = buildEventBuckets(auditEvents.map((event) => event.occurred_at_unix_secs))
  const topKinds = Object.entries(
    auditEvents.reduce<Record<string, number>>((accumulator, event) => {
      accumulator[event.kind] = (accumulator[event.kind] ?? 0) + 1
      return accumulator
    }, {})
  )
    .sort((left, right) => right[1] - left[1])
    .slice(0, 3)
    .map(([kind, value], index) => ({
      label: copy.audit.kindNames[kind as keyof typeof copy.audit.kindNames],
      value,
      color:
        [CHART_COLORS.sky, CHART_COLORS.violet, CHART_COLORS.emerald][index] ??
        CHART_COLORS.sky,
    }))

  const derpHealthy = Boolean(derp && !derp.last_refresh_error)
  const derpScore = Math.max(
    0,
    Math.min(100, (derpHealthy ? 100 : 62) - (derp?.refresh_failures_total ?? 0) * 4)
  )

  const signalCards = [
    {
      label: copy.monitoring.labels.database,
      value: health
        ? health.database_ready
          ? copy.common.ok
          : copy.overview.status.attention
        : "—",
      tone: health ? (health.database_ready ? "healthy" : "danger") : "neutral",
    },
    {
      label: copy.monitoring.labels.adminAuth,
      value: health
        ? health.admin_auth_configured
          ? copy.common.configured
          : copy.common.unconfigured
        : "—",
      tone: health ? (health.admin_auth_configured ? "healthy" : "warning") : "neutral",
    },
    {
      label: copy.monitoring.labels.oidc,
      value: health
        ? health.oidc_enabled
          ? copy.common.enabled
          : copy.common.disabled
        : "—",
      tone: health ? (health.oidc_enabled ? "healthy" : "neutral") : "neutral",
    },
    {
      label: copy.monitoring.labels.webRoot,
      value: config
        ? config.summary.web_root_configured
          ? copy.common.configured
          : copy.common.unconfigured
        : "—",
      tone: config ? (config.summary.web_root_configured ? "healthy" : "warning") : "neutral",
    },
    {
      label: copy.monitoring.labels.logTimezone,
      value: health?.log_timezone ?? config?.summary.log_timezone ?? "—",
      tone: "neutral",
    },
    {
      label: copy.overview.metrics.uptime,
      value: health ? formatUptime(health.uptime_seconds, locale) : "—",
      tone: "neutral",
    },
  ] as const

  return (
    <div className="space-y-6">
      <div className="grid auto-rows-fr gap-6 2xl:grid-cols-[1.5fr_0.95fr_0.95fr]">
        <EventVolumeBoard
          title={copy.monitoring.sections.eventVolume}
          bucketLabel={copy.monitoring.labels.buckets}
          totalLabel={copy.audit.title}
          totalValue={String(auditEvents.length)}
          onlineLabel={copy.monitoring.metrics.healthyNodes}
          onlineValue={String(onlineNodes)}
          unhealthyLabel={copy.monitoring.metrics.unhealthyNodes}
          unhealthyValue={String(Math.max(totalNodes - onlineNodes, 0))}
          buckets={eventBuckets}
          topKinds={topKinds}
        />
        <PieBoard
          title={copy.monitoring.sections.nodeHealth}
          centerLabel={copy.monitoring.labels.onlineRate}
          centerValue={formatRatio(onlineNodes, totalNodes)}
          leftStatLabel={copy.monitoring.labels.totalNodes}
          leftStatValue={String(totalNodes)}
          rightStatLabel={copy.monitoring.metrics.healthyNodes}
          rightStatValue={String(onlineNodes)}
          data={nodeData}
        />
        <PieBoard
          title={copy.monitoring.sections.authKeys}
          centerLabel={copy.monitoring.labels.activeRate}
          centerValue={formatRatio(activeKeys, totalKeys)}
          leftStatLabel={copy.monitoring.labels.totalKeys}
          leftStatValue={String(totalKeys)}
          rightStatLabel={copy.monitoring.metrics.activeKeys}
          rightStatValue={String(activeKeys)}
          data={authKeyData}
        />
      </div>

      <div className="grid auto-rows-fr gap-6 2xl:grid-cols-[1.1fr_0.95fr_0.95fr]">
        <RouteBoard
          title={copy.monitoring.sections.routes}
          subtitle={copy.monitoring.labels.totalRoutes}
          exitNodesLabel={copy.monitoring.labels.exitNodes}
          autoApprovedLabel={copy.monitoring.labels.approvedByPolicy}
          data={routeData}
          totalRoutes={routes.length}
          exitNodes={routeExitNodes}
          autoApproved={autoApprovedRoutes}
        />
        <DerpBoard
          title={copy.monitoring.sections.derp}
          healthy={derpHealthy}
          score={derpScore}
          scoreLabel={copy.monitoring.labels.score}
          healthyLabel={copy.overview.status.healthy}
          attentionLabel={copy.overview.status.attention}
          regionCountLabel={copy.monitoring.metrics.derpRegions}
          failureCountLabel={copy.monitoring.metrics.refreshFailures}
          lastSuccessLabel={copy.monitoring.labels.lastSuccess}
          lastAttemptLabel={copy.monitoring.labels.lastAttempt}
          regionCount={derp?.effective_region_count ?? 0}
          failureCount={derp?.refresh_failures_total ?? 0}
          lastSuccess={
            derp?.last_refresh_success_unix_secs
              ? formatDateTime(derp.last_refresh_success_unix_secs, locale, timezone)
              : copy.common.never
          }
          lastAttempt={
            derp?.last_refresh_attempt_unix_secs
              ? formatDateTime(derp.last_refresh_attempt_unix_secs, locale, timezone)
              : copy.common.never
          }
          regionCodes={Object.values(derp?.effective_map.Regions ?? {})
            .slice(0, 12)
            .map((region) => region.RegionCode)}
        />
        <Panel title={copy.monitoring.sections.signals} className="h-full" contentClassName="flex h-full flex-col">
          <div className="grid gap-3 sm:grid-cols-2">
            {signalCards.map((signal) => (
              <SignalCard
                key={signal.label}
                label={signal.label}
                value={signal.value}
                tone={signal.tone}
              />
            ))}
          </div>
        </Panel>
      </div>
    </div>
  )
}

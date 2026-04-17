"use client"

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  Activity,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Copy,
  Database,
  Eye,
  EyeOff,
  Globe2,
  KeyRound,
  Network,
  PencilLine,
  Save,
  ShieldCheck,
  X,
} from "lucide-react"
import { useMemo, useState, type FormEvent } from "react"

import { AuthKeyTable } from "@/components/auth-key-table"
import { NodeTable } from "@/components/node-table"
import { RouteTable } from "@/components/route-table"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { adminApi } from "@/lib/api"
import { formatDateTime, formatUptime, joinTags, truncateMiddle } from "@/lib/format"
import type {
  AuditEventKind,
  AuthKey,
  CreateAuthKeyInput,
  IssuedAuthKey,
  Node,
  Route,
  UpdateNodeInput,
} from "@/lib/types"
import { CONSOLE_COPY } from "./strings"
import { useConsole, getConsoleErrorMessage } from "./console-context"
import { usePersistentUiState } from "./use-persistent-ui-state"
import { useUrlQueryState } from "./use-url-query-state"
import {
  DetailSheet,
  InlineAlert,
  KeyValueGrid,
  MetricTile,
  Panel,
  PanelRefreshAction,
  PanelState,
  SearchField,
  StatusPill,
} from "./primitives"
import { focusCollectionItem } from "./interaction"

function splitTags(raw: string) {
  return raw
    .split(/[\n,]/)
    .map((value) => value.trim())
    .filter(Boolean)
}

type AuthKeyExpiryPreset = "24h" | "7d" | "30d" | "never" | "custom"

type AuthKeyDraft = {
  description: string
  tags: string
  reusable: boolean
  ephemeral: boolean
  expiresPreset: AuthKeyExpiryPreset
  customExpiresAt: string
}

type AuthKeyDraftErrors = Partial<Record<"description" | "tags" | "expiresAt", string>>

const DEFAULT_AUTH_KEY_DRAFT: AuthKeyDraft = {
  description: "",
  tags: "",
  reusable: false,
  ephemeral: false,
  expiresPreset: "30d",
  customExpiresAt: "",
}

const AUTH_KEY_EXPIRY_PRESETS: Array<{
  value: AuthKeyExpiryPreset
  seconds?: number
}> = [
  { value: "24h", seconds: 24 * 60 * 60 },
  { value: "7d", seconds: 7 * 24 * 60 * 60 },
  { value: "30d", seconds: 30 * 24 * 60 * 60 },
  { value: "never" },
  { value: "custom" },
]

function toDateTimeLocalValue(unixSeconds: number) {
  const date = new Date(unixSeconds * 1000)
  const pad = (value: number) => String(value).padStart(2, "0")

  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(
    date.getHours()
  )}:${pad(date.getMinutes())}`
}

function parseCustomExpiry(value: string) {
  if (!value.trim()) {
    return null
  }

  const timestamp = new Date(value).getTime()
  if (Number.isNaN(timestamp)) {
    return null
  }

  return Math.floor(timestamp / 1000)
}

function resolveDraftExpiryUnixSecs(draft: AuthKeyDraft) {
  const preset = AUTH_KEY_EXPIRY_PRESETS.find((candidate) => candidate.value === draft.expiresPreset)
  if (!preset) {
    return undefined
  }

  if (preset.value === "never") {
    return undefined
  }

  if (preset.value === "custom") {
    const customExpiry = parseCustomExpiry(draft.customExpiresAt)
    return customExpiry ?? null
  }

  return Math.floor(Date.now() / 1000) + (preset.seconds ?? 0)
}

function validateAuthKeyDraft(
  draft: AuthKeyDraft,
  tags: string[],
  messages: {
    descriptionBlank: string
    tagPrefix: string
    tagEmpty: string
    tagWhitespace: string
    expiryRequired: string
    expiryInvalid: string
    expiryPast: string
  }
): AuthKeyDraftErrors {
  const errors: AuthKeyDraftErrors = {}

  if (draft.description.length > 0 && draft.description.trim().length === 0) {
    errors.description = messages.descriptionBlank
  }

  for (const tag of tags) {
    if (!tag.startsWith("tag:")) {
      errors.tags = messages.tagPrefix
      break
    }

    const tagName = tag.slice(4).trim()
    if (!tagName) {
      errors.tags = messages.tagEmpty
      break
    }

    if (/\s/.test(tagName)) {
      errors.tags = messages.tagWhitespace
      break
    }
  }

  if (draft.expiresPreset === "custom") {
    if (!draft.customExpiresAt.trim()) {
      errors.expiresAt = messages.expiryRequired
    } else {
      const customExpiry = parseCustomExpiry(draft.customExpiresAt)
      if (customExpiry === null) {
        errors.expiresAt = messages.expiryInvalid
      } else if (customExpiry <= Math.floor(Date.now() / 1000)) {
        errors.expiresAt = messages.expiryPast
      }
    }
  }

  return errors
}

type FeedbackState = {
  tone: "success" | "info"
  message: string
}

const AUDIT_PAGE_SIZE_OPTIONS = [10, 25, 50]
const AUDIT_KIND_OPTIONS: AuditEventKind[] = [
  "node_registered",
  "node_updated",
  "node_disabled",
  "node_deleted",
  "auth_key_created",
  "auth_key_revoked",
  "policy_updated",
  "dns_updated",
  "route_created",
  "route_approved",
  "route_rejected",
  "admin_authenticated",
  "backup_restored",
  "ssh_check_approved",
  "ssh_check_rejected",
]

async function performBulkAction<T>(
  items: T[],
  action: (item: T) => Promise<unknown>
) {
  const results = await Promise.allSettled(items.map((item) => action(item)))
  const success = results.filter((result) => result.status === "fulfilled").length
  return {
    success,
    failed: results.length - success,
  }
}

async function copyCurrentLocation(
  successMessage: string,
  errorMessage: string,
  pushToast: (input: {
  message: string
  tone?: "success" | "info" | "error"
}) => void
) {
  if (typeof window === "undefined" || typeof navigator === "undefined") {
    return
  }

  try {
    await navigator.clipboard.writeText(window.location.href)
    pushToast({ tone: "success", message: successMessage })
  } catch {
    pushToast({ tone: "error", message: errorMessage })
  }
}

export function OverviewPage() {
  const {
    settings,
    connectionReady,
    queryScope,
    locale,
    timezone,
    refreshAll,
    isRefreshing,
  } = useConsole()
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
  const routesQuery = useQuery({
    queryKey: [...queryScope, "routes"],
    queryFn: () => adminApi.getRoutes(settings),
    refetchInterval: 20_000,
    enabled: connectionReady,
  })
  const auditQuery = useQuery({
    queryKey: [...queryScope, "overview-audit-events"],
    queryFn: () => adminApi.getAuditEvents(settings, 5),
    refetchInterval: 20_000,
    enabled: connectionReady,
  })

  const health = healthQuery.data
  const config = configQuery.data
  const derp = derpQuery.data
  const nodes = nodesQuery.data ?? []
  const routes = routesQuery.data ?? []
  const recentAuditEvents = auditQuery.data ?? []
  const derpRegions = derp?.effective_region_count ?? 0
  const onlineNodes = nodes.filter((node) => node.status === "online").length
  const pendingRoutes = routes.filter((route) => route.approval === "pending").length
  const warningCount =
    Number(Boolean(health?.config_has_warnings)) +
    Number(Boolean(derp?.last_refresh_error)) +
    Number(health ? !health.database_ready : false) +
    Number(health ? !health.admin_auth_configured : false)
  const hasOverviewLoadFailure =
    (!health && Boolean(healthQuery.error)) ||
    (!config && Boolean(configQuery.error)) ||
    (!derp && Boolean(derpQuery.error))

  const hasBlockingIssue = Boolean(
    health && (!health.database_ready || Boolean(derp?.last_refresh_error))
  )
  const hasWarningState = Boolean(
    health &&
      !hasBlockingIssue &&
      (health.config_has_warnings || !health.admin_auth_configured)
  )

  const overviewStatus = hasOverviewLoadFailure
    ? "attention"
    : !health || !config || !derp
      ? "waiting"
      : hasBlockingIssue
        ? "attention"
        : hasWarningState
          ? "degraded"
          : "healthy"

  const overviewStatusLabel = copy.overview.status[overviewStatus]

  const summaryItems = [
    {
      label: copy.overview.summary.controlPlane,
      value: health ? `${health.service} ${health.version}` : "—",
    },
    {
      label: copy.overview.summary.database,
      value: health
        ? health.database_ready
          ? copy.common.ok
          : copy.overview.status.attention
        : "—",
    },
    {
      label: copy.overview.summary.adminAuth,
      value: health
        ? health.admin_auth_configured
          ? copy.common.configured
          : copy.common.unconfigured
        : "—",
    },
    {
      label: copy.overview.summary.oidc,
      value: health
        ? health.oidc_enabled
          ? copy.common.enabled
          : copy.common.disabled
        : "—",
    },
    {
      label: copy.overview.summary.webRoot,
      value: config
        ? config.summary.web_root_configured
          ? copy.common.configured
          : copy.common.unconfigured
        : "—",
    },
    {
      label: copy.overview.summary.derpRefresh,
      value: derp
        ? derp.last_refresh_error
          ? copy.overview.status.attention
          : copy.common.ok
        : "—",
    },
  ]

  return (
    <div className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
        <MetricTile
          label={copy.overview.metrics.online}
          value={nodesQuery.isPending && nodes.length === 0 ? "…" : String(onlineNodes)}
          icon={Activity}
        />
        <MetricTile
          label={copy.overview.metrics.pendingRoutes}
          value={routesQuery.isPending && routes.length === 0 ? "…" : String(pendingRoutes)}
          icon={Network}
        />
        <MetricTile
          label={copy.overview.metrics.derpFailures}
          value={derp ? String(derp.refresh_failures_total) : derpQuery.isPending ? "…" : "—"}
          icon={Globe2}
        />
        <MetricTile
          label={copy.overview.metrics.warnings}
          value={health || derp ? String(warningCount) : healthQuery.isPending ? "…" : "—"}
          icon={Database}
        />
        <MetricTile
          label={copy.overview.metrics.uptime}
          value={
            health ? formatUptime(health.uptime_seconds, locale) : healthQuery.isPending ? "…" : "—"
          }
          icon={ShieldCheck}
        />
      </div>

      <div className="grid gap-6 xl:grid-cols-[1.05fr_0.95fr]">
        <Panel
          title={copy.overview.sections.summaryTitle}
          action={
            <div className="flex items-center gap-3">
              <StatusPill
                label={overviewStatusLabel}
                healthy={overviewStatus === "healthy"}
              />
              <PanelRefreshAction
                label={copy.refresh}
                refreshingLabel={copy.refreshing}
                refreshing={isRefreshing}
                onRefresh={refreshAll}
              />
            </div>
          }
        >
          {healthQuery.isPending && !health && configQuery.isPending && !config && derpQuery.isPending && !derp ? (
            <PanelState mode="loading" message={copy.common.loading} />
          ) : hasOverviewLoadFailure ? (
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
          ) : (
            <div className="space-y-3">
              {summaryItems.map((item) => (
                <div
                  key={item.label}
                  className="flex items-center justify-between gap-4 rounded-[12px] border border-border/70 px-4 py-3"
                >
                  <div className="text-[13px] font-[510] text-foreground">{item.label}</div>
                  <div className="text-right text-[13px] text-muted-foreground">{item.value}</div>
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel title={copy.overview.sections.activityTitle}>
          {auditQuery.isPending && recentAuditEvents.length === 0 ? (
            <PanelState mode="loading" message={copy.common.loading} />
          ) : auditQuery.error && recentAuditEvents.length === 0 ? (
            <PanelState
              mode="error"
              message={getConsoleErrorMessage(auditQuery.error, locale, copy.common.loadFailed)}
              actionLabel={copy.common.retry}
              onAction={() => void auditQuery.refetch()}
            />
          ) : recentAuditEvents.length === 0 ? (
            <PanelState mode="empty" message={copy.overview.activity.empty} />
          ) : (
            <div className="space-y-3">
              {recentAuditEvents.map((event) => (
                <div
                  key={event.id}
                  className="rounded-[12px] border border-border/70 px-4 py-3"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0 space-y-1">
                      <div className="text-[13px] font-[510] text-foreground">
                        {copy.audit.kindNames[event.kind]}
                      </div>
                      <div className="text-[12px] text-muted-foreground">
                        {event.actor.subject}
                        {copy.audit.actorSeparator}
                        {event.target}
                      </div>
                    </div>
                    <div className="shrink-0 whitespace-nowrap pl-3 text-right text-[12px] text-muted-foreground">
                      {formatDateTime(event.occurred_at_unix_secs, locale, timezone)}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>

      <Panel title={copy.overview.sections.diagnosticsTitle}>
          {configQuery.isPending && !config ? (
            <PanelState mode="loading" message={copy.common.loading} />
          ) : configQuery.error && !config ? (
            <PanelState
              mode="error"
              message={getConsoleErrorMessage(configQuery.error, locale, copy.common.loadFailed)}
              actionLabel={copy.common.retry}
              onAction={() => void configQuery.refetch()}
            />
          ) : config && health && derp ? (
            <div className="space-y-4">
              <KeyValueGrid
                items={[
                  { label: copy.overview.summary.bind, value: health.bind_addr },
                  { label: copy.overview.summary.logFormat, value: health.log_format },
                  { label: copy.overview.summary.logTimezone, value: health.log_timezone },
                  { label: copy.overview.summary.tailnetIpv4, value: config.summary.tailnet_ipv4_range },
                  { label: copy.overview.summary.tailnetIpv6, value: config.summary.tailnet_ipv6_range },
                  {
                    label: copy.overview.summary.stun,
                    value: config.summary.derp_stun_bind_addr || copy.common.unconfigured,
                  },
                  {
                    label: copy.overview.summary.refreshInterval,
                    value: `${config.summary.derp_refresh_interval_secs}${copy.common.seconds}`,
                  },
                  { label: copy.overview.summary.regions, value: String(derpRegions) },
                  { label: copy.overview.summary.sources, value: String(derp.source_count) },
                ]}
              />
              <details className="group rounded-[12px] border border-border/70 px-4 py-3">
                <summary className="cursor-pointer list-none text-[13px] font-[510] text-foreground">
                  {copy.overview.sections.doctorToggle}
                </summary>
                <Textarea
                  readOnly
                  value={JSON.stringify(config.doctor ?? {}, null, 2)}
                  className="mt-3 min-h-[240px] border-border bg-[var(--surface-soft)] font-mono text-[12px]"
                />
              </details>
            </div>
          ) : null}
      </Panel>
    </div>
  )
}

export function NodesPage() {
  const {
    settings,
    connectionReady,
    queryScope,
    locale,
    timezone,
    confirmAction,
    pushToast,
  } = useConsole()
  const copy = CONSOLE_COPY[locale]
  const queryClient = useQueryClient()
  const [feedback, setFeedback] = useState<FeedbackState | null>(null)
  const [selectionVersion, setSelectionVersion] = useState(0)
  const [selectedNodeId, setSelectedNodeId] = useUrlQueryState("nodes-detail")
  const [editingNodeId, setEditingNodeId] = useState<string | null>(null)
  const [nodeDraft, setNodeDraft] = useState({
    name: "",
    hostname: "",
    tags: "",
  })

  const nodesQuery = useQuery({
    queryKey: [...queryScope, "nodes"],
    queryFn: () => adminApi.getNodes(settings),
    refetchInterval: 12_000,
    enabled: connectionReady,
  })

  const disableNodeMutation = useMutation({
    mutationFn: (node: NonNullable<typeof nodesQuery.data>[number]) =>
      adminApi.disableNode(settings, node.id),
    onSuccess: async (_result, node) => {
      setFeedback({ tone: "success", message: copy.nodes.disableSuccess(node.name) })
      window.setTimeout(() => setFeedback(null), 2400)
      setSelectionVersion((current) => current + 1)
      await queryClient.invalidateQueries({ queryKey: [...queryScope, "nodes"] })
    },
  })

  const bulkDisableMutation = useMutation({
    mutationFn: (selectedNodes: Node[]) =>
      performBulkAction(selectedNodes, (node) => adminApi.disableNode(settings, node.id)),
    onSuccess: async ({ success, failed }) => {
      setFeedback({
        tone: failed > 0 ? "info" : "success",
        message: copy.nodes.bulkDisableSuccess(success, failed),
      })
      window.setTimeout(() => setFeedback(null), 2800)
      setSelectionVersion((current) => current + 1)
      await queryClient.invalidateQueries({ queryKey: [...queryScope, "nodes"] })
    },
  })

  const updateNodeMutation = useMutation({
    mutationFn: async ({
      node,
      input,
    }: {
      node: Node
      input: UpdateNodeInput
    }) => adminApi.updateNode(settings, node.id, input),
    onSuccess: async (updatedNode) => {
      setFeedback({
        tone: "success",
        message: copy.nodes.editSuccess(updatedNode.name),
      })
      window.setTimeout(() => setFeedback(null), 2400)
      setEditingNodeId(null)
      await queryClient.invalidateQueries({ queryKey: [...queryScope, "nodes"] })
    },
  })

  const nodes = nodesQuery.data ?? []

  const selectedNodeDetail = selectedNodeId
    ? nodes.find((node) => String(node.id) === selectedNodeId) ?? null
    : null
  const selectedNodeIndex = selectedNodeDetail
    ? nodes.findIndex((node) => node.id === selectedNodeDetail.id)
    : -1
  const isEditingNode =
    selectedNodeDetail !== null && editingNodeId === String(selectedNodeDetail.id)

  const beginNodeEdit = (node: Node) => {
    setNodeDraft({
      name: node.name,
      hostname: node.hostname,
      tags: node.tags.join(", "),
    })
    setEditingNodeId(String(node.id))
  }

  const stopNodeEdit = (node?: Node | null) => {
    setEditingNodeId(null)
    if (!node) {
      setNodeDraft({ name: "", hostname: "", tags: "" })
      return
    }

    setNodeDraft({
      name: node.name,
      hostname: node.hostname,
      tags: node.tags.join(", "),
    })
  }

  const handleDisable = async (node: NonNullable<typeof nodesQuery.data>[number]) => {
    const confirmed = await confirmAction({
      message: copy.nodes.disableConfirm(node.name),
      confirmLabel: copy.nodes.disable,
      tone: "danger",
    })
    if (!confirmed) {
      return
    }

    disableNodeMutation.mutate(node)
  }

  const handleBulkDisable = async (selectedNodes: Node[]) => {
    const confirmed = await confirmAction({
      message: copy.nodes.bulkDisableConfirm(selectedNodes.length),
      confirmLabel: copy.nodes.bulkDisable,
      tone: "danger",
    })
    if (!confirmed) {
      return
    }

    bulkDisableMutation.mutate(selectedNodes)
  }

  const handleSaveNode = async () => {
    if (!selectedNodeDetail) {
      return
    }

    const nextName = nodeDraft.name.trim()
    const nextHostname = nodeDraft.hostname.trim()
    const nextTags = splitTags(nodeDraft.tags)
    const input: UpdateNodeInput = {}

    if (nextName !== selectedNodeDetail.name) {
      input.name = nextName
    }

    if (nextHostname !== selectedNodeDetail.hostname) {
      input.hostname = nextHostname
    }

    if (nextTags.join(",") !== selectedNodeDetail.tags.join(",")) {
      input.tags = nextTags
    }

    if (Object.keys(input).length === 0) {
      stopNodeEdit(selectedNodeDetail)
      return
    }

    try {
      await updateNodeMutation.mutateAsync({
        node: selectedNodeDetail,
        input,
      })
    } catch {
      // mutation state already drives the inline error surface
    }
  }

  const canSaveNode =
    nodeDraft.name.trim().length > 0 && nodeDraft.hostname.trim().length > 0

  const selectNodeDetail = (nodeId: string) => {
    setEditingNodeId(null)
    setSelectedNodeId(nodeId)
  }

  return (
    <Panel>
      {nodesQuery.isPending && nodes.length === 0 ? (
        <PanelState mode="loading" message={copy.common.loading} />
      ) : nodesQuery.error && nodes.length === 0 ? (
        <PanelState
          mode="error"
          message={getConsoleErrorMessage(nodesQuery.error, locale, copy.common.loadFailed)}
          actionLabel={copy.common.retry}
          onAction={() => void nodesQuery.refetch()}
        />
      ) : (
        <div className="space-y-4">
          {feedback ? (
            <InlineAlert
              tone={feedback.tone}
              action={
                <Button variant="ghost" size="sm" onClick={() => setFeedback(null)}>
                  {copy.common.dismiss}
                </Button>
              }
            >
              {feedback.message}
            </InlineAlert>
          ) : null}
          {nodesQuery.error && nodes.length > 0 ? (
            <InlineAlert
              action={
                <Button variant="outline" size="sm" onClick={() => void nodesQuery.refetch()}>
                  {copy.common.retry}
                </Button>
              }
              >
              {getConsoleErrorMessage(nodesQuery.error, locale, copy.common.loadFailed)}
            </InlineAlert>
          ) : null}
          {disableNodeMutation.error ? (
            <InlineAlert>
              {getConsoleErrorMessage(disableNodeMutation.error, locale, copy.common.loadFailed)}
            </InlineAlert>
          ) : null}
          {bulkDisableMutation.error ? (
            <InlineAlert>
              {getConsoleErrorMessage(bulkDisableMutation.error, locale, copy.common.loadFailed)}
            </InlineAlert>
          ) : null}
          {updateNodeMutation.error ? (
            <InlineAlert>
              {getConsoleErrorMessage(updateNodeMutation.error, locale, copy.common.loadFailed)}
            </InlineAlert>
          ) : null}
          <NodeTable
            nodes={nodes}
            pendingNodeId={
              disableNodeMutation.isPending
                ? disableNodeMutation.variables?.id ?? null
                : null
            }
            onDisable={handleDisable}
            onBulkDisable={handleBulkDisable}
            onView={(node) => selectNodeDetail(String(node.id))}
            activeNodeId={selectedNodeDetail?.id ?? null}
            bulkDisabled={bulkDisableMutation.isPending}
            resetSelectionKey={selectionVersion}
          />
          <DetailSheet
            open={Boolean(selectedNodeDetail)}
            title={copy.nodes.detailsTitle}
            subtitle={selectedNodeDetail?.name}
            canPrevious={selectedNodeIndex > 0}
            canNext={selectedNodeIndex >= 0 && selectedNodeIndex < nodes.length - 1}
            onPrevious={() => selectNodeDetail(String(nodes[selectedNodeIndex - 1]?.id ?? ""))}
            onNext={() => selectNodeDetail(String(nodes[selectedNodeIndex + 1]?.id ?? ""))}
            headerActions={
              selectedNodeDetail ? (
                <>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={selectedNodeIndex <= 0}
                    onClick={() =>
                      selectNodeDetail(String(nodes[selectedNodeIndex - 1]?.id ?? ""))
                    }
                  >
                    <ChevronLeft className="size-4" />
                    {copy.common.previous}
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={selectedNodeIndex < 0 || selectedNodeIndex >= nodes.length - 1}
                    onClick={() =>
                      selectNodeDetail(String(nodes[selectedNodeIndex + 1]?.id ?? ""))
                    }
                  >
                    {copy.common.next}
                    <ChevronRight className="size-4" />
                  </Button>
                </>
              ) : null
            }
            onClose={() => {
              stopNodeEdit(null)
              setSelectedNodeId("")
            }}
          >
            {selectedNodeDetail ? (
              <div className="space-y-4">
                {isEditingNode ? (
                  <div className="space-y-4">
                    <div className="console-eyebrow text-[12px] font-[510] tracking-[0.14em] uppercase">
                      {copy.nodes.editTitle}
                    </div>
                    <div className="grid gap-4">
                      <div className="space-y-2">
                        <label className="console-eyebrow text-[12px] font-[510] tracking-[0.14em] uppercase">
                          {copy.nodes.form.name}
                        </label>
                        <Input
                          value={nodeDraft.name}
                          onChange={(event) =>
                            setNodeDraft((current) => ({
                              ...current,
                              name: event.target.value,
                            }))
                          }
                        />
                      </div>
                      <div className="space-y-2">
                        <label className="console-eyebrow text-[12px] font-[510] tracking-[0.14em] uppercase">
                          {copy.nodes.form.hostname}
                        </label>
                        <Input
                          value={nodeDraft.hostname}
                          onChange={(event) =>
                            setNodeDraft((current) => ({
                              ...current,
                              hostname: event.target.value,
                            }))
                          }
                        />
                      </div>
                      <div className="space-y-2">
                        <label className="console-eyebrow text-[12px] font-[510] tracking-[0.14em] uppercase">
                          {copy.nodes.form.tags}
                        </label>
                        <Textarea
                          value={nodeDraft.tags}
                          onChange={(event) =>
                            setNodeDraft((current) => ({
                              ...current,
                              tags: event.target.value,
                            }))
                          }
                          placeholder={copy.nodes.form.tagsPlaceholder}
                          className="min-h-[104px]"
                        />
                      </div>
                    </div>
                  </div>
                ) : (
                  <KeyValueGrid
                    items={[
                      { label: copy.common.hostname, value: selectedNodeDetail.hostname },
                      { label: copy.common.stableId, value: selectedNodeDetail.stable_id },
                      {
                        label: copy.nodes.columns.status,
                        value: copy.status.node[selectedNodeDetail.status],
                      },
                      {
                        label: copy.nodes.columns.tags,
                        value: joinTags(selectedNodeDetail.tags, copy.common.notSet),
                      },
                      { label: copy.common.ipv4, value: selectedNodeDetail.ipv4 ?? copy.common.noIpv4 },
                      { label: copy.common.ipv6, value: selectedNodeDetail.ipv6 ?? copy.common.noIpv6 },
                      {
                        label: copy.common.lastSeen,
                        value: formatDateTime(
                          selectedNodeDetail.last_seen_unix_secs,
                          locale,
                          timezone
                        ),
                      },
                      {
                        label: copy.common.identifier,
                        value: selectedNodeDetail.auth_key_id ?? copy.common.notSet,
                      },
                    ]}
                  />
                )}
                <div className="flex justify-end gap-2">
                  <Button
                    variant="outline"
                    onClick={() =>
                      void copyCurrentLocation(
                        copy.common.linkCopied,
                        copy.common.linkCopyFailed,
                        pushToast
                      )
                    }
                  >
                    <Copy className="size-4" />
                    {copy.common.copyLink}
                  </Button>
                  {isEditingNode ? (
                    <>
                      <Button
                        variant="outline"
                        onClick={() => stopNodeEdit(selectedNodeDetail)}
                      >
                        {copy.common.cancel}
                      </Button>
                      <Button
                        disabled={!canSaveNode || updateNodeMutation.isPending}
                        onClick={() => void handleSaveNode()}
                      >
                        <Save className="size-4" />
                        {updateNodeMutation.isPending ? copy.nodes.saving : copy.nodes.save}
                      </Button>
                    </>
                  ) : (
                    <>
                      <Button
                        variant="outline"
                        onClick={() => {
                          stopNodeEdit(null)
                          setSelectedNodeId("")
                        }}
                      >
                        {copy.common.dismiss}
                      </Button>
                      <Button
                        variant="outline"
                        onClick={() => beginNodeEdit(selectedNodeDetail)}
                      >
                        <PencilLine className="size-4" />
                        {copy.nodes.edit}
                      </Button>
                      <Button
                        variant="destructive"
                        disabled={
                          selectedNodeDetail.status === "disabled" ||
                          disableNodeMutation.isPending
                        }
                        onClick={() => void handleDisable(selectedNodeDetail)}
                      >
                        <Network className="size-4" />
                        {disableNodeMutation.isPending &&
                        disableNodeMutation.variables?.id === selectedNodeDetail.id
                          ? copy.nodes.disabling
                          : copy.nodes.disable}
                      </Button>
                    </>
                  )}
                </div>
              </div>
            ) : null}
          </DetailSheet>
        </div>
      )}
    </Panel>
  )
}

export function AccessPage() {
  const {
    settings,
    connectionReady,
    queryScope,
    locale,
    timezone,
    confirmAction,
    pushToast,
  } = useConsole()
  const copy = CONSOLE_COPY[locale]
  const queryClient = useQueryClient()
  const [draft, setDraft] = useState<AuthKeyDraft>(DEFAULT_AUTH_KEY_DRAFT)
  const [lastIssuedKey, setLastIssuedKey] = useState<IssuedAuthKey | null>(null)
  const [showIssuedSecret, setShowIssuedSecret] = useState(false)
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle")
  const [feedback, setFeedback] = useState<FeedbackState | null>(null)
  const [selectionVersion, setSelectionVersion] = useState(0)
  const [showOperations, setShowOperations] = useState(false)
  const [selectedAuthKeyId, setSelectedAuthKeyId] = useUrlQueryState("access-detail")
  const draftTags = useMemo(() => splitTags(draft.tags), [draft.tags])
  const draftErrors = useMemo(
    () => validateAuthKeyDraft(draft, draftTags, copy.access.validation),
    [copy.access.validation, draft, draftTags]
  )
  const resolvedDraftExpiryUnixSecs = useMemo(
    () => resolveDraftExpiryUnixSecs(draft),
    [draft]
  )

  const authKeysQuery = useQuery({
    queryKey: [...queryScope, "auth-keys"],
    queryFn: () => adminApi.getAuthKeys(settings),
    refetchInterval: 30_000,
    enabled: connectionReady,
  })

  const revokeAuthKeyMutation = useMutation({
    mutationFn: (authKey: NonNullable<typeof authKeysQuery.data>[number]) =>
      adminApi.revokeAuthKey(settings, authKey.id),
    onSuccess: async (_result, authKey) => {
      setFeedback({
        tone: "success",
        message: copy.access.revokeSuccess(authKey.description || authKey.id),
      })
      window.setTimeout(() => setFeedback(null), 2400)
      setSelectionVersion((current) => current + 1)
      await queryClient.invalidateQueries({ queryKey: [...queryScope, "auth-keys"] })
    },
  })

  const bulkRevokeMutation = useMutation({
    mutationFn: (selectedAuthKeys: AuthKey[]) =>
      performBulkAction(selectedAuthKeys, (authKey) =>
        adminApi.revokeAuthKey(settings, authKey.id)
      ),
    onSuccess: async ({ success, failed }) => {
      setFeedback({
        tone: failed > 0 ? "info" : "success",
        message: copy.access.bulkRevokeSuccess(success, failed),
      })
      window.setTimeout(() => setFeedback(null), 2800)
      setSelectionVersion((current) => current + 1)
      await queryClient.invalidateQueries({ queryKey: [...queryScope, "auth-keys"] })
    },
  })

  const createAuthKeyMutation = useMutation({
    mutationFn: (input: CreateAuthKeyInput) => adminApi.createAuthKey(settings, input),
    onSuccess: async (issuedAuthKey) => {
      setLastIssuedKey(issuedAuthKey)
      setShowIssuedSecret(true)
      setFeedback({ tone: "success", message: copy.access.issueSuccess })
      pushToast({ tone: "success", message: copy.access.issueSuccess })
      window.setTimeout(() => setFeedback(null), 2400)
      setDraft(DEFAULT_AUTH_KEY_DRAFT)
      setCopyState("idle")
      setShowOperations(true)
      await queryClient.invalidateQueries({ queryKey: [...queryScope, "auth-keys"] })
    },
  })

  const canSubmitDraft =
    connectionReady &&
    !createAuthKeyMutation.isPending &&
    Object.keys(draftErrors).length === 0

  const updateDraft = (updater: (current: AuthKeyDraft) => AuthKeyDraft) => {
    if (createAuthKeyMutation.error) {
      createAuthKeyMutation.reset()
    }
    setDraft(updater)
  }

  const issueExpirySummary =
    resolvedDraftExpiryUnixSecs != null
      ? copy.access.secretExpiresAt(
          formatDateTime(resolvedDraftExpiryUnixSecs, locale, timezone)
        )
      : copy.access.secretNeverExpires

  const onSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (Object.keys(draftErrors).length > 0) {
      return
    }

    await createAuthKeyMutation.mutateAsync({
      description: draft.description.trim() || undefined,
      tags: draftTags,
      reusable: draft.reusable,
      ephemeral: draft.ephemeral,
      expires_at_unix_secs: resolvedDraftExpiryUnixSecs ?? undefined,
    })
  }

  const copyLastIssuedKey = async () => {
    if (!lastIssuedKey || typeof navigator === "undefined") {
      return
    }

    try {
      await navigator.clipboard.writeText(lastIssuedKey.key)
      setCopyState("copied")
      pushToast({ tone: "success", message: copy.access.copySuccess })
      window.setTimeout(() => setCopyState("idle"), 1500)
    } catch {
      setCopyState("failed")
      window.setTimeout(() => setCopyState("idle"), 2500)
    }
  }

  const authKeys = authKeysQuery.data ?? []
  const latestIssuedExpirySummary =
    lastIssuedKey?.auth_key.expires_at_unix_secs != null
      ? copy.access.secretExpiresAt(
          formatDateTime(lastIssuedKey.auth_key.expires_at_unix_secs, locale, timezone)
        )
      : copy.access.secretNeverExpires
  const selectedAuthKeyDetail = selectedAuthKeyId
    ? authKeys.find((authKey) => authKey.id === selectedAuthKeyId) ?? null
    : null
  const selectedAuthKeyIndex = selectedAuthKeyDetail
    ? authKeys.findIndex((authKey) => authKey.id === selectedAuthKeyDetail.id)
    : -1

  const applyAuthKeyTemplate = (authKey: AuthKey) => {
    createAuthKeyMutation.reset()
    const futureExpiry =
      authKey.expires_at_unix_secs && authKey.expires_at_unix_secs > Math.floor(Date.now() / 1000)
        ? authKey.expires_at_unix_secs
        : null
    setDraft({
      description: authKey.description ?? "",
      tags: authKey.tags.join(", "),
      reusable: authKey.reusable,
      ephemeral: authKey.ephemeral,
      expiresPreset: futureExpiry ? "custom" : "30d",
      customExpiresAt: futureExpiry ? toDateTimeLocalValue(futureExpiry) : "",
    })
    setLastIssuedKey(null)
    setShowIssuedSecret(false)
    setCopyState("idle")
    setShowOperations(true)
    setSelectedAuthKeyId("")
  }

  const acknowledgeIssuedSecret = () => {
    createAuthKeyMutation.reset()
    setLastIssuedKey(null)
    setShowIssuedSecret(false)
    setCopyState("idle")
    setShowOperations(false)
  }

  const closeIssueSheet = () => {
    if (lastIssuedKey) {
      acknowledgeIssuedSecret()
      return
    }
    createAuthKeyMutation.reset()
    setDraft(DEFAULT_AUTH_KEY_DRAFT)
    setShowOperations(false)
  }

  const handleRevoke = async (authKey: NonNullable<typeof authKeysQuery.data>[number]) => {
    const label = authKey.description || authKey.id
    const confirmed = await confirmAction({
      message: copy.access.revokeConfirm(label),
      confirmLabel: copy.access.table.revoke,
      tone: "danger",
    })
    if (!confirmed) {
      return
    }

    revokeAuthKeyMutation.mutate(authKey)
  }

  const handleBulkRevoke = async (selectedAuthKeys: AuthKey[]) => {
    const confirmed = await confirmAction({
      message: copy.access.bulkRevokeConfirm(selectedAuthKeys.length),
      confirmLabel: copy.access.bulkRevoke,
      tone: "danger",
    })
    if (!confirmed) {
      return
    }

    bulkRevokeMutation.mutate(selectedAuthKeys)
  }

  return (
    <Panel>
      <div className="space-y-4">
        {authKeysQuery.isPending && authKeys.length === 0 ? (
          <PanelState mode="loading" message={copy.access.loading} />
        ) : authKeysQuery.error && authKeys.length === 0 ? (
          <PanelState
            mode="error"
            message={getConsoleErrorMessage(authKeysQuery.error, locale, copy.common.loadFailed)}
            actionLabel={copy.common.retry}
            onAction={() => void authKeysQuery.refetch()}
          />
        ) : (
          <div className="space-y-4">
            {feedback ? (
              <InlineAlert
                tone={feedback.tone}
                action={
                  <Button variant="ghost" size="sm" onClick={() => setFeedback(null)}>
                    {copy.common.dismiss}
                  </Button>
                }
              >
                {feedback.message}
              </InlineAlert>
            ) : null}
            {authKeysQuery.error && authKeys.length > 0 ? (
              <InlineAlert
                action={
                  <Button variant="outline" size="sm" onClick={() => void authKeysQuery.refetch()}>
                    {copy.common.retry}
                  </Button>
                }
              >
                {getConsoleErrorMessage(authKeysQuery.error, locale, copy.common.loadFailed)}
              </InlineAlert>
            ) : null}
            {revokeAuthKeyMutation.error ? (
              <InlineAlert>
                {getConsoleErrorMessage(revokeAuthKeyMutation.error, locale, copy.common.loadFailed)}
              </InlineAlert>
            ) : null}
            {bulkRevokeMutation.error ? (
              <InlineAlert>
                {getConsoleErrorMessage(bulkRevokeMutation.error, locale, copy.common.loadFailed)}
              </InlineAlert>
            ) : null}
            <AuthKeyTable
              authKeys={authKeys}
              pendingKeyId={
                revokeAuthKeyMutation.isPending
                  ? revokeAuthKeyMutation.variables?.id ?? null
                  : null
              }
              onRevoke={handleRevoke}
              onBulkRevoke={handleBulkRevoke}
              onView={(authKey) => setSelectedAuthKeyId(authKey.id)}
              activeKeyId={selectedAuthKeyDetail?.id ?? null}
              bulkRevoking={bulkRevokeMutation.isPending}
              resetSelectionKey={selectionVersion}
              toolbarAction={
                <Button
                  variant={showOperations ? "secondary" : "outline"}
                  size="sm"
                  onClick={() => {
                    if (lastIssuedKey) {
                      acknowledgeIssuedSecret()
                      return
                    }
                    setShowOperations((current) => !current)
                  }}
                >
                  {lastIssuedKey ? (
                    <CheckCircle2 className="size-3.5" />
                  ) : (
                    <KeyRound className="size-3.5" />
                  )}
                  {lastIssuedKey
                    ? copy.access.secretStored
                    : showOperations
                      ? copy.common.dismiss
                      : copy.access.form.issue}
                </Button>
              }
            />
            <DetailSheet
              open={showOperations}
              title={copy.access.issueTitle}
              subtitle={lastIssuedKey ? copy.access.latestTitle : copy.access.issueHelper}
              onClose={closeIssueSheet}
            >
              <div className="space-y-5">
                <form className="space-y-4" onSubmit={onSubmit}>
                  <div className="space-y-2">
                    <label className="console-eyebrow text-[12px] font-[510] tracking-[0.14em] uppercase">
                      {copy.access.form.description}
                    </label>
                    <Input
                      value={draft.description}
                      onChange={(event) =>
                        updateDraft((current) => ({
                          ...current,
                          description: event.target.value,
                        }))
                      }
                      placeholder={copy.access.form.descriptionPlaceholder}
                      aria-invalid={Boolean(draftErrors.description)}
                    />
                    {draftErrors.description ? (
                      <p className="text-[12px] text-destructive-foreground">
                        {draftErrors.description}
                      </p>
                    ) : null}
                  </div>

                  <div className="space-y-2">
                    <label className="console-eyebrow text-[12px] font-[510] tracking-[0.14em] uppercase">
                      {copy.access.form.tags}
                    </label>
                    <Textarea
                      value={draft.tags}
                      onChange={(event) =>
                        updateDraft((current) => ({
                          ...current,
                          tags: event.target.value,
                        }))
                      }
                      placeholder={copy.access.form.tagsPlaceholder}
                      className="min-h-[104px]"
                      aria-invalid={Boolean(draftErrors.tags)}
                    />
                    {draftErrors.tags ? (
                      <p className="text-[12px] text-destructive-foreground">{draftErrors.tags}</p>
                    ) : null}
                  </div>

                  <div className="space-y-3">
                    <div className="space-y-2">
                      <label className="console-eyebrow text-[12px] font-[510] tracking-[0.14em] uppercase">
                        {copy.access.form.expires}
                      </label>
                      <div className="flex flex-wrap gap-2">
                        {AUTH_KEY_EXPIRY_PRESETS.map((preset) => {
                          const label =
                            preset.value === "24h"
                              ? copy.access.form.expiresPreset24h
                              : preset.value === "7d"
                                ? copy.access.form.expiresPreset7d
                                : preset.value === "30d"
                                  ? copy.access.form.expiresPreset30d
                                  : preset.value === "custom"
                                    ? copy.access.form.expiresPresetCustom
                                    : copy.access.form.expiresNever

                          return (
                            <Button
                              key={preset.value}
                              type="button"
                              size="sm"
                              variant={
                                draft.expiresPreset === preset.value ? "secondary" : "outline"
                              }
                              onClick={() =>
                                updateDraft((current) => ({
                                  ...current,
                                  expiresPreset: preset.value,
                                  customExpiresAt:
                                    preset.value === "custom" ? current.customExpiresAt : "",
                                }))
                              }
                            >
                              {label}
                            </Button>
                          )
                        })}
                      </div>
                    </div>
                    {draft.expiresPreset === "custom" ? (
                      <div className="space-y-2">
                        <label className="console-eyebrow text-[12px] font-[510] tracking-[0.14em] uppercase">
                          {copy.access.form.expiresCustomLabel}
                        </label>
                        <Input
                          type="datetime-local"
                          value={draft.customExpiresAt}
                          onChange={(event) =>
                            updateDraft((current) => ({
                              ...current,
                              customExpiresAt: event.target.value,
                            }))
                          }
                          placeholder={copy.access.form.expiresCustomPlaceholder}
                          aria-invalid={Boolean(draftErrors.expiresAt)}
                        />
                        {draftErrors.expiresAt ? (
                          <p className="text-[12px] text-destructive-foreground">
                            {draftErrors.expiresAt}
                          </p>
                        ) : null}
                      </div>
                    ) : null}
                    <div className="console-surface-elevated space-y-2 rounded-[12px] p-3">
                      <p className="text-[12px] text-secondary-foreground">
                        {copy.access.form.expiresHelp}
                      </p>
                      <div className="text-[12px] font-[510] text-foreground">
                        {issueExpirySummary}
                      </div>
                    </div>
                  </div>

                  <div className="grid gap-3 sm:grid-cols-2">
                    <label className="console-surface-elevated flex items-center gap-3 rounded-[12px] px-3 py-3 text-[13px] text-secondary-foreground">
                      <input
                        type="checkbox"
                        checked={draft.reusable}
                        onChange={(event) =>
                          updateDraft((current) => ({
                            ...current,
                            reusable: event.target.checked,
                          }))
                        }
                        className="size-4 accent-[var(--primary)]"
                      />
                      {copy.access.form.reusable}
                    </label>
                    <label className="console-surface-elevated flex items-center gap-3 rounded-[12px] px-3 py-3 text-[13px] text-secondary-foreground">
                      <input
                        type="checkbox"
                        checked={draft.ephemeral}
                        onChange={(event) =>
                          updateDraft((current) => ({
                            ...current,
                            ephemeral: event.target.checked,
                          }))
                        }
                        className="size-4 accent-[var(--primary)]"
                      />
                      {copy.access.form.ephemeral}
                    </label>
                  </div>

                  {createAuthKeyMutation.error ? (
                    <div className="console-alert-error rounded-[12px] px-3 py-2 text-[13px]">
                      {getConsoleErrorMessage(
                        createAuthKeyMutation.error,
                        locale,
                        copy.errorUnknown
                      )}
                    </div>
                  ) : null}

                  {!lastIssuedKey ? <InlineAlert tone="info">{copy.access.issueHelper}</InlineAlert> : null}

                  <div className="flex flex-wrap gap-2">
                    <Button type="submit" disabled={!canSubmitDraft}>
                      <KeyRound className="size-4" />
                      {createAuthKeyMutation.isPending
                        ? copy.access.form.issuing
                        : copy.access.form.issue}
                    </Button>
                    <Button
                      type="button"
                      variant="outline"
                      disabled={createAuthKeyMutation.isPending}
                      onClick={closeIssueSheet}
                    >
                      <X className="size-3.5" />
                      {copy.common.dismiss}
                    </Button>
                  </div>
                </form>

                {lastIssuedKey ? (
                  <div className="space-y-3 border-t border-border pt-5">
                    <InlineAlert tone="info">{copy.access.secretShownOnce}</InlineAlert>
                    <div className="console-surface-elevated space-y-3 rounded-[12px] p-3">
                      <div className="console-eyebrow text-[12px] font-[510] tracking-[0.14em] uppercase">
                        {copy.access.latestTitle}
                      </div>
                      <div className="flex flex-wrap items-center gap-2">
                        <Input
                          readOnly
                          type={showIssuedSecret ? "text" : "password"}
                          value={lastIssuedKey.key}
                          onFocus={(event) => event.currentTarget.select()}
                          className="h-10 border-0 bg-transparent font-mono text-[12px] text-foreground shadow-none focus-visible:ring-0"
                        />
                        <Button
                          type="button"
                          size="sm"
                          variant="outline"
                          onClick={() => setShowIssuedSecret((current) => !current)}
                        >
                          {showIssuedSecret ? (
                            <EyeOff className="size-3.5" />
                          ) : (
                            <Eye className="size-3.5" />
                          )}
                          {showIssuedSecret ? copy.access.secretHide : copy.access.secretReveal}
                        </Button>
                        <Button type="button" size="sm" onClick={() => void copyLastIssuedKey()}>
                          <Copy className="size-3.5" />
                          {copyState === "copied" ? copy.common.copied : copy.common.copy}
                        </Button>
                      </div>
                      <div className="flex flex-wrap items-center justify-between gap-2 text-[12px] text-secondary-foreground">
                        <span>{latestIssuedExpirySummary}</span>
                        <Badge variant="secondary">
                          {lastIssuedKey.auth_key.description ??
                            copy.access.table.descriptionFallback}
                        </Badge>
                      </div>
                    </div>
                    {copyState === "failed" ? (
                      <InlineAlert>{copy.access.copyFailed}</InlineAlert>
                    ) : null}
                    <Button type="button" onClick={acknowledgeIssuedSecret}>
                      <CheckCircle2 className="size-4" />
                      {copy.access.secretStored}
                    </Button>
                  </div>
                ) : null}
              </div>
            </DetailSheet>
            <DetailSheet
              open={Boolean(selectedAuthKeyDetail)}
              title={copy.access.detailsTitle}
              subtitle={selectedAuthKeyDetail?.description || selectedAuthKeyDetail?.id}
              canPrevious={selectedAuthKeyIndex > 0}
              canNext={
                selectedAuthKeyIndex >= 0 && selectedAuthKeyIndex < authKeys.length - 1
              }
              onPrevious={() => setSelectedAuthKeyId(authKeys[selectedAuthKeyIndex - 1]?.id ?? "")}
              onNext={() => setSelectedAuthKeyId(authKeys[selectedAuthKeyIndex + 1]?.id ?? "")}
              headerActions={
                selectedAuthKeyDetail ? (
                  <>
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={selectedAuthKeyIndex <= 0}
                      onClick={() => setSelectedAuthKeyId(authKeys[selectedAuthKeyIndex - 1]?.id ?? "")}
                    >
                      <ChevronLeft className="size-4" />
                      {copy.common.previous}
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={
                        selectedAuthKeyIndex < 0 || selectedAuthKeyIndex >= authKeys.length - 1
                      }
                      onClick={() => setSelectedAuthKeyId(authKeys[selectedAuthKeyIndex + 1]?.id ?? "")}
                    >
                      {copy.common.next}
                      <ChevronRight className="size-4" />
                    </Button>
                  </>
                ) : null
              }
              onClose={() => setSelectedAuthKeyId("")}
            >
              {selectedAuthKeyDetail ? (
                <div className="space-y-4">
                  <KeyValueGrid
                    items={[
                      {
                        label: copy.common.identifier,
                        value: truncateMiddle(selectedAuthKeyDetail.id, 16, 12),
                      },
                      {
                        label: copy.access.table.columns.status,
                        value: copy.status.authKey[selectedAuthKeyDetail.state],
                      },
                      {
                        label: copy.access.table.columns.tags,
                        value: joinTags(selectedAuthKeyDetail.tags, copy.common.notSet),
                      },
                      {
                        label: copy.common.reusable,
                        value: selectedAuthKeyDetail.reusable ? copy.common.yes : copy.common.no,
                      },
                      {
                        label: copy.common.ephemeral,
                        value: selectedAuthKeyDetail.ephemeral ? copy.common.yes : copy.common.no,
                      },
                      {
                        label: copy.common.usage,
                        value: copy.access.table.usageCount(selectedAuthKeyDetail.usage_count),
                      },
                      {
                        label: copy.common.createdAt,
                        value: formatDateTime(
                          selectedAuthKeyDetail.created_at_unix_secs,
                          locale,
                          timezone
                        ),
                      },
                      {
                        label: copy.common.expiresAt,
                        value: formatDateTime(
                          selectedAuthKeyDetail.expires_at_unix_secs,
                          locale,
                          timezone
                        ),
                      },
                      {
                        label: copy.common.lastUsed,
                        value: formatDateTime(
                          selectedAuthKeyDetail.last_used_at_unix_secs,
                          locale,
                          timezone
                        ),
                      },
                    ]}
                  />
                  <div className="flex justify-end gap-2">
                    <Button
                      variant="outline"
                      onClick={() =>
                        void copyCurrentLocation(
                          copy.common.linkCopied,
                          copy.common.linkCopyFailed,
                          pushToast
                        )
                      }
                    >
                      <Copy className="size-4" />
                      {copy.common.copyLink}
                    </Button>
                    <Button variant="outline" onClick={() => setSelectedAuthKeyId("")}>
                      {copy.common.dismiss}
                    </Button>
                    <Button
                      variant="outline"
                      onClick={() => applyAuthKeyTemplate(selectedAuthKeyDetail)}
                    >
                      <PencilLine className="size-4" />
                      {copy.access.useAsTemplate}
                    </Button>
                    <Button
                      variant="destructive"
                      disabled={
                        selectedAuthKeyDetail.state !== "active" ||
                        revokeAuthKeyMutation.isPending
                      }
                      onClick={() => void handleRevoke(selectedAuthKeyDetail)}
                    >
                      <X className="size-4" />
                      {revokeAuthKeyMutation.isPending &&
                      revokeAuthKeyMutation.variables?.id === selectedAuthKeyDetail.id
                        ? copy.access.table.revoking
                        : copy.access.table.revoke}
                    </Button>
                  </div>
                </div>
              ) : null}
            </DetailSheet>
          </div>
        )}
      </div>
    </Panel>
  )
}

export function NetworkPage() {
  const {
    settings,
    connectionReady,
    queryScope,
    locale,
    timezone,
    confirmAction,
    pushToast,
  } = useConsole()
  const copy = CONSOLE_COPY[locale]
  const queryClient = useQueryClient()
  const [feedback, setFeedback] = useState<FeedbackState | null>(null)
  const [selectionVersion, setSelectionVersion] = useState(0)
  const [selectedRouteId, setSelectedRouteId] = useUrlQueryState("network-detail")

  const routesQuery = useQuery({
    queryKey: [...queryScope, "routes"],
    queryFn: () => adminApi.getRoutes(settings),
    refetchInterval: 15_000,
    enabled: connectionReady,
  })
  const nodesQuery = useQuery({
    queryKey: [...queryScope, "nodes"],
    queryFn: () => adminApi.getNodes(settings),
    refetchInterval: 12_000,
    enabled: connectionReady,
  })
  const derpQuery = useQuery({
    queryKey: [...queryScope, "derp"],
    queryFn: () => adminApi.getDerp(settings),
    refetchInterval: 20_000,
    enabled: connectionReady,
  })

  const routeDecisionMutation = useMutation({
    mutationFn: ({
      route,
      action,
    }: {
      route: NonNullable<typeof routesQuery.data>[number]
      action: "approve" | "reject"
    }) =>
      action === "approve"
        ? adminApi.approveRoute(settings, route.id)
        : adminApi.rejectRoute(settings, route.id),
    onSuccess: async (_result, { route, action }) => {
      setFeedback({
        tone: "success",
        message:
          action === "approve"
            ? copy.network.table.approveSuccess(route.prefix)
            : copy.network.table.rejectSuccess(route.prefix),
      })
      window.setTimeout(() => setFeedback(null), 2400)
      setSelectionVersion((current) => current + 1)
      await queryClient.invalidateQueries({ queryKey: [...queryScope, "routes"] })
    },
  })

  const bulkRouteDecisionMutation = useMutation({
    mutationFn: ({
      routes,
      action,
    }: {
      routes: Route[]
      action: "approve" | "reject"
    }) =>
      performBulkAction(routes, (route) =>
        action === "approve"
          ? adminApi.approveRoute(settings, route.id)
          : adminApi.rejectRoute(settings, route.id)
      ).then((result) => ({ ...result, action })),
    onSuccess: async ({ success, failed, action }) => {
      setFeedback({
        tone: failed > 0 ? "info" : "success",
        message:
          action === "approve"
            ? copy.network.table.bulkApproveSuccess(success, failed)
            : copy.network.table.bulkRejectSuccess(success, failed),
      })
      window.setTimeout(() => setFeedback(null), 2800)
      setSelectionVersion((current) => current + 1)
      await queryClient.invalidateQueries({ queryKey: [...queryScope, "routes"] })
    },
  })

  const routes = routesQuery.data ?? []
  const nodes = nodesQuery.data ?? []
  const derp = derpQuery.data
  const pendingRouteCount = routes.filter((route) => route.approval === "pending").length
  const nodesById = new Map(nodes.map((node) => [node.id, node]))
  const selectedRouteDetail = selectedRouteId
    ? routes.find((route) => String(route.id) === selectedRouteId) ?? null
    : null
  const selectedRouteIndex = selectedRouteDetail
    ? routes.findIndex((route) => route.id === selectedRouteDetail.id)
    : -1

  const handleApprove = async (route: NonNullable<typeof routesQuery.data>[number]) => {
    const confirmed = await confirmAction({
      message: copy.network.table.approveConfirm(route.prefix),
      confirmLabel: copy.network.table.approve,
    })
    if (!confirmed) {
      return
    }

    routeDecisionMutation.mutate({ route, action: "approve" })
  }

  const handleReject = async (route: NonNullable<typeof routesQuery.data>[number]) => {
    const confirmed = await confirmAction({
      message: copy.network.table.rejectConfirm(route.prefix),
      confirmLabel: copy.network.table.reject,
      tone: "danger",
    })
    if (!confirmed) {
      return
    }

    routeDecisionMutation.mutate({ route, action: "reject" })
  }

  const handleBulkApprove = async (selectedRoutes: Route[]) => {
    const confirmed = await confirmAction({
      message: copy.network.table.bulkApproveConfirm(selectedRoutes.length),
      confirmLabel: copy.network.table.bulkApprove,
    })
    if (!confirmed) {
      return
    }

    bulkRouteDecisionMutation.mutate({ routes: selectedRoutes, action: "approve" })
  }

  const handleBulkReject = async (selectedRoutes: Route[]) => {
    const confirmed = await confirmAction({
      message: copy.network.table.bulkRejectConfirm(selectedRoutes.length),
      confirmLabel: copy.network.table.bulkReject,
      tone: "danger",
    })
    if (!confirmed) {
      return
    }

    bulkRouteDecisionMutation.mutate({ routes: selectedRoutes, action: "reject" })
  }

  return (
    <div className="grid gap-6 xl:grid-cols-[1.08fr_0.92fr]">
      <Panel>
        {routesQuery.isPending && routes.length === 0 ? (
          <PanelState mode="loading" message={copy.common.loading} />
        ) : routesQuery.error && routes.length === 0 ? (
          <PanelState
            mode="error"
            message={getConsoleErrorMessage(routesQuery.error, locale, copy.common.loadFailed)}
            actionLabel={copy.common.retry}
            onAction={() => void routesQuery.refetch()}
          />
        ) : (
          <div className="space-y-4">
            {feedback ? (
              <InlineAlert
                tone={feedback.tone}
                action={
                  <Button variant="ghost" size="sm" onClick={() => setFeedback(null)}>
                    {copy.common.dismiss}
                  </Button>
                }
              >
                {feedback.message}
              </InlineAlert>
            ) : null}
            {routesQuery.error && routes.length > 0 ? (
              <InlineAlert
                action={
                  <Button variant="outline" size="sm" onClick={() => void routesQuery.refetch()}>
                    {copy.common.retry}
                  </Button>
                }
              >
                {getConsoleErrorMessage(routesQuery.error, locale, copy.common.loadFailed)}
              </InlineAlert>
            ) : null}
            {routeDecisionMutation.error ? (
              <InlineAlert>
                {getConsoleErrorMessage(routeDecisionMutation.error, locale, copy.common.loadFailed)}
              </InlineAlert>
            ) : null}
            {bulkRouteDecisionMutation.error ? (
              <InlineAlert>
                {getConsoleErrorMessage(
                  bulkRouteDecisionMutation.error,
                  locale,
                  copy.common.loadFailed
                )}
              </InlineAlert>
            ) : null}
            <RouteTable
              routes={routes}
              nodes={nodesById}
              pendingRouteAction={
                routeDecisionMutation.isPending
                  ? `${routeDecisionMutation.variables?.route.id}:${routeDecisionMutation.variables?.action}`
                  : null
              }
              onApprove={handleApprove}
              onReject={handleReject}
              onBulkApprove={handleBulkApprove}
              onBulkReject={handleBulkReject}
              onView={(route) => setSelectedRouteId(String(route.id))}
              activeRouteId={selectedRouteDetail?.id ?? null}
              bulkPending={bulkRouteDecisionMutation.isPending}
              resetSelectionKey={selectionVersion}
            />
            <DetailSheet
              open={Boolean(selectedRouteDetail)}
              title={copy.network.detailsTitle}
              subtitle={selectedRouteDetail?.prefix}
              canPrevious={selectedRouteIndex > 0}
              canNext={selectedRouteIndex >= 0 && selectedRouteIndex < routes.length - 1}
              onPrevious={() => setSelectedRouteId(String(routes[selectedRouteIndex - 1]?.id ?? ""))}
              onNext={() => setSelectedRouteId(String(routes[selectedRouteIndex + 1]?.id ?? ""))}
              headerActions={
                selectedRouteDetail ? (
                  <>
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={selectedRouteIndex <= 0}
                      onClick={() => setSelectedRouteId(String(routes[selectedRouteIndex - 1]?.id ?? ""))}
                    >
                      <ChevronLeft className="size-4" />
                      {copy.common.previous}
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={selectedRouteIndex < 0 || selectedRouteIndex >= routes.length - 1}
                      onClick={() => setSelectedRouteId(String(routes[selectedRouteIndex + 1]?.id ?? ""))}
                    >
                      {copy.common.next}
                      <ChevronRight className="size-4" />
                    </Button>
                  </>
                ) : null
              }
              onClose={() => setSelectedRouteId("")}
            >
              {selectedRouteDetail ? (
                <div className="space-y-4">
                  <KeyValueGrid
                    items={[
                      { label: copy.network.table.columns.prefix, value: selectedRouteDetail.prefix },
                      {
                        label: copy.common.approval,
                        value: copy.status.routeApproval[selectedRouteDetail.approval],
                      },
                      {
                        label: copy.network.table.columns.source,
                        value: selectedRouteDetail.approved_by_policy
                          ? copy.network.table.autoApproved
                          : copy.network.table.awaitingDecision,
                      },
                      {
                        label: copy.common.advertised,
                        value: selectedRouteDetail.advertised
                          ? copy.network.table.advertised
                          : copy.network.table.notAdvertised,
                      },
                      {
                        label: copy.common.routeType,
                        value: selectedRouteDetail.is_exit_node
                          ? copy.network.table.exitNode
                          : copy.network.table.subnetRoute,
                      },
                      {
                        label: copy.nodes.columns.node,
                        value:
                          nodesById.get(selectedRouteDetail.node_id)?.name ??
                          `node-${selectedRouteDetail.node_id}`,
                      },
                    ]}
                  />
                  <div className="flex justify-end gap-2">
                    <Button
                      variant="outline"
                      onClick={() =>
                        void copyCurrentLocation(
                          copy.common.linkCopied,
                          copy.common.linkCopyFailed,
                          pushToast
                        )
                      }
                    >
                      <Copy className="size-4" />
                      {copy.common.copyLink}
                    </Button>
                    <Button variant="outline" onClick={() => setSelectedRouteId("")}>
                      {copy.common.dismiss}
                    </Button>
                    <Button
                      variant="outline"
                      disabled={
                        selectedRouteDetail.approval === "rejected" ||
                        routeDecisionMutation.isPending
                      }
                      onClick={() => void handleReject(selectedRouteDetail)}
                    >
                      <X className="size-4" />
                      {routeDecisionMutation.isPending &&
                      routeDecisionMutation.variables?.route.id === selectedRouteDetail.id &&
                      routeDecisionMutation.variables?.action === "reject"
                        ? copy.network.table.rejecting
                        : copy.network.table.reject}
                    </Button>
                    <Button
                      disabled={
                        selectedRouteDetail.approval === "approved" ||
                        routeDecisionMutation.isPending
                      }
                      onClick={() => void handleApprove(selectedRouteDetail)}
                    >
                      <Network className="size-4" />
                      {routeDecisionMutation.isPending &&
                      routeDecisionMutation.variables?.route.id === selectedRouteDetail.id &&
                      routeDecisionMutation.variables?.action === "approve"
                        ? copy.network.table.approving
                        : copy.network.table.approve}
                    </Button>
                  </div>
                </div>
              ) : null}
            </DetailSheet>
          </div>
        )}
      </Panel>

      <div className="space-y-6">
        <Panel title={copy.network.signalsTitle} eyebrow={copy.network.signalsEyebrow}>
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-1">
            <MetricTile
              label={copy.network.metrics.pending}
              value={String(pendingRouteCount)}
              icon={Network}
            />
            <MetricTile
              label={copy.network.metrics.derpFailures}
              value={String(derp?.refresh_failures_total ?? 0)}
              icon={Globe2}
            />
          </div>
        </Panel>

        <Panel
          title={copy.network.derpRefreshTitle}
          eyebrow={copy.network.derpRefreshEyebrow}
          action={
            <PanelRefreshAction
              label={copy.refresh}
              refreshingLabel={copy.refreshing}
              refreshing={derpQuery.isFetching}
              onRefresh={() => void derpQuery.refetch()}
            />
          }
        >
          {derpQuery.isPending && !derp ? (
            <PanelState mode="loading" message={copy.common.loading} />
          ) : derpQuery.error && !derp ? (
            <PanelState
              mode="error"
              message={getConsoleErrorMessage(derpQuery.error, locale, copy.common.loadFailed)}
              actionLabel={copy.common.retry}
              onAction={() => void derpQuery.refetch()}
            />
          ) : (
            <>
              <KeyValueGrid
                items={[
                  {
                    label: copy.network.refresh.lastSuccess,
                    value: formatDateTime(
                      derp?.last_refresh_success_unix_secs,
                      locale,
                      timezone
                    ),
                  },
                  {
                    label: copy.network.refresh.lastAttempt,
                    value: formatDateTime(
                      derp?.last_refresh_attempt_unix_secs,
                      locale,
                      timezone
                    ),
                  },
                  {
                    label: copy.network.refresh.interval,
                    value: copy.network.refresh.seconds(derp?.refresh_interval_secs ?? 0),
                  },
                  {
                    label: copy.network.refresh.externalSources,
                    value: String(derp?.source_count ?? 0),
                  },
                ]}
              />
              {derp?.last_refresh_error ? (
                <div className="console-alert-error mt-4 rounded-[12px] px-3 py-2 text-[13px]">
                  {derp.last_refresh_error}
                </div>
              ) : null}
            </>
          )}
        </Panel>
      </div>
    </div>
  )
}

export function AuditPage() {
  const { settings, connectionReady, queryScope, locale, timezone, pushToast } =
    useConsole()
  const copy = CONSOLE_COPY[locale]
  const [query, setQuery] = useUrlQueryState("audit-q")
  const [kind, setKind] = useUrlQueryState("audit-kind")
  const [selectedEventId, setSelectedEventId] = useUrlQueryState("audit-detail")
  const [pageSize, setPageSize] = usePersistentUiState<number>("audit-page-size", 10)
  const [pageIndex, setPageIndex] = useState(0)

  const auditQuery = useQuery({
    queryKey: [...queryScope, "audit-events"],
    queryFn: () => adminApi.getAuditEvents(settings, 200),
    refetchInterval: 20_000,
    enabled: connectionReady,
  })

  const auditEvents = auditQuery.data ?? []
  const normalizedQuery = query.trim().toLowerCase()
  const filteredAuditEvents = auditEvents.filter((event) => {
    const matchesKind = !kind || event.kind === kind
    if (!matchesKind) {
      return false
    }

    if (!normalizedQuery) {
      return true
    }

    return [event.kind, event.target, event.actor.subject, event.actor.mechanism]
      .join(" ")
      .toLowerCase()
      .includes(normalizedQuery)
  })
  const totalPages = Math.max(1, Math.ceil(filteredAuditEvents.length / pageSize))
  const safePageIndex = Math.min(pageIndex, totalPages - 1)
  const pagedAuditEvents = filteredAuditEvents.slice(
    safePageIndex * pageSize,
    safePageIndex * pageSize + pageSize
  )
  const rangeStart = filteredAuditEvents.length === 0 ? 0 : safePageIndex * pageSize + 1
  const rangeEnd =
    filteredAuditEvents.length === 0 ? 0 : rangeStart + pagedAuditEvents.length - 1
  const selectedEvent = selectedEventId
    ? auditEvents.find((event) => event.id === selectedEventId) ?? null
    : null
  const selectedEventIndex = selectedEvent
    ? filteredAuditEvents.findIndex((event) => event.id === selectedEvent.id)
    : -1

  const clearFilters = () => {
    setQuery("")
    setKind("")
  }
  const clearQuery = () => {
    setQuery("")
    setPageIndex(0)
  }

  return (
    <Panel>
      {auditQuery.isPending && auditEvents.length === 0 ? (
        <PanelState mode="loading" message={copy.audit.loading} />
      ) : auditQuery.error && auditEvents.length === 0 ? (
        <PanelState
          mode="error"
          message={getConsoleErrorMessage(auditQuery.error, locale, copy.common.loadFailed)}
          actionLabel={copy.common.retry}
          onAction={() => void auditQuery.refetch()}
        />
      ) : (
        <div className="space-y-3">
          <div className="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
            <div>
              <p className="text-[13px] tracking-[-0.13px] text-muted-foreground">
                {copy.audit.count(filteredAuditEvents.length, auditEvents.length)}
              </p>
            </div>
            <div className="flex flex-col gap-2 md:flex-row md:items-center">
              <SearchField
                value={query}
                onChange={(nextValue) => {
                  setQuery(nextValue)
                  setPageIndex(0)
                }}
                onClear={clearQuery}
                placeholder={copy.audit.filterPlaceholder}
                clearLabel={copy.common.clearFilters}
                focusLabel={copy.common.focusSearch}
                className="w-full md:w-72"
              />
              <label className="console-surface-soft flex items-center gap-2 rounded-[10px] px-3 py-2 text-[12px] text-secondary-foreground">
                <span>{copy.audit.kindLabel}</span>
                <select
                  value={kind}
                  onChange={(event) => {
                    setKind(event.target.value)
                    setPageIndex(0)
                  }}
                  className="bg-transparent text-foreground outline-none"
                >
                  <option value="">{copy.audit.allKinds}</option>
                  {AUDIT_KIND_OPTIONS.map((value) => (
                    <option key={value} value={value}>
                      {copy.audit.kindNames[value]}
                    </option>
                  ))}
                </select>
              </label>
              <Button
                variant="ghost"
                size="sm"
                onClick={clearFilters}
                disabled={!query && !kind}
              >
                {copy.common.clearFilters}
              </Button>
            </div>
          </div>
          {auditQuery.error ? (
            <InlineAlert
              action={
                <Button variant="outline" size="sm" onClick={() => void auditQuery.refetch()}>
                  {copy.common.retry}
                </Button>
              }
            >
              {getConsoleErrorMessage(auditQuery.error, locale, copy.common.loadFailed)}
            </InlineAlert>
          ) : null}
          {filteredAuditEvents.length === 0 ? (
            <div className="console-surface-dashed rounded-[14px] p-8 text-center text-[13px] text-muted-foreground">
              {copy.audit.empty}
            </div>
          ) : null}
          {pagedAuditEvents.map((event) => (
            <div
              key={event.id}
              data-console-row="audit"
              className={`console-surface-soft cursor-pointer rounded-[14px] p-4 transition hover:bg-[var(--surface-elevated)] ${
                selectedEventId === event.id ? "bg-[var(--surface-elevated)]" : ""
              }`}
              onClick={() => setSelectedEventId(event.id)}
              onKeyDown={(keydownEvent) => {
                if (keydownEvent.key === "ArrowDown") {
                  keydownEvent.preventDefault()
                  focusCollectionItem(keydownEvent.currentTarget, '[data-console-row="audit"]', "next")
                  return
                }

                if (keydownEvent.key === "ArrowUp") {
                  keydownEvent.preventDefault()
                  focusCollectionItem(keydownEvent.currentTarget, '[data-console-row="audit"]', "previous")
                  return
                }

                if (keydownEvent.key === "Home") {
                  keydownEvent.preventDefault()
                  focusCollectionItem(keydownEvent.currentTarget, '[data-console-row="audit"]', "first")
                  return
                }

                if (keydownEvent.key === "End") {
                  keydownEvent.preventDefault()
                  focusCollectionItem(keydownEvent.currentTarget, '[data-console-row="audit"]', "last")
                  return
                }

                if (keydownEvent.key === "Enter" || keydownEvent.key === " ") {
                  keydownEvent.preventDefault()
                  setSelectedEventId(event.id)
                }
              }}
              tabIndex={0}
              aria-selected={selectedEventId === event.id}
            >
              <div className="flex flex-col gap-3 xl:flex-row xl:items-start xl:justify-between">
                <div className="space-y-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge variant="outline">{copy.audit.kindNames[event.kind]}</Badge>
                    <span className="text-[15px] font-[510] tracking-[-0.18px] text-foreground">
                      {event.target}
                    </span>
                  </div>
                  <div className="text-[13px] text-muted-foreground">
                    {event.actor.subject}
                    {copy.audit.actorSeparator}
                    {event.actor.mechanism}
                  </div>
                </div>
                <div className="text-[12px] font-mono text-muted-foreground">
                  {formatDateTime(event.occurred_at_unix_secs, locale, timezone)}
                </div>
              </div>
            </div>
          ))}
          {filteredAuditEvents.length > 0 ? (
            <div className="flex flex-col gap-3 pt-1 sm:flex-row sm:items-center sm:justify-between">
              <div className="text-[13px] text-muted-foreground">
                {copy.common.range(rangeStart, rangeEnd, filteredAuditEvents.length)}
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <label className="console-surface-soft flex items-center gap-2 rounded-[10px] px-3 py-2 text-[12px] text-secondary-foreground">
                  <span>{copy.common.rowsPerPage}</span>
                  <select
                    value={pageSize}
                    onChange={(event) => {
                      setPageSize(Number(event.target.value))
                      setPageIndex(0)
                    }}
                    className="bg-transparent text-foreground outline-none"
                  >
                    {AUDIT_PAGE_SIZE_OPTIONS.map((value) => (
                      <option key={value} value={value}>
                        {value}
                      </option>
                    ))}
                  </select>
                </label>
                <div className="text-[12px] text-muted-foreground">
                  {copy.common.page(totalPages === 0 ? 0 : safePageIndex + 1, totalPages)}
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPageIndex((current) => Math.max(0, current - 1))}
                  disabled={safePageIndex === 0}
                >
                  {copy.common.previous}
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() =>
                    setPageIndex((current) => Math.min(totalPages - 1, current + 1))
                  }
                  disabled={safePageIndex >= totalPages - 1}
                >
                  {copy.common.next}
                </Button>
              </div>
            </div>
          ) : null}
            <DetailSheet
              open={Boolean(selectedEvent)}
              title={copy.audit.detailsTitle}
              subtitle={selectedEvent ? copy.audit.kindNames[selectedEvent.kind] : undefined}
              canPrevious={selectedEventIndex > 0}
              canNext={
                selectedEventIndex >= 0 && selectedEventIndex < filteredAuditEvents.length - 1
              }
              onPrevious={() => setSelectedEventId(filteredAuditEvents[selectedEventIndex - 1]?.id ?? "")}
              onNext={() => setSelectedEventId(filteredAuditEvents[selectedEventIndex + 1]?.id ?? "")}
              headerActions={
                selectedEvent ? (
                  <>
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={selectedEventIndex <= 0}
                      onClick={() => setSelectedEventId(filteredAuditEvents[selectedEventIndex - 1]?.id ?? "")}
                    >
                      <ChevronLeft className="size-4" />
                      {copy.common.previous}
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={
                        selectedEventIndex < 0 ||
                        selectedEventIndex >= filteredAuditEvents.length - 1
                      }
                      onClick={() => setSelectedEventId(filteredAuditEvents[selectedEventIndex + 1]?.id ?? "")}
                    >
                      {copy.common.next}
                      <ChevronRight className="size-4" />
                    </Button>
                  </>
                ) : null
              }
              onClose={() => setSelectedEventId("")}
            >
              {selectedEvent ? (
                <div className="space-y-4">
                  <KeyValueGrid
                    items={[
                      { label: copy.common.identifier, value: truncateMiddle(selectedEvent.id, 14, 10) },
                      { label: copy.common.target, value: selectedEvent.target },
                      { label: copy.common.actor, value: selectedEvent.actor.subject },
                      { label: copy.common.mechanism, value: selectedEvent.actor.mechanism },
                      {
                        label: copy.common.occurredAt,
                        value: formatDateTime(
                          selectedEvent.occurred_at_unix_secs,
                          locale,
                          timezone
                        ),
                      },
                    ]}
                  />
                  <div className="flex justify-end gap-2">
                    <Button
                      variant="outline"
                      onClick={() =>
                        void copyCurrentLocation(
                          copy.common.linkCopied,
                          copy.common.linkCopyFailed,
                          pushToast
                        )
                      }
                    >
                      <Copy className="size-4" />
                      {copy.common.copyLink}
                    </Button>
                    <Button variant="outline" onClick={() => setSelectedEventId("")}>
                      {copy.common.dismiss}
                    </Button>
                  </div>
                </div>
              ) : null}
            </DetailSheet>
        </div>
      )}
    </Panel>
  )
}

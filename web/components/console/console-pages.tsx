"use client"

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  Activity,
  ChevronLeft,
  ChevronRight,
  Copy,
  Database,
  Globe2,
  KeyRound,
  Network,
  ShieldCheck,
  X,
} from "lucide-react"
import { useState, type FormEvent } from "react"

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
} from "./primitives"
import { focusCollectionItem } from "./interaction"

function splitTags(raw: string) {
  return raw
    .split(/[\n,]/)
    .map((value) => value.trim())
    .filter(Boolean)
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
  const { settings, connectionReady, queryScope, locale } = useConsole()
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

  const health = healthQuery.data
  const config = configQuery.data
  const derp = derpQuery.data
  const derpRegions = Object.values(derp?.effective_map.Regions ?? {})

  return (
    <div className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
        <MetricTile label={copy.overview.metrics.online} value="—" icon={Activity} />
        <MetricTile
          label={copy.overview.metrics.config}
          value={config ? copy.common.ok : configQuery.isPending ? "…" : "—"}
          icon={Database}
        />
        <MetricTile
          label={copy.overview.metrics.derp}
          value={derp ? String(derpRegions.length) : derpQuery.isPending ? "…" : "—"}
          icon={Globe2}
        />
        <MetricTile
          label={copy.overview.metrics.warnings}
          value={
            health
              ? health.config_has_warnings
                ? copy.common.yes
                : copy.common.no
              : healthQuery.isPending
                ? "…"
                : "—"
          }
          icon={Network}
        />
        <MetricTile
          label={copy.overview.metrics.uptime}
          value={
            health ? formatUptime(health.uptime_seconds, locale) : healthQuery.isPending ? "…" : "—"
          }
          icon={ShieldCheck}
        />
      </div>

      <div className="grid gap-6 xl:grid-cols-[1.08fr_0.92fr]">
        <Panel
          title={copy.overview.panels.healthTitle}
          eyebrow={copy.overview.panels.healthEyebrow}
          action={
            <PanelRefreshAction
              label={copy.refresh}
              refreshingLabel={copy.refreshing}
              refreshing={healthQuery.isFetching}
              onRefresh={() => void healthQuery.refetch()}
            />
          }
        >
          {healthQuery.isPending && !health ? (
            <PanelState mode="loading" message={copy.common.loading} />
          ) : healthQuery.error && !health ? (
            <PanelState
              mode="error"
              message={getConsoleErrorMessage(healthQuery.error, copy.common.loadFailed)}
              actionLabel={copy.common.retry}
              onAction={() => void healthQuery.refetch()}
            />
          ) : health ? (
            <KeyValueGrid
              items={[
                { label: copy.overview.health.service, value: health.service },
                { label: copy.overview.health.version, value: health.version },
                { label: copy.overview.health.bind, value: health.bind_addr },
                { label: copy.overview.health.log, value: health.log_format },
                {
                  label: copy.overview.health.uptime,
                  value: formatUptime(health.uptime_seconds, locale),
                },
                {
                  label: copy.overview.health.configWarnings,
                  value: health.config_has_warnings
                    ? copy.overview.health.present
                    : copy.overview.health.absent,
                },
              ]}
            />
          ) : null}
        </Panel>

        <Panel
          title={copy.overview.panels.controlTitle}
          eyebrow={copy.overview.panels.controlEyebrow}
          action={
            <PanelRefreshAction
              label={copy.refresh}
              refreshingLabel={copy.refreshing}
              refreshing={configQuery.isFetching}
              onRefresh={() => void configQuery.refetch()}
            />
          }
        >
          {configQuery.isPending && !config ? (
            <PanelState mode="loading" message={copy.common.loading} />
          ) : configQuery.error && !config ? (
            <PanelState
              mode="error"
              message={getConsoleErrorMessage(configQuery.error, copy.common.loadFailed)}
              actionLabel={copy.common.retry}
              onAction={() => void configQuery.refetch()}
            />
          ) : config ? (
            <KeyValueGrid
              items={[
                {
                  label: copy.overview.control.tailnetIpv4,
                  value: config.summary.tailnet_ipv4_range,
                },
                {
                  label: copy.overview.control.tailnetIpv6,
                  value: config.summary.tailnet_ipv6_range,
                },
                {
                  label: copy.overview.control.controlProtocol,
                  value: config.summary.control_protocol_enabled
                    ? copy.common.enabled
                    : copy.common.disabled,
                },
                {
                  label: copy.overview.control.adminAuth,
                  value: config.summary.admin_auth_configured
                    ? copy.common.configured
                    : copy.common.unconfigured,
                },
                {
                  label: copy.overview.control.webRoot,
                  value: config.summary.web_root_configured
                    ? copy.common.configured
                    : copy.common.unconfigured,
                },
                {
                  label: copy.overview.control.stun,
                  value: config.summary.derp_stun_bind_addr || copy.common.unconfigured,
                },
              ]}
            />
          ) : null}
        </Panel>
      </div>

      <div className="grid gap-6 xl:grid-cols-[0.92fr_1.08fr]">
        <Panel
          title={copy.overview.panels.derpTitle}
          eyebrow={copy.overview.panels.derpEyebrow}
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
              message={getConsoleErrorMessage(derpQuery.error, copy.common.loadFailed)}
              actionLabel={copy.common.retry}
              onAction={() => void derpQuery.refetch()}
            />
          ) : derp ? (
            <div className="space-y-4">
              <div className="grid gap-3 sm:grid-cols-3">
                <div className="console-surface-soft rounded-[12px] p-4">
                  <div className="console-eyebrow text-[11px] font-[510] tracking-[0.16em] uppercase">
                    {copy.overview.derp.regions}
                  </div>
                  <div className="mt-2 text-[24px] font-[510] tracking-[-0.4px] text-foreground">
                    {derpRegions.length}
                  </div>
                </div>
                <div className="console-surface-soft rounded-[12px] p-4">
                  <div className="console-eyebrow text-[11px] font-[510] tracking-[0.16em] uppercase">
                    {copy.overview.derp.sources}
                  </div>
                  <div className="mt-2 text-[24px] font-[510] tracking-[-0.4px] text-foreground">
                    {derp.source_count}
                  </div>
                </div>
                <div className="console-surface-soft rounded-[12px] p-4">
                  <div className="console-eyebrow text-[11px] font-[510] tracking-[0.16em] uppercase">
                    {copy.overview.derp.failures}
                  </div>
                  <div className="mt-2 text-[24px] font-[510] tracking-[-0.4px] text-foreground">
                    {derp.refresh_failures_total}
                  </div>
                </div>
              </div>

              <div className="space-y-3">
                {derpRegions.map((region) => (
                  <div
                    key={region.RegionID}
                    className="console-surface-soft rounded-[12px] p-4"
                  >
                    <div className="flex items-start justify-between gap-4">
                      <div>
                        <div className="text-[15px] font-[510] tracking-[-0.18px] text-foreground">
                          {region.RegionName}
                        </div>
                        <div className="mt-1 text-[12px] text-muted-foreground">
                          {copy.overview.derp.regionSummary(region.RegionCode, region.Nodes.length)}
                        </div>
                      </div>
                      <Badge variant="outline">{region.RegionID}</Badge>
                    </div>
                    <div className="mt-3 flex flex-wrap gap-2">
                      {region.Nodes.map((node) => (
                        <Badge key={node.Name} variant="secondary">
                          {node.HostName}:{node.DERPPort || 443}
                        </Badge>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : null}
        </Panel>

        <Panel
          title={copy.overview.panels.doctorTitle}
          eyebrow={copy.overview.panels.doctorEyebrow}
          action={
            <PanelRefreshAction
              label={copy.refresh}
              refreshingLabel={copy.refreshing}
              refreshing={configQuery.isFetching}
              onRefresh={() => void configQuery.refetch()}
            />
          }
        >
          {configQuery.isPending && !config ? (
            <PanelState mode="loading" message={copy.common.loading} />
          ) : configQuery.error && !config ? (
            <PanelState
              mode="error"
              message={getConsoleErrorMessage(configQuery.error, copy.common.loadFailed)}
              actionLabel={copy.common.retry}
              onAction={() => void configQuery.refetch()}
            />
          ) : (
            <Textarea
              readOnly
              value={JSON.stringify(config?.doctor ?? {}, null, 2)}
              className="min-h-[320px] border-border bg-[var(--surface-soft)] font-mono text-[12px]"
            />
          )}
        </Panel>
      </div>
    </div>
  )
}

export function NodesPage() {
  const { settings, connectionReady, queryScope, locale, confirmAction, pushToast } = useConsole()
  const copy = CONSOLE_COPY[locale]
  const queryClient = useQueryClient()
  const [feedback, setFeedback] = useState<FeedbackState | null>(null)
  const [selectionVersion, setSelectionVersion] = useState(0)
  const [selectedNodeId, setSelectedNodeId] = useUrlQueryState("nodes-detail")

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

  const nodes = nodesQuery.data ?? []

  const selectedNodeDetail = selectedNodeId
    ? nodes.find((node) => String(node.id) === selectedNodeId) ?? null
    : null
  const selectedNodeIndex = selectedNodeDetail
    ? nodes.findIndex((node) => node.id === selectedNodeDetail.id)
    : -1

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

  return (
    <Panel
      title={copy.nodes.panelTitle}
      eyebrow={copy.nodes.panelEyebrow}
      action={
        <PanelRefreshAction
          label={copy.refresh}
          refreshingLabel={copy.refreshing}
          refreshing={nodesQuery.isFetching}
          onRefresh={() => void nodesQuery.refetch()}
        />
      }
    >
      {nodesQuery.isPending && nodes.length === 0 ? (
        <PanelState mode="loading" message={copy.common.loading} />
      ) : nodesQuery.error && nodes.length === 0 ? (
        <PanelState
          mode="error"
          message={getConsoleErrorMessage(nodesQuery.error, copy.common.loadFailed)}
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
              {getConsoleErrorMessage(nodesQuery.error, copy.common.loadFailed)}
            </InlineAlert>
          ) : null}
          {disableNodeMutation.error ? (
            <InlineAlert>
              {getConsoleErrorMessage(disableNodeMutation.error, copy.common.loadFailed)}
            </InlineAlert>
          ) : null}
          {bulkDisableMutation.error ? (
            <InlineAlert>
              {getConsoleErrorMessage(bulkDisableMutation.error, copy.common.loadFailed)}
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
            onView={(node) => setSelectedNodeId(String(node.id))}
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
            onPrevious={() => setSelectedNodeId(String(nodes[selectedNodeIndex - 1]?.id ?? ""))}
            onNext={() => setSelectedNodeId(String(nodes[selectedNodeIndex + 1]?.id ?? ""))}
            headerActions={
              selectedNodeDetail ? (
                <>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={selectedNodeIndex <= 0}
                    onClick={() => setSelectedNodeId(String(nodes[selectedNodeIndex - 1]?.id ?? ""))}
                  >
                    <ChevronLeft className="size-4" />
                    {copy.common.previous}
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={selectedNodeIndex < 0 || selectedNodeIndex >= nodes.length - 1}
                    onClick={() => setSelectedNodeId(String(nodes[selectedNodeIndex + 1]?.id ?? ""))}
                  >
                    {copy.common.next}
                    <ChevronRight className="size-4" />
                  </Button>
                </>
              ) : null
            }
            onClose={() => setSelectedNodeId("")}
          >
            {selectedNodeDetail ? (
              <div className="space-y-4">
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
                      value: formatDateTime(selectedNodeDetail.last_seen_unix_secs, locale),
                    },
                    {
                      label: copy.common.identifier,
                      value: selectedNodeDetail.auth_key_id ?? copy.common.notSet,
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
                  <Button variant="outline" onClick={() => setSelectedNodeId("")}>
                    {copy.common.dismiss}
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
  const { settings, connectionReady, queryScope, locale, confirmAction, pushToast } = useConsole()
  const copy = CONSOLE_COPY[locale]
  const queryClient = useQueryClient()
  const [draft, setDraft] = useState({
    description: "",
    tags: "",
    reusable: false,
    ephemeral: false,
  })
  const [lastIssuedKey, setLastIssuedKey] = useState<IssuedAuthKey | null>(null)
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle")
  const [feedback, setFeedback] = useState<FeedbackState | null>(null)
  const [selectionVersion, setSelectionVersion] = useState(0)
  const [showOperations, setShowOperations] = useState(false)
  const [selectedAuthKeyId, setSelectedAuthKeyId] = useUrlQueryState("access-detail")

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
      setFeedback({ tone: "success", message: copy.access.issueSuccess })
      pushToast({ tone: "success", message: copy.access.issueSuccess })
      window.setTimeout(() => setFeedback(null), 2400)
      setDraft({
        description: "",
        tags: "",
        reusable: false,
        ephemeral: false,
      })
      setCopyState("idle")
      await queryClient.invalidateQueries({ queryKey: [...queryScope, "auth-keys"] })
    },
  })

  const onSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    await createAuthKeyMutation.mutateAsync({
      description: draft.description.trim() || undefined,
      tags: splitTags(draft.tags),
      reusable: draft.reusable,
      ephemeral: draft.ephemeral,
    })
  }

  const copyLastIssuedKey = async () => {
    if (!lastIssuedKey || typeof navigator === "undefined") {
      return
    }

    try {
      await navigator.clipboard.writeText(lastIssuedKey.key)
      setCopyState("copied")
      window.setTimeout(() => setCopyState("idle"), 1500)
    } catch {
      setCopyState("failed")
      window.setTimeout(() => setCopyState("idle"), 2500)
    }
  }

  const authKeys = authKeysQuery.data ?? []
  const selectedAuthKeyDetail = selectedAuthKeyId
    ? authKeys.find((authKey) => authKey.id === selectedAuthKeyId) ?? null
    : null
  const selectedAuthKeyIndex = selectedAuthKeyDetail
    ? authKeys.findIndex((authKey) => authKey.id === selectedAuthKeyDetail.id)
    : -1

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
    <Panel
      title={copy.access.authKeysTitle}
      eyebrow={copy.access.authKeysEyebrow}
      action={
        <div className="flex flex-wrap items-center gap-2">
          <Button
            variant={showOperations ? "secondary" : "outline"}
            size="sm"
            onClick={() => setShowOperations((current) => !current)}
          >
            <KeyRound className="size-3.5" />
            {showOperations ? copy.common.dismiss : copy.access.form.issue}
          </Button>
          <PanelRefreshAction
            label={copy.refresh}
            refreshingLabel={copy.refreshing}
            refreshing={authKeysQuery.isFetching}
            onRefresh={() => void authKeysQuery.refetch()}
          />
        </div>
      }
    >
      <div className="space-y-4">
        {showOperations ? (
          <div className="console-surface-soft space-y-4 rounded-[14px] p-4">
            <div className="grid gap-4 xl:grid-cols-[0.9fr_1.1fr]">
              <form className="space-y-4" onSubmit={onSubmit}>
                <div className="space-y-2">
                  <label className="console-eyebrow text-[12px] font-[510] tracking-[0.14em] uppercase">
                    {copy.access.form.description}
                  </label>
                  <Input
                    value={draft.description}
                    onChange={(event) =>
                      setDraft((current) => ({
                        ...current,
                        description: event.target.value,
                      }))
                    }
                    placeholder={copy.access.form.descriptionPlaceholder}
                  />
                </div>

                <div className="space-y-2">
                  <label className="console-eyebrow text-[12px] font-[510] tracking-[0.14em] uppercase">
                    {copy.access.form.tags}
                  </label>
                  <Textarea
                    value={draft.tags}
                    onChange={(event) =>
                      setDraft((current) => ({
                        ...current,
                        tags: event.target.value,
                      }))
                    }
                    placeholder={copy.access.form.tagsPlaceholder}
                    className="min-h-[104px]"
                  />
                </div>

                <div className="grid gap-3 sm:grid-cols-2">
                  <label className="console-surface-elevated flex items-center gap-3 rounded-[12px] px-3 py-3 text-[13px] text-secondary-foreground">
                    <input
                      type="checkbox"
                      checked={draft.reusable}
                      onChange={(event) =>
                        setDraft((current) => ({
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
                        setDraft((current) => ({
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
                    {getConsoleErrorMessage(createAuthKeyMutation.error, copy.errorUnknown)}
                  </div>
                ) : null}

                <div className="flex flex-wrap gap-2">
                  <Button
                    type="submit"
                    disabled={!connectionReady || createAuthKeyMutation.isPending}
                  >
                    <KeyRound className="size-4" />
                    {createAuthKeyMutation.isPending
                      ? copy.access.form.issuing
                      : copy.access.form.issue}
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => {
                      setDraft({
                        description: "",
                        tags: "",
                        reusable: false,
                        ephemeral: false,
                      })
                      setShowOperations(false)
                    }}
                  >
                    <X className="size-3.5" />
                    {copy.common.dismiss}
                  </Button>
                </div>
              </form>

              <div className="space-y-3">
                <div className="console-eyebrow text-[12px] font-[510] tracking-[0.14em] uppercase">
                  {copy.access.latestTitle}
                </div>
                {lastIssuedKey ? (
                  <div className="space-y-3">
                    <div className="console-surface-elevated flex items-center gap-2 rounded-[12px] p-2">
                      <Input
                        readOnly
                        value={lastIssuedKey.key}
                        onFocus={(event) => event.currentTarget.select()}
                        className="h-10 border-0 bg-transparent font-mono text-[12px] text-foreground shadow-none focus-visible:ring-0"
                      />
                      <Button size="sm" onClick={copyLastIssuedKey}>
                        <Copy className="size-3.5" />
                        {copyState === "copied" ? copy.common.copied : copy.common.copy}
                      </Button>
                    </div>
                    {copyState === "failed" ? (
                      <InlineAlert>{copy.access.copyFailed}</InlineAlert>
                    ) : null}
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => {
                        setLastIssuedKey(null)
                        setCopyState("idle")
                      }}
                    >
                      <X className="size-3.5" />
                      {copy.common.clear}
                    </Button>
                  </div>
                ) : (
                  <div className="console-surface-dashed rounded-[12px] p-4 text-[12px] text-muted-foreground">
                    {copy.access.latestEmpty}
                  </div>
                )}
              </div>
            </div>
          </div>
        ) : null}

        {authKeysQuery.isPending && authKeys.length === 0 ? (
          <PanelState mode="loading" message={copy.access.loading} />
        ) : authKeysQuery.error && authKeys.length === 0 ? (
          <PanelState
            mode="error"
            message={getConsoleErrorMessage(authKeysQuery.error, copy.common.loadFailed)}
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
                {getConsoleErrorMessage(authKeysQuery.error, copy.common.loadFailed)}
              </InlineAlert>
            ) : null}
            {revokeAuthKeyMutation.error ? (
              <InlineAlert>
                {getConsoleErrorMessage(revokeAuthKeyMutation.error, copy.common.loadFailed)}
              </InlineAlert>
            ) : null}
            {bulkRevokeMutation.error ? (
              <InlineAlert>
                {getConsoleErrorMessage(bulkRevokeMutation.error, copy.common.loadFailed)}
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
            />
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
                        value: formatDateTime(selectedAuthKeyDetail.created_at_unix_secs, locale),
                      },
                      {
                        label: copy.common.expiresAt,
                        value: formatDateTime(selectedAuthKeyDetail.expires_at_unix_secs, locale),
                      },
                      {
                        label: copy.common.lastUsed,
                        value: formatDateTime(selectedAuthKeyDetail.last_used_at_unix_secs, locale),
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
  const { settings, connectionReady, queryScope, locale, confirmAction, pushToast } = useConsole()
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
      <Panel
        title={copy.network.routesTitle}
        eyebrow={copy.network.routesEyebrow}
        action={
          <PanelRefreshAction
            label={copy.refresh}
            refreshingLabel={copy.refreshing}
            refreshing={routesQuery.isFetching || nodesQuery.isFetching}
            onRefresh={() => {
              void routesQuery.refetch()
              void nodesQuery.refetch()
            }}
          />
        }
      >
        {routesQuery.isPending && routes.length === 0 ? (
          <PanelState mode="loading" message={copy.common.loading} />
        ) : routesQuery.error && routes.length === 0 ? (
          <PanelState
            mode="error"
            message={getConsoleErrorMessage(routesQuery.error, copy.common.loadFailed)}
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
                {getConsoleErrorMessage(routesQuery.error, copy.common.loadFailed)}
              </InlineAlert>
            ) : null}
            {routeDecisionMutation.error ? (
              <InlineAlert>
                {getConsoleErrorMessage(routeDecisionMutation.error, copy.common.loadFailed)}
              </InlineAlert>
            ) : null}
            {bulkRouteDecisionMutation.error ? (
              <InlineAlert>
                {getConsoleErrorMessage(bulkRouteDecisionMutation.error, copy.common.loadFailed)}
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
              message={getConsoleErrorMessage(derpQuery.error, copy.common.loadFailed)}
              actionLabel={copy.common.retry}
              onAction={() => void derpQuery.refetch()}
            />
          ) : (
            <>
              <KeyValueGrid
                items={[
                  {
                    label: copy.network.refresh.lastSuccess,
                    value: formatDateTime(derp?.last_refresh_success_unix_secs, locale),
                  },
                  {
                    label: copy.network.refresh.lastAttempt,
                    value: formatDateTime(derp?.last_refresh_attempt_unix_secs, locale),
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
  const { settings, connectionReady, queryScope, locale, pushToast } = useConsole()
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
    <Panel
      title={copy.audit.title}
      eyebrow={copy.audit.eyebrow}
      action={
        <PanelRefreshAction
          label={copy.refresh}
          refreshingLabel={copy.refreshing}
          refreshing={auditQuery.isFetching}
          onRefresh={() => void auditQuery.refetch()}
        />
      }
    >
      {auditQuery.isPending && auditEvents.length === 0 ? (
        <PanelState mode="loading" message={copy.audit.loading} />
      ) : auditQuery.error && auditEvents.length === 0 ? (
        <PanelState
          mode="error"
          message={getConsoleErrorMessage(auditQuery.error, copy.common.loadFailed)}
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
              {getConsoleErrorMessage(auditQuery.error, copy.common.loadFailed)}
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
                  {formatDateTime(event.occurred_at_unix_secs, locale)}
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
                        value: formatDateTime(selectedEvent.occurred_at_unix_secs, locale),
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

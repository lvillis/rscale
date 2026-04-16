import { Badge } from "@/components/ui/badge"
import { useConsole } from "@/components/console/console-context"
import { CONSOLE_COPY } from "@/components/console/strings"
import type {
  AuthKeyState,
  NodeStatus,
  NodeTagSource,
  RouteApproval,
} from "@/lib/types"

function tone(
  variant: React.ComponentProps<typeof Badge>["variant"],
  className?: string
) {
  return { variant, className }
}

export function HealthBadge({
  healthy,
  healthyLabel,
  unhealthyLabel,
}: {
  healthy: boolean
  healthyLabel: string
  unhealthyLabel: string
}) {
  const current = healthy
    ? tone("secondary", "border-transparent bg-emerald-500 text-white")
    : tone(
        "destructive",
        "border-destructive/25 bg-destructive/10 text-destructive-foreground"
      )

  return (
    <Badge variant={current.variant} className={current.className}>
      {healthy ? healthyLabel : unhealthyLabel}
    </Badge>
  )
}

export function NodeStatusBadge({ status }: { status: NodeStatus }) {
  const { locale } = useConsole()
  const labels = CONSOLE_COPY[locale].status.node
  const current =
    {
      online: {
        label: labels.online,
        ...tone("secondary", "border-transparent bg-emerald-500 text-white"),
      },
      offline: {
        label: labels.offline,
        ...tone("outline", "text-muted-foreground"),
      },
      pending: {
        label: labels.pending,
        ...tone("outline", "text-secondary-foreground"),
      },
      expired: {
        label: labels.expired,
        ...tone(
          "destructive",
          "border-destructive/25 bg-destructive/10 text-destructive-foreground"
        ),
      },
      disabled: {
        label: labels.disabled,
        ...tone("outline", "text-[var(--text-quaternary)]"),
      },
    }[status] ?? {
      label: status,
      ...tone("outline"),
    }

  return (
    <Badge variant={current.variant} className={current.className}>
      {current.label}
    </Badge>
  )
}

export function TagSourceBadge({ source }: { source: NodeTagSource }) {
  const { locale } = useConsole()
  const labels = CONSOLE_COPY[locale].status.tagSource
  const current =
    {
      none: { label: labels.none, ...tone("outline") },
      request: {
        label: labels.request,
        ...tone(
          "outline",
          "border-primary/25 bg-primary/10 text-secondary-foreground"
        ),
      },
      auth_key: {
        label: labels.auth_key,
        ...tone(
          "outline",
          "border-primary/[0.3] bg-primary/[0.14] text-foreground"
        ),
      },
      admin: {
        label: labels.admin,
        ...tone(
          "outline",
          "border-primary/[0.28] bg-[var(--surface-soft)] text-foreground"
        ),
      },
    }[source] ?? { label: source, ...tone("outline") }

  return (
    <Badge variant={current.variant} className={current.className}>
      {current.label}
    </Badge>
  )
}

export function AuthKeyStateBadge({ state }: { state: AuthKeyState }) {
  const { locale } = useConsole()
  const labels = CONSOLE_COPY[locale].status.authKey
  const current =
    {
      active: {
        label: labels.active,
        ...tone("secondary", "border-transparent bg-emerald-500 text-white"),
      },
      revoked: {
        label: labels.revoked,
        ...tone(
          "destructive",
          "border-destructive/25 bg-destructive/10 text-destructive-foreground"
        ),
      },
      expired: {
        label: labels.expired,
        ...tone("outline", "text-muted-foreground"),
      },
    }[state] ?? { label: state, ...tone("outline") }

  return (
    <Badge variant={current.variant} className={current.className}>
      {current.label}
    </Badge>
  )
}

export function RouteApprovalBadge({ approval }: { approval: RouteApproval }) {
  const { locale } = useConsole()
  const labels = CONSOLE_COPY[locale].status.routeApproval
  const current =
    {
      approved: {
        label: labels.approved,
        ...tone("secondary", "border-transparent bg-emerald-500 text-white"),
      },
      rejected: {
        label: labels.rejected,
        ...tone(
          "destructive",
          "border-destructive/25 bg-destructive/10 text-destructive-foreground"
        ),
      },
      pending: {
        label: labels.pending,
        ...tone("outline", "text-secondary-foreground"),
      },
    }[approval] ?? { label: approval, ...tone("outline") }

  return (
    <Badge variant={current.variant} className={current.className}>
      {current.label}
    </Badge>
  )
}

export type AdminHealthResponse = {
  service: string
  version: string
  uptime_seconds: number
  bind_addr: string
  database_configured: boolean
  admin_auth_configured: boolean
  database_ready: boolean
  oidc_enabled: boolean
  config_has_warnings: boolean
  log_format: string
}

export type ConfigSummary = {
  bind_addr: string
  web_root_configured: boolean
  control_protocol_enabled: boolean
  tailnet_ipv4_range: string
  tailnet_ipv6_range: string
  database_configured: boolean
  derp_region_count: number
  derp_url_count: number
  derp_path_count: number
  derp_omit_default_regions: boolean
  derp_refresh_interval_secs: number
  derp_embedded_relay_enabled: boolean
  derp_stun_bind_addr: string | null
  derp_verify_clients: boolean
  admin_auth_configured: boolean
  oidc_enabled: boolean
  oidc_discovery_validation: boolean
  control_display_message_count: number
  control_dial_candidate_count: number
  control_client_version_configured: boolean
  control_collect_services_configured: boolean
  control_node_attr_count: number
  control_pop_browser_url_configured: boolean
  log_filter: string
  log_format: string
}

export type AdminConfigResponse = {
  summary: ConfigSummary
  doctor: unknown
}

export type ControlDerpNode = {
  Name: string
  RegionID: number
  HostName: string
  CertName?: string
  IPv4?: string
  IPv6?: string
  STUNPort?: number
  STUNOnly?: boolean
  DERPPort?: number
  InsecureForTests?: boolean
  STUNTestIP?: string
  CanPort80?: boolean
}

export type ControlDerpRegion = {
  RegionID: number
  RegionCode: string
  RegionName: string
  Latitude?: number
  Longitude?: number
  Avoid?: boolean
  NoMeasureNoHome?: boolean
  Nodes: ControlDerpNode[]
}

export type ControlDerpMap = {
  Regions: Record<string, ControlDerpRegion>
  HomeParams?: {
    RegionScore?: Record<string, number>
  }
  omitDefaultRegions?: boolean
}

export type DerpRuntimeStatus = {
  effective_map: ControlDerpMap
  effective_region_count: number
  source_count: number
  source_urls: string[]
  source_paths: string[]
  refresh_enabled: boolean
  refresh_interval_secs: number
  last_refresh_attempt_unix_secs: number | null
  last_refresh_success_unix_secs: number | null
  last_refresh_error: string | null
  refresh_failures_total: number
}

export type NodeStatus =
  | "pending"
  | "online"
  | "offline"
  | "expired"
  | "disabled"

export type NodeTagSource = "none" | "request" | "auth_key" | "admin"

export type Node = {
  id: number
  stable_id: string
  name: string
  hostname: string
  auth_key_id: string | null
  principal_id: number | null
  ipv4: string | null
  ipv6: string | null
  status: NodeStatus
  tags: string[]
  tag_source: NodeTagSource
  last_seen_unix_secs: number | null
}

export type AuthKeyState = "active" | "revoked" | "expired"

export type AuthKey = {
  id: string
  description: string | null
  tags: string[]
  reusable: boolean
  ephemeral: boolean
  expires_at_unix_secs: number | null
  created_at_unix_secs: number
  last_used_at_unix_secs: number | null
  revoked_at_unix_secs: number | null
  usage_count: number
  state: AuthKeyState
}

export type IssuedAuthKey = {
  auth_key: AuthKey
  key: string
}

export type RouteApproval = "pending" | "approved" | "rejected"

export type Route = {
  id: number
  node_id: number
  prefix: string
  advertised: boolean
  approval: RouteApproval
  approved_by_policy: boolean
  is_exit_node: boolean
}

export type AuditEventKind =
  | "node_registered"
  | "node_updated"
  | "node_disabled"
  | "node_deleted"
  | "auth_key_created"
  | "auth_key_revoked"
  | "policy_updated"
  | "dns_updated"
  | "route_created"
  | "route_approved"
  | "route_rejected"
  | "admin_authenticated"
  | "backup_restored"
  | "ssh_check_approved"
  | "ssh_check_rejected"

export type AuditEvent = {
  id: string
  actor: {
    subject: string
    mechanism: string
  }
  kind: AuditEventKind
  target: string
  occurred_at_unix_secs: number
}

export type CreateAuthKeyInput = {
  description?: string
  tags: string[]
  reusable: boolean
  ephemeral: boolean
}

export type ApiErrorPayload = {
  code?: string
  message?: string
}

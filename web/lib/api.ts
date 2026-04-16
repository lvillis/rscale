import type {
  AdminConfigResponse,
  AdminHealthResponse,
  AuditEvent,
  AuthKey,
  CreateAuthKeyInput,
  DerpRuntimeStatus,
  IssuedAuthKey,
  Node,
  Route,
} from "@/lib/types"

export const CONSOLE_AUTH_EXPIRED_EVENT = "rscale:auth-expired"

export type ConsoleConnectionSettings = {
  apiBaseUrl: string
  adminToken: string
}

export class ConsoleApiError extends Error {
  status: number
  code?: string

  constructor(message: string, status: number, code?: string) {
    super(message)
    this.name = "ConsoleApiError"
    this.status = status
    this.code = code
  }
}

function resolveApiBaseUrl(apiBaseUrl: string) {
  const trimmed = apiBaseUrl.trim()

  if (trimmed) {
    return trimmed.replace(/\/+$/, "")
  }

  if (typeof window !== "undefined") {
    return window.location.origin
  }

  return ""
}

async function parseResponseBody(response: Response) {
  const text = await response.text()
  if (!text) {
    return null
  }

  try {
    return JSON.parse(text) as unknown
  } catch {
    return text
  }
}

async function requestJson<T>(
  path: string,
  settings: ConsoleConnectionSettings,
  init?: RequestInit
) {
  const baseUrl = resolveApiBaseUrl(settings.apiBaseUrl)
  if (!baseUrl) {
    throw new ConsoleApiError("缺少管理 API 地址", 400, "missing_api_base_url")
  }

  if (!settings.adminToken.trim()) {
    throw new ConsoleApiError(
      "缺少管理员 token",
      400,
      "missing_admin_token"
    )
  }

  const response = await fetch(`${baseUrl}/api/v1/admin${path}`, {
    ...init,
    headers: {
      Accept: "application/json",
      Authorization: `Bearer ${settings.adminToken.trim()}`,
      ...(init?.headers ?? {}),
    },
  })
  const payload = await parseResponseBody(response)

  if (!response.ok) {
    const message =
      typeof payload === "object" &&
      payload !== null &&
      "message" in payload &&
      typeof payload.message === "string"
        ? payload.message
        : `请求失败 (${response.status})`
    const code =
      typeof payload === "object" &&
      payload !== null &&
      "code" in payload &&
      typeof payload.code === "string"
        ? payload.code
        : undefined

    if (response.status === 401 && typeof window !== "undefined") {
      window.dispatchEvent(new CustomEvent(CONSOLE_AUTH_EXPIRED_EVENT))
    }

    throw new ConsoleApiError(message, response.status, code)
  }

  return payload as T
}

export const adminApi = {
  getHealth: (settings: ConsoleConnectionSettings) =>
    requestJson<AdminHealthResponse>("/health", settings),
  getConfig: (settings: ConsoleConnectionSettings) =>
    requestJson<AdminConfigResponse>("/config", settings),
  getDerp: (settings: ConsoleConnectionSettings) =>
    requestJson<DerpRuntimeStatus>("/derp-map", settings),
  getNodes: (settings: ConsoleConnectionSettings) =>
    requestJson<Node[]>("/nodes", settings),
  disableNode: (settings: ConsoleConnectionSettings, id: number) =>
    requestJson<Node>(`/nodes/${id}/disable`, settings, {
      method: "POST",
    }),
  getAuthKeys: (settings: ConsoleConnectionSettings) =>
    requestJson<AuthKey[]>("/auth-keys", settings),
  createAuthKey: (
    settings: ConsoleConnectionSettings,
    input: CreateAuthKeyInput
  ) =>
    requestJson<IssuedAuthKey>("/auth-keys", settings, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(input),
    }),
  revokeAuthKey: (settings: ConsoleConnectionSettings, id: string) =>
    requestJson<AuthKey>(`/auth-keys/${id}/revoke`, settings, {
      method: "POST",
    }),
  getRoutes: (settings: ConsoleConnectionSettings) =>
    requestJson<Route[]>("/routes", settings),
  approveRoute: (settings: ConsoleConnectionSettings, id: number) =>
    requestJson<Route>(`/routes/${id}/approve`, settings, {
      method: "POST",
    }),
  rejectRoute: (settings: ConsoleConnectionSettings, id: number) =>
    requestJson<Route>(`/routes/${id}/reject`, settings, {
      method: "POST",
    }),
  getAuditEvents: (settings: ConsoleConnectionSettings, limit = 24) =>
    requestJson<AuditEvent[]>(`/audit-events?limit=${limit}`, settings),
}

CREATE TABLE IF NOT EXISTS auth_keys (
    id TEXT PRIMARY KEY,
    secret_hash TEXT NOT NULL UNIQUE,
    description TEXT NULL,
    reusable BOOLEAN NOT NULL,
    ephemeral BOOLEAN NOT NULL,
    state TEXT NOT NULL,
    expires_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ NULL,
    usage_count BIGINT NOT NULL DEFAULT 0,
    last_used_at TIMESTAMPTZ NULL,
    tags JSONB NOT NULL DEFAULT '[]'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_auth_keys_secret_hash ON auth_keys (secret_hash);

CREATE TABLE IF NOT EXISTS principals (
    id BIGSERIAL PRIMARY KEY,
    provider TEXT NOT NULL,
    issuer TEXT NULL,
    subject TEXT NULL,
    login_name TEXT NOT NULL,
    display_name TEXT NOT NULL,
    email TEXT NULL,
    groups JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT principals_provider_subject_unique UNIQUE (provider, issuer, subject)
);

CREATE INDEX IF NOT EXISTS idx_principals_provider_subject
    ON principals (provider, issuer, subject);

CREATE TABLE IF NOT EXISTS nodes (
    id BIGSERIAL PRIMARY KEY,
    stable_id TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL UNIQUE,
    hostname TEXT NOT NULL,
    ipv4 TEXT NULL,
    ipv6 TEXT NULL,
    status TEXT NOT NULL,
    tags JSONB NOT NULL DEFAULT '[]'::jsonb,
    tag_source TEXT NOT NULL DEFAULT 'none',
    auth_key_id TEXT NULL REFERENCES auth_keys (id),
    principal_id BIGINT NULL REFERENCES principals (id),
    session_secret_hash TEXT NULL,
    session_expires_at TIMESTAMPTZ NULL,
    last_sync_at TIMESTAMPTZ NULL,
    last_seen_unix_secs BIGINT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_nodes_status ON nodes (status);
CREATE INDEX IF NOT EXISTS idx_nodes_auth_key_id ON nodes (auth_key_id);
CREATE INDEX IF NOT EXISTS idx_nodes_principal_id ON nodes (principal_id);
CREATE INDEX IF NOT EXISTS idx_nodes_session_secret_hash ON nodes (session_secret_hash);
CREATE INDEX IF NOT EXISTS idx_nodes_session_expires_at ON nodes (session_expires_at);

CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    actor_subject TEXT NOT NULL,
    actor_mechanism TEXT NOT NULL,
    target TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_events_occurred_at_desc
    ON audit_events (occurred_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS control_plane_state (
    id TEXT PRIMARY KEY,
    policy JSONB NOT NULL,
    dns JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO control_plane_state (id, policy, dns)
VALUES (
    'global',
    '{"groups":[],"rules":[]}'::jsonb,
    '{"magic_dns":false,"base_domain":null,"nameservers":[],"search_domains":[]}'::jsonb
)
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS routes (
    id BIGSERIAL PRIMARY KEY,
    node_id BIGINT NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
    prefix TEXT NOT NULL,
    advertised BOOLEAN NOT NULL DEFAULT TRUE,
    approval TEXT NOT NULL,
    is_exit_node BOOLEAN NOT NULL DEFAULT FALSE,
    approved_by_policy BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (node_id, prefix, is_exit_node)
);

CREATE INDEX IF NOT EXISTS idx_routes_node_id ON routes (node_id);
CREATE INDEX IF NOT EXISTS idx_routes_approval ON routes (approval);
CREATE INDEX IF NOT EXISTS idx_routes_approved_by_policy ON routes (approved_by_policy);

CREATE TABLE IF NOT EXISTS node_control_state (
    node_id BIGINT PRIMARY KEY REFERENCES nodes (id) ON DELETE CASCADE,
    machine_key TEXT NOT NULL UNIQUE,
    node_key TEXT NOT NULL UNIQUE,
    disco_key TEXT NULL,
    hostinfo JSONB NOT NULL DEFAULT '{}'::jsonb,
    endpoints JSONB NOT NULL DEFAULT '[]'::jsonb,
    key_expiry TIMESTAMPTZ NULL,
    map_request_version BIGINT NOT NULL DEFAULT 0,
    map_session_handle TEXT NULL,
    map_session_seq BIGINT NOT NULL DEFAULT 0,
    last_control_seen_at TIMESTAMPTZ NULL,
    last_map_poll_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_node_control_state_machine_key
    ON node_control_state (machine_key);

CREATE INDEX IF NOT EXISTS idx_node_control_state_node_key
    ON node_control_state (node_key);

CREATE INDEX IF NOT EXISTS idx_node_control_state_updated_at
    ON node_control_state (updated_at);

CREATE TABLE IF NOT EXISTS oidc_auth_requests (
    id TEXT PRIMARY KEY,
    machine_key TEXT NOT NULL,
    node_key TEXT NOT NULL,
    old_node_key TEXT NOT NULL DEFAULT '',
    nl_key TEXT NOT NULL DEFAULT '',
    expiry TIMESTAMPTZ NULL,
    hostinfo JSONB NOT NULL DEFAULT '{}'::jsonb,
    ephemeral BOOLEAN NOT NULL DEFAULT false,
    tailnet TEXT NOT NULL DEFAULT '',
    oidc_state TEXT NOT NULL UNIQUE,
    oidc_nonce TEXT NOT NULL,
    pkce_verifier TEXT NOT NULL,
    principal_issuer TEXT NULL,
    principal_sub TEXT NULL,
    principal_email TEXT NULL,
    principal_name TEXT NULL,
    principal_groups JSONB NOT NULL DEFAULT '[]'::jsonb,
    completed_at TIMESTAMPTZ NULL,
    node_id BIGINT NULL REFERENCES nodes (id) ON DELETE SET NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_oidc_auth_requests_machine_key
    ON oidc_auth_requests (machine_key);

CREATE INDEX IF NOT EXISTS idx_oidc_auth_requests_state
    ON oidc_auth_requests (oidc_state);

CREATE INDEX IF NOT EXISTS idx_oidc_auth_requests_expires_at
    ON oidc_auth_requests (expires_at);

CREATE TABLE IF NOT EXISTS ssh_auth_requests (
    id TEXT PRIMARY KEY,
    src_node_id BIGINT NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
    dst_node_id BIGINT NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
    oidc_state TEXT NOT NULL UNIQUE,
    oidc_nonce TEXT NOT NULL,
    pkce_verifier TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    message TEXT NULL,
    principal_issuer TEXT NULL,
    principal_sub TEXT NULL,
    principal_email TEXT NULL,
    principal_name TEXT NULL,
    ssh_user TEXT NOT NULL DEFAULT '',
    local_user TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ NOT NULL,
    resolved_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ssh_auth_requests_state
    ON ssh_auth_requests (oidc_state);

CREATE INDEX IF NOT EXISTS idx_ssh_auth_requests_expires_at
    ON ssh_auth_requests (expires_at);

CREATE INDEX IF NOT EXISTS idx_ssh_auth_requests_status
    ON ssh_auth_requests (status);

CREATE INDEX IF NOT EXISTS idx_ssh_auth_requests_binding
    ON ssh_auth_requests (src_node_id, dst_node_id, ssh_user, local_user);

CREATE TABLE IF NOT EXISTS ssh_check_approvals (
    src_node_id BIGINT NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
    dst_node_id BIGINT NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
    ssh_user TEXT NOT NULL DEFAULT '',
    local_user TEXT NOT NULL DEFAULT '',
    authenticated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (src_node_id, dst_node_id, ssh_user, local_user)
);

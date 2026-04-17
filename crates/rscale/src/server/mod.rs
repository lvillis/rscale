use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Instant;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::{Extension, Path, Query, Request, State};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, HOST, LOCATION, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, get_service, post};
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use http_body_util::BodyExt as _;
use hyper::body::Incoming;
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper::{Request as HyperRequest, Response as HyperResponse};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::{self, Duration};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{ServerConfig as RustlsServerConfig, pki_types::PrivateKeyDer},
};
use tokio_stream::wrappers::ReceiverStream;
use tower::Service;
use tower_http::services::ServeDir;
use tracing::{info, warn};
use uuid::Uuid;

use crate::app::{AdminHealthResponse, HealthService, LivezResponse, ReadyzResponse};
use crate::config::{AppConfig, ConfigSummary};
use crate::domain::{
    AclPolicy, AuditActor, AuditEvent, AuthKey, BackupRestoreResult, BackupSnapshot, DnsConfig,
    IssuedAuthKey, Node, NodeHeartbeat, NodeMap, NodeRegistration, Route, RouteApproval,
};
use crate::error::{AppError, AppResult};
use crate::infra::auth::break_glass::BreakGlassAuth;
use crate::infra::auth::oidc::OidcRuntime;
use crate::infra::db::{
    CreateAuthKeyInput, CreateNodeInput, CreateRouteInput, PendingSshAuthRequest, PostgresStore,
    RegisterNodeInput, SshAuthRequestStatus, UpdateNodeInput,
};
use crate::infra::derp::{DerpMapRuntime, DerpRuntimeStatus};
use crate::infra::derp_server::{DerpRelaySnapshot, EmbeddedDerpServer};
use crate::protocol::{
    ControlDerpMap, ControlService, DerpAdmitClientRequest, DerpAdmitClientResponse, EarlyNoise,
    MapRequest as ControlMapRequest, MapResponse, OverTlsPublicKeyResponse,
    RegisterRequest as ControlRegisterRequest, accept as accept_noise_connection, encode_json_body,
    encode_map_response_frame, generate_challenge_public_key, incremental_map_response,
    keep_alive_response, machine_public_key_from_private, parse_machine_private_key,
    write_early_payload,
};

const ADMIN_WWW_AUTHENTICATE: &str = "Bearer realm=\"rscale-admin\"";
const NODE_WWW_AUTHENTICATE: &str = "Bearer realm=\"rscale-node\"";
const CONTROL_UPGRADE_PROTOCOL: &str = "tailscale-control-protocol";
const CONTROL_HANDSHAKE_HEADER: &str = "X-Tailscale-Handshake";
const DEFAULT_AUDIT_LIMIT: u32 = 100;
const MAX_AUDIT_LIMIT: u32 = 500;
const CONTROL_BODY_LIMIT: usize = 1024 * 1024;
const VERIFY_BODY_LIMIT: usize = 4 * 1024;
const X_REQUEST_ID: &str = "x-request-id";
const DERP_FAST_START_HEADER: &str = "Derp-Fast-Start";
const INITIAL_HTTP_HEADER_LIMIT: usize = 64 * 1024;

#[derive(Clone)]
struct AppState {
    config: AppConfig,
    health: HealthService,
    config_summary: ConfigSummary,
    config_doctor: serde_json::Value,
    config_has_warnings: bool,
    database: Option<PostgresStore>,
    derp: DerpMapRuntime,
    embedded_derp: Option<EmbeddedDerpServer>,
    control_service: Option<ControlService>,
    oidc: Option<OidcRuntime>,
    control_private_key: [u8; 32],
    control_public_key: String,
    admin_auth: BreakGlassAuth,
    metrics: ServerMetrics,
    tls_acceptor: Option<TlsAcceptor>,
}

impl AppState {
    #[cfg(test)]
    fn without_database(mut config: AppConfig) -> AppResult<Self> {
        if config.server.control_private_key.is_empty() {
            config.server.control_private_key =
                "privkey:1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string();
        }
        if config.auth.break_glass_token.is_none() {
            config.auth.break_glass_token = Some("0123456789abcdef01234567".to_string());
        }
        if config.derp.regions.is_empty()
            && config.derp.urls.is_empty()
            && config.derp.paths.is_empty()
        {
            config.derp.regions.push(crate::config::DerpRegionConfig {
                region_id: 900,
                region_code: "test".to_string(),
                region_name: "Test Region".to_string(),
                nodes: vec![crate::config::DerpNodeConfig {
                    name: "900a".to_string(),
                    host_name: "derp.example.com".to_string(),
                    stun_port: 3478,
                    derp_port: 443,
                    ..crate::config::DerpNodeConfig::default()
                }],
                ..crate::config::DerpRegionConfig::default()
            });
        }

        let control_private_key = parse_machine_private_key(&config.server.control_private_key)?;
        let admin_auth = BreakGlassAuth::from_config(&config.auth)?;
        let derp = DerpMapRuntime::from_static_config(&config.derp);
        let tls_acceptor = build_embedded_tls_acceptor(&config, &derp.effective_map())?;

        Ok(Self {
            config: config.clone(),
            health: HealthService::new(config.clone()),
            config_summary: config.summary(),
            config_doctor: serde_json::json!({}),
            config_has_warnings: false,
            database: None,
            derp,
            embedded_derp: None,
            control_service: None,
            oidc: None,
            control_private_key,
            control_public_key: machine_public_key_from_private(&control_private_key),
            admin_auth,
            metrics: ServerMetrics::new(),
            tls_acceptor,
        })
    }

    fn database(&self) -> Result<&PostgresStore, ApiError> {
        self.database.as_ref().ok_or_else(|| ApiError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "database_unavailable",
            message: "database is not initialized".to_string(),
            www_authenticate: None,
        })
    }

    fn oidc(&self) -> Result<&OidcRuntime, ApiError> {
        self.oidc.as_ref().ok_or_else(|| ApiError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "oidc_unavailable",
            message: "oidc is not initialized".to_string(),
            www_authenticate: None,
        })
    }
}

fn router(state: AppState) -> Router {
    let admin_routes = Router::new()
        .route("/health", get(admin_health))
        .route("/config", get(admin_config))
        .route("/derp-map", get(admin_derp_map))
        .route("/nodes", get(list_nodes).post(create_node))
        .route("/nodes/{id}", get(get_node).patch(update_node))
        .route("/nodes/{id}/disable", post(disable_node))
        .route("/auth-keys", get(list_auth_keys).post(create_auth_key))
        .route("/auth-keys/{id}/revoke", post(revoke_auth_key))
        .route("/routes", get(list_routes).post(create_route))
        .route("/routes/{id}/approve", post(approve_route))
        .route("/routes/{id}/reject", post(reject_route))
        .route("/policy", get(get_policy).put(update_policy))
        .route("/dns", get(get_dns).put(update_dns))
        .route("/audit-events", get(list_audit_events))
        .route("/backup/export", get(export_backup))
        .route("/backup/restore", post(restore_backup))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            admin_authenticate,
        ));

    let mut router = Router::new()
        .route("/livez", get(livez))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .route("/key", get(control_public_key))
        .route("/verify", post(verify_derp_client))
        .route("/bootstrap-dns", get(bootstrap_dns))
        .route("/register/{auth_id}", get(oidc_register))
        .route("/ssh/check/{auth_id}", get(ssh_check_auth))
        .route("/oidc/callback", get(oidc_callback))
        .route("/derp/probe", get(derp_probe).head(derp_probe))
        .route("/derp/latency-check", get(derp_probe).head(derp_probe))
        .route("/generate_204", get(generate_204))
        .route("/api/v1/register/nodes", post(register_node))
        .route("/api/v1/control/nodes/{id}/heartbeat", post(node_heartbeat))
        .route("/api/v1/control/nodes/{id}/map", get(node_map))
        .nest("/api/v1/admin", admin_routes)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            request_context,
        ))
        .with_state(state.clone());

    if let Some(web_root) = state
        .config
        .server
        .web_root
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        router = router.fallback_service(get_service(ServeDir::new(web_root)));
    }

    router
}

pub async fn serve(loaded: tier::LoadedConfig<AppConfig>) -> AppResult<()> {
    let config = loaded.clone().into_inner();
    config.validate()?;

    let admin_auth = BreakGlassAuth::from_config(&config.auth)?;
    let control_private_key = parse_machine_private_key(&config.server.control_private_key)?;
    let control_public_key = machine_public_key_from_private(&control_private_key);
    let database = PostgresStore::connect(&config.database, &config.network).await?;
    let bind_addr = config.bind_addr()?;
    let derp = DerpMapRuntime::bootstrap(&config.derp).await?;
    let effective_derp_map = derp.effective_map();
    let embedded_derp =
        EmbeddedDerpServer::bootstrap(&config.derp, &effective_derp_map, Some(database.clone()))
            .await?;
    let tls_acceptor = build_embedded_tls_acceptor(&config, &effective_derp_map)?;
    let oidc =
        OidcRuntime::from_config(&config.auth.oidc, config.server.public_base_url.as_deref())
            .await?;
    let control_service =
        ControlService::new(config.clone(), database.clone(), derp.clone(), oidc.clone());

    let state = AppState {
        config: config.clone(),
        health: HealthService::new(config.clone()),
        config_summary: config.summary(),
        config_doctor: loaded.report().doctor_json(),
        config_has_warnings: loaded.report().has_warnings(),
        database: Some(database),
        derp,
        embedded_derp,
        control_service: Some(control_service),
        oidc,
        control_private_key,
        control_public_key,
        admin_auth,
        metrics: ServerMetrics::new(),
        tls_acceptor,
    };
    let app = router(state.clone());
    let listener = TcpListener::bind(bind_addr).await?;

    info!(%bind_addr, "rscale server listening");

    serve_http(listener, app, state).await
}

fn build_embedded_tls_acceptor(
    config: &AppConfig,
    effective_derp_map: &ControlDerpMap,
) -> AppResult<Option<TlsAcceptor>> {
    if !embedded_tls_required(config, effective_derp_map) {
        return Ok(None);
    }

    let mut subject_alt_names =
        BTreeSet::from(["localhost".to_string(), "host.docker.internal".to_string()]);
    for region in &config.derp.regions {
        for node in &region.nodes {
            let host_name = node.host_name.trim();
            if !host_name.is_empty() && !host_name.contains(':') {
                subject_alt_names.insert(host_name.to_string());
            }
        }
    }

    let CertifiedKey { cert, signing_key } = generate_simple_self_signed(
        subject_alt_names.into_iter().collect::<Vec<_>>(),
    )
    .map_err(|err| {
        AppError::Bootstrap(format!(
            "failed to generate embedded TLS certificate: {err}"
        ))
    })?;
    let private_key = PrivateKeyDer::try_from(signing_key.serialize_der()).map_err(|err| {
        AppError::Bootstrap(format!("failed to build embedded TLS private key: {err}"))
    })?;
    let tls_config = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], private_key)
        .map_err(|err| {
            AppError::Bootstrap(format!("failed to build embedded TLS config: {err}"))
        })?;

    warn!(
        "embedded TLS is enabled with a generated self-signed certificate; prefer trusted TLS termination for production"
    );

    Ok(Some(TlsAcceptor::from(Arc::new(tls_config))))
}

fn embedded_tls_required(config: &AppConfig, effective_derp_map: &ControlDerpMap) -> bool {
    if !config.derp.server.enabled {
        return false;
    }

    let configured_node_name = config
        .derp
        .server
        .node_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if let Some(node_name) = configured_node_name
        && let Some(node) = effective_derp_map
            .regions
            .values()
            .flat_map(|region| region.nodes.iter())
            .find(|node| node.name == node_name)
    {
        return !node.stun_only;
    }

    effective_derp_map
        .regions
        .values()
        .flat_map(|region| region.nodes.iter())
        .any(|node| !node.stun_only)
}

async fn stream_looks_like_tls(stream: &TcpStream) -> AppResult<bool> {
    let mut prefix = [0_u8; 3];
    let read = stream.peek(&mut prefix).await?;
    if read == 0 {
        return Ok(false);
    }
    if prefix[0] != 0x16 {
        return Ok(false);
    }
    if read < 3 {
        return Ok(true);
    }
    Ok(prefix[1] == 0x03 && (0x01..=0x04).contains(&prefix[2]))
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

async fn serve_http(listener: TcpListener, app: Router, state: AppState) -> AppResult<()> {
    let mut shutdown = Box::pin(shutdown_signal());

    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let (stream, remote_addr) = accepted?;
                let app = app.clone();
                let state = state.clone();

                tokio::spawn(async move {
                    if let Err(err) = serve_http_connection(stream, remote_addr, app, state).await {
                        warn!(%remote_addr, error = ?err, "HTTP connection failed");
                    }
                });
            }
        }
    }

    Ok(())
}

async fn serve_http_connection(
    stream: TcpStream,
    remote_addr: SocketAddr,
    app: Router,
    state: AppState,
) -> AppResult<()> {
    if stream_looks_like_tls(&stream).await? {
        let Some(acceptor) = state.tls_acceptor.clone() else {
            return Err(AppError::InvalidRequest(
                "received TLS connection but embedded TLS is not enabled".to_string(),
            ));
        };
        let tls_stream = acceptor.accept(stream).await.map_err(|err| {
            AppError::Bootstrap(format!("failed to accept TLS connection: {err}"))
        })?;
        return serve_http_stream_connection(tls_stream, remote_addr, app, state).await;
    }

    serve_http_stream_connection(stream, remote_addr, app, state).await
}

async fn serve_http_stream_connection<S>(
    mut stream: S,
    remote_addr: SocketAddr,
    app: Router,
    state: AppState,
) -> AppResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let initial_request = read_initial_http_request(&mut stream).await?;
    if initial_request.path_only() == "/derp" {
        return serve_derp_connection(stream, remote_addr, state, initial_request).await;
    }
    if initial_request.path_only() == "/ts2021" {
        return serve_ts2021_connection(stream, state, initial_request).await;
    }

    let service = service_fn(move |request: HyperRequest<Incoming>| {
        let app = app.clone();
        let state = state.clone();
        async move { handle_http_request(request, app, state).await }
    });

    let io = TokioIo::new(PrefixedStream::new(stream, initial_request.raw));
    http1::Builder::new()
        .serve_connection(io, service)
        .with_upgrades()
        .await
        .map_err(|err| AppError::Bootstrap(format!("failed to serve HTTP/1 connection: {err}")))
}

async fn serve_derp_connection<S>(
    stream: S,
    remote_addr: SocketAddr,
    state: AppState,
    request: InitialHttpRequest,
) -> AppResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if request.method != Method::GET.as_str() {
        let mut stream = stream;
        write_raw_http_error(
            &mut stream,
            StatusCode::METHOD_NOT_ALLOWED,
            "DERP relay only accepts GET requests",
        )
        .await?;
        return Ok(());
    }

    let Some(embedded_derp) = state.embedded_derp.clone() else {
        let mut stream = stream;
        write_raw_http_error(
            &mut stream,
            StatusCode::SERVICE_UNAVAILABLE,
            "DERP relay is not enabled",
        )
        .await?;
        return Ok(());
    };

    let upgrade = request.header("upgrade").unwrap_or_default();
    if upgrade.eq_ignore_ascii_case("websocket") {
        let prefixed = PrefixedStream::new(stream, request.raw);
        return embedded_derp
            .serve_websocket_connection(prefixed, remote_addr)
            .await;
    }

    if !upgrade.eq_ignore_ascii_case("derp") {
        let mut stream = stream;
        write_raw_http_error(
            &mut stream,
            StatusCode::UPGRADE_REQUIRED,
            "DERP requires connection upgrade",
        )
        .await?;
        return Ok(());
    }

    let fast_start = request
        .header(DERP_FAST_START_HEADER)
        .is_some_and(|value| value == "1");
    embedded_derp
        .serve_plain_connection(stream, remote_addr, fast_start)
        .await
}

async fn serve_ts2021_connection<S>(
    mut stream: S,
    state: AppState,
    request: InitialHttpRequest,
) -> AppResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if request.method != Method::POST.as_str() {
        write_raw_http_error(
            &mut stream,
            StatusCode::METHOD_NOT_ALLOWED,
            "TS2021 control endpoint only accepts POST requests",
        )
        .await?;
        return Ok(());
    }

    let upgrade = request.header("upgrade").unwrap_or_default();
    if !upgrade.eq_ignore_ascii_case(CONTROL_UPGRADE_PROTOCOL) {
        write_raw_http_error(
            &mut stream,
            StatusCode::BAD_REQUEST,
            "missing or unsupported TS2021 Upgrade header",
        )
        .await?;
        return Ok(());
    }

    let Some(handshake_header) = request.header(CONTROL_HANDSHAKE_HEADER) else {
        write_raw_http_error(
            &mut stream,
            StatusCode::BAD_REQUEST,
            "missing X-Tailscale-Handshake header",
        )
        .await?;
        return Ok(());
    };

    let initial_handshake = match BASE64_STANDARD.decode(handshake_header) {
        Ok(value) => value,
        Err(_) => {
            write_raw_http_error(
                &mut stream,
                StatusCode::BAD_REQUEST,
                "X-Tailscale-Handshake header must be valid base64",
            )
            .await?;
            return Ok(());
        }
    };

    let Some(control_service) = state.control_service.clone() else {
        write_raw_http_error(
            &mut stream,
            StatusCode::SERVICE_UNAVAILABLE,
            "control service is not initialized",
        )
        .await?;
        return Ok(());
    };

    write_raw_http_switching_protocols(&mut stream, CONTROL_UPGRADE_PROTOCOL).await?;

    let upgraded = PrefixedStream::new(stream, request.trailing);

    serve_control_connection(
        upgraded,
        state.control_private_key,
        control_service,
        initial_handshake,
        state.config,
    )
    .await
}

async fn handle_http_request(
    request: HyperRequest<Incoming>,
    app: Router,
    _state: AppState,
) -> Result<HyperResponse<Body>, std::convert::Infallible> {
    let response = match app.clone().call(request).await {
        Ok(response) => response,
        Err(err) => {
            warn!(error = %err, "application router returned an unexpected error");
            text_response(StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
        }
    };

    Ok(response)
}

async fn read_initial_http_request<S>(stream: &mut S) -> AppResult<InitialHttpRequest>
where
    S: AsyncRead + Unpin,
{
    let mut raw = Vec::with_capacity(2048);
    let mut buffer = [0_u8; 2048];

    loop {
        if let Some(header_end) = find_http_header_end(&raw) {
            return parse_initial_http_request(raw, header_end);
        }

        if raw.len() >= INITIAL_HTTP_HEADER_LIMIT {
            return Err(AppError::InvalidRequest(format!(
                "HTTP request headers exceed limit of {INITIAL_HTTP_HEADER_LIMIT} bytes"
            )));
        }

        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            return Err(AppError::InvalidRequest(
                "client closed the connection before sending complete HTTP headers".to_string(),
            ));
        }
        raw.extend_from_slice(&buffer[..read]);
    }
}

fn parse_initial_http_request(raw: Vec<u8>, header_end: usize) -> AppResult<InitialHttpRequest> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut headers);
    request
        .parse(&raw[..header_end])
        .map_err(|err| AppError::InvalidRequest(format!("failed to parse HTTP request: {err}")))?;

    let method = request
        .method
        .ok_or_else(|| AppError::InvalidRequest("HTTP request method is missing".to_string()))?
        .to_string();
    let path = request
        .path
        .ok_or_else(|| AppError::InvalidRequest("HTTP request path is missing".to_string()))?
        .to_string();

    let parsed_headers = request
        .headers
        .iter()
        .map(|header| {
            let name = header.name.to_ascii_lowercase();
            let value = String::from_utf8_lossy(header.value).trim().to_string();
            (name, value)
        })
        .collect();

    let trailing = raw[header_end..].to_vec();

    Ok(InitialHttpRequest {
        raw,
        trailing,
        method,
        path,
        headers: parsed_headers,
    })
}

fn find_http_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

async fn write_raw_http_error<S>(stream: &mut S, status: StatusCode, body: &str) -> AppResult<()>
where
    S: AsyncWrite + Unpin,
{
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status.as_u16(),
        status.canonical_reason().unwrap_or("Error"),
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}

async fn write_raw_http_switching_protocols<S>(
    stream: &mut S,
    upgrade_protocol: &str,
) -> AppResult<()>
where
    S: AsyncWrite + Unpin,
{
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: {upgrade_protocol}\r\nConnection: upgrade\r\n\r\n"
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

#[derive(Debug)]
struct InitialHttpRequest {
    raw: Vec<u8>,
    trailing: Vec<u8>,
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
}

impl InitialHttpRequest {
    fn path_only(&self) -> &str {
        self.path
            .split_once('?')
            .map_or(self.path.as_str(), |(path, _)| path)
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }
}

struct PrefixedStream<T> {
    prefix: Cursor<Vec<u8>>,
    inner: T,
}

impl<T> PrefixedStream<T> {
    fn new(inner: T, prefix: Vec<u8>) -> Self {
        Self {
            prefix: Cursor::new(prefix),
            inner,
        }
    }
}

struct TapIo<T> {
    inner: T,
    read_prefix: Arc<Mutex<Vec<u8>>>,
    limit: usize,
}

impl<T> TapIo<T> {
    fn new(inner: T, read_prefix: Arc<Mutex<Vec<u8>>>, limit: usize) -> Self {
        Self {
            inner,
            read_prefix,
            limit,
        }
    }

    fn capture(&self, bytes: &[u8]) {
        let Ok(mut prefix) = self.read_prefix.lock() else {
            return;
        };
        if prefix.len() >= self.limit {
            return;
        }
        let remaining = self.limit - prefix.len();
        prefix.extend_from_slice(&bytes[..bytes.len().min(remaining)]);
    }
}

impl<T> AsyncRead for TapIo<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let after = buf.filled().len();
                if after > before {
                    self.capture(&buf.filled()[before..after]);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<T> AsyncWrite for TapIo<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn debug_read_prefix(prefix: &Arc<Mutex<Vec<u8>>>) -> String {
    let Ok(prefix) = prefix.lock() else {
        return "<poisoned>".to_string();
    };
    if prefix.is_empty() {
        return "<empty>".to_string();
    }

    let hex = prefix
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    let ascii = String::from_utf8_lossy(&prefix)
        .chars()
        .map(|ch| if ch.is_control() { '.' } else { ch })
        .collect::<String>();
    format!("hex=[{hex}] ascii={ascii:?}")
}

impl<T> AsyncRead for PrefixedStream<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let position = self.prefix.position();
        let remaining = self.prefix.get_ref().len() as u64 - position;
        if remaining > 0 {
            let start = position as usize;
            let available = &self.prefix.get_ref()[start..];
            let read = available.len().min(buf.remaining());
            buf.put_slice(&available[..read]);
            self.prefix.set_position(position + read as u64);
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T> AsyncWrite for PrefixedStream<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn serve_control_connection<T>(
    upgraded: T,
    control_private_key: [u8; 32],
    control_service: ControlService,
    initial_handshake: Vec<u8>,
    config: AppConfig,
) -> AppResult<()>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let accepted =
        accept_noise_connection(upgraded, &control_private_key, &initial_handshake).await?;
    let machine_public_key = accepted.machine_public_key.clone();
    let protocol_version = accepted.protocol_version;
    let mut transport = accepted.transport;

    write_early_payload(
        &mut transport,
        &EarlyNoise {
            node_key_challenge: generate_challenge_public_key()?,
        },
    )
    .await?;

    let service = service_fn(move |request: HyperRequest<Incoming>| {
        let control_service = control_service.clone();
        let machine_public_key = machine_public_key.clone();
        let config = config.clone();
        async move {
            handle_control_request(
                request,
                control_service,
                machine_public_key,
                protocol_version,
                config,
            )
            .await
        }
    });
    let read_prefix = Arc::new(Mutex::new(Vec::new()));
    let transport = TapIo::new(transport, read_prefix.clone(), 64);

    http2::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(transport), service)
        .await
        .map_err(|err| {
            let prefix = debug_read_prefix(&read_prefix);
            AppError::Bootstrap(format!(
                "failed to serve HTTP/2 control session: {err:?}; first_client_bytes={prefix}"
            ))
        })?;

    Ok(())
}

async fn handle_control_request(
    request: HyperRequest<Incoming>,
    control_service: ControlService,
    machine_public_key: String,
    protocol_version: u16,
    config: AppConfig,
) -> Result<HyperResponse<Body>, std::convert::Infallible> {
    let advertised_derp_host = request_authority_host(&request).map(str::to_string);
    let ssh_action_path = parse_ssh_action_path(request.uri().path());
    let response = match (request.method(), request.uri().path()) {
        (&Method::POST, "/machine/register") => {
            match decode_json_request::<ControlRegisterRequest>(request).await {
                Ok(register_request) => json_response(
                    StatusCode::OK,
                    control_service
                        .register(&machine_public_key, register_request)
                        .await,
                ),
                Err(err) => control_error_response(err),
            }
        }
        (&Method::POST, "/machine/map") => {
            match decode_json_request::<ControlMapRequest>(request).await {
                Ok(map_request) => {
                    let node = match control_service
                        .prepare_map_node(&machine_public_key, &map_request)
                        .await
                    {
                        Ok(node) => node,
                        Err(err) => return Ok(control_error_response(err)),
                    };

                    if !map_request.stream && map_request.omit_peers && !map_request.read_only {
                        empty_response(StatusCode::OK)
                    } else if map_request.stream {
                        match build_streaming_map_body(
                            control_service,
                            node.node.id,
                            advertised_derp_host.clone(),
                            map_request.compress.clone(),
                            map_request.keep_alive,
                            config.server.map_poll_interval_secs,
                            config.server.map_keepalive_interval_secs,
                        )
                        .await
                        {
                            Ok(body) => body_response(StatusCode::OK, body),
                            Err(err) => control_error_response(err),
                        }
                    } else {
                        match control_service
                            .build_one_shot_map(
                                node.node.id,
                                1,
                                None,
                                advertised_derp_host.as_deref(),
                            )
                            .await
                            .and_then(|response| {
                                encode_map_response_frame(&response, &map_request.compress)
                            }) {
                            Ok(frame) => body_response(StatusCode::OK, Body::from(frame)),
                            Err(err) => control_error_response(err),
                        }
                    }
                }
                Err(err) => control_error_response(err),
            }
        }
        (&Method::GET, "/machine/whoami") => {
            let body = format!(
                "{{\"machineKey\":\"{}\",\"protocolVersion\":{}}}",
                machine_public_key, protocol_version
            );
            json_body_response(StatusCode::OK, Body::from(body))
        }
        (&Method::GET, _) if ssh_action_path.is_some() => {
            let Some((src_node_id, dst_node_id)) = ssh_action_path else {
                return Ok(control_error_response(AppError::InvalidRequest(
                    "invalid SSH action path".to_string(),
                )));
            };
            let query = match decode_query::<ControlSshActionQuery>(request.uri().query()) {
                Ok(query) => query,
                Err(err) => return Ok(control_error_response(err)),
            };
            json_response(
                StatusCode::OK,
                control_service
                    .resolve_ssh_action(
                        &machine_public_key,
                        src_node_id,
                        dst_node_id,
                        query.auth_id.as_deref(),
                        query.ssh_user.as_deref(),
                        query.local_user.as_deref(),
                    )
                    .await,
            )
        }
        _ => text_response(StatusCode::NOT_FOUND, "control endpoint not found"),
    };

    Ok(response)
}

async fn build_streaming_map_body(
    control_service: ControlService,
    node_id: u64,
    advertised_derp_host: Option<String>,
    compress: String,
    _client_requested_keep_alive: bool,
    poll_interval_secs: u64,
    keepalive_interval_secs: u64,
) -> AppResult<Body> {
    let (_session_handle, initial_response, mut last_signature) = control_service
        .build_stream_state(node_id, 1, advertised_derp_host.as_deref())
        .await?;
    let initial_frame = encode_map_response_frame(&initial_response, &compress)?;
    let mut last_full_response = initial_response.clone();
    let (sender, receiver) = mpsc::channel::<Result<Vec<u8>, std::io::Error>>(8);
    let mut control_updates = control_service.subscribe_map_updates();
    sender
        .send(Ok(initial_frame))
        .await
        .map_err(|_| AppError::Bootstrap("failed to enqueue initial map response".to_string()))?;

    tokio::spawn(async move {
        let mut next_seq = 2_i64;
        let mut poll_tick = time::interval(Duration::from_secs(poll_interval_secs));
        let mut keepalive_tick = time::interval(Duration::from_secs(keepalive_interval_secs));
        let update_context = StreamUpdateContext {
            sender: &sender,
            control_service: &control_service,
            node_id,
            advertised_derp_host: advertised_derp_host.as_deref(),
            compress: &compress,
        };
        poll_tick.tick().await;
        keepalive_tick.tick().await;

        loop {
            tokio::select! {
                changed = control_updates.changed() => {
                    match changed {
                        Ok(()) => {
                            match enqueue_stream_update(
                                &update_context,
                                next_seq,
                                &mut last_full_response,
                                &mut last_signature,
                            ).await {
                                StreamUpdateOutcome::Sent => {
                                    next_seq += 1;
                                }
                                StreamUpdateOutcome::Unchanged => {}
                                StreamUpdateOutcome::Failed => break,
                            }
                        }
                        Err(_) => break,
                    }
                }
                _ = poll_tick.tick() => {
                    match enqueue_stream_update(
                        &update_context,
                        next_seq,
                        &mut last_full_response,
                        &mut last_signature,
                    ).await {
                        StreamUpdateOutcome::Sent => {
                            next_seq += 1;
                        }
                        StreamUpdateOutcome::Unchanged => {}
                        StreamUpdateOutcome::Failed => break,
                    }
                }
                _ = keepalive_tick.tick() => {
                    let keepalive = keep_alive_response();
                    match encode_map_response_frame(&keepalive, &compress) {
                        Ok(frame) => {
                            if sender.send(Ok(frame)).await.is_err() {
                                break;
                            }
                        }
                        Err(err) => {
                            let _ = sender.send(Err(std::io::Error::other(err.to_string()))).await;
                            break;
                        }
                    }
                }
            }
        }
    });

    Ok(Body::from_stream(ReceiverStream::new(receiver)))
}

async fn enqueue_stream_update(
    context: &StreamUpdateContext<'_>,
    seq: i64,
    last_full_response: &mut MapResponse,
    last_signature: &mut Vec<u8>,
) -> StreamUpdateOutcome {
    match context
        .control_service
        .refresh_stream_state(context.node_id, seq, context.advertised_derp_host)
        .await
    {
        Ok((response, signature)) => {
            if signature == *last_signature {
                return StreamUpdateOutcome::Unchanged;
            }

            let Some(delta) = incremental_map_response(last_full_response, &response) else {
                *last_signature = signature;
                *last_full_response = response;
                return StreamUpdateOutcome::Unchanged;
            };

            match encode_map_response_frame(&delta, context.compress) {
                Ok(frame) => {
                    if context.sender.send(Ok(frame)).await.is_err() {
                        return StreamUpdateOutcome::Failed;
                    }
                    *last_signature = signature;
                    *last_full_response = response;
                    StreamUpdateOutcome::Sent
                }
                Err(err) => {
                    let _ = context
                        .sender
                        .send(Err(std::io::Error::other(err.to_string())))
                        .await;
                    StreamUpdateOutcome::Failed
                }
            }
        }
        Err(err) => {
            let _ = context
                .sender
                .send(Err(std::io::Error::other(err.to_string())))
                .await;
            StreamUpdateOutcome::Failed
        }
    }
}

enum StreamUpdateOutcome {
    Sent,
    Unchanged,
    Failed,
}

struct StreamUpdateContext<'a> {
    sender: &'a mpsc::Sender<Result<Vec<u8>, std::io::Error>>,
    control_service: &'a ControlService,
    node_id: u64,
    advertised_derp_host: Option<&'a str>,
    compress: &'a str,
}

async fn decode_json_request<T: serde::de::DeserializeOwned>(
    request: HyperRequest<Incoming>,
) -> AppResult<T> {
    let body = request
        .into_body()
        .collect()
        .await
        .map_err(|err| AppError::InvalidRequest(format!("failed to read request body: {err}")))?
        .to_bytes();
    if body.len() > CONTROL_BODY_LIMIT {
        return Err(AppError::InvalidRequest(format!(
            "request body exceeds limit of {CONTROL_BODY_LIMIT} bytes"
        )));
    }
    serde_json::from_slice::<T>(&body)
        .map_err(|err| AppError::InvalidRequest(format!("failed to decode request JSON: {err}")))
}

fn decode_query<T>(query: Option<&str>) -> AppResult<T>
where
    T: serde::de::DeserializeOwned + Default,
{
    match query {
        Some(query) if !query.is_empty() => serde_urlencoded::from_str::<T>(query).map_err(|err| {
            AppError::InvalidRequest(format!("failed to decode request query: {err}"))
        }),
        _ => Ok(T::default()),
    }
}

fn parse_ssh_action_path(path: &str) -> Option<(u64, u64)> {
    let path = path.trim_matches('/');
    let parts = path.split('/').collect::<Vec<_>>();
    if parts.len() != 7
        || parts[0] != "machine"
        || parts[1] != "ssh"
        || parts[2] != "action"
        || parts[3] != "from"
        || parts[5] != "to"
    {
        return None;
    }

    let src_node_id = parts[4].parse::<u64>().ok()?;
    let dst_node_id = parts[6].parse::<u64>().ok()?;
    Some((src_node_id, dst_node_id))
}

fn request_authority_host(request: &HyperRequest<Incoming>) -> Option<&str> {
    request
        .uri()
        .authority()
        .map(|authority| authority.host())
        .or_else(|| {
            request
                .headers()
                .get(HOST)
                .and_then(|value| value.to_str().ok())
                .and_then(authority_host)
        })
}

fn authority_host(value: &str) -> Option<&str> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    if let Some(stripped) = value.strip_prefix('[') {
        return stripped.split_once(']').map(|(host, _)| host);
    }

    if let Some((host, port)) = value.rsplit_once(':')
        && !host.contains(':')
        && port.parse::<u16>().is_ok()
    {
        return Some(host);
    }

    Some(value)
}

fn control_error_response(error: AppError) -> HyperResponse<Body> {
    let status = match error {
        AppError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
        AppError::InvalidRequest(_) | AppError::InvalidConfig(_) | AppError::Json(_) => {
            StatusCode::BAD_REQUEST
        }
        AppError::NotFound(_) => StatusCode::NOT_FOUND,
        AppError::Conflict(_) => StatusCode::CONFLICT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };

    text_response(status, error.to_string())
}

fn json_response<T>(status: StatusCode, result: AppResult<T>) -> HyperResponse<Body>
where
    T: Serialize,
{
    match result.and_then(|value| encode_json_body(&value)) {
        Ok(body) => json_body_response(status, Body::from(body)),
        Err(err) => control_error_response(err),
    }
}

fn text_response(status: StatusCode, body: impl Into<String>) -> HyperResponse<Body> {
    body_response(status, Body::from(body.into()))
}

fn body_response(status: StatusCode, body: Body) -> HyperResponse<Body> {
    let mut response = HyperResponse::new(body);
    *response.status_mut() = status;
    response
}

fn empty_response(status: StatusCode) -> HyperResponse<Body> {
    body_response(status, Body::empty())
}

fn json_body_response(status: StatusCode, body: Body) -> HyperResponse<Body> {
    let mut response = body_response(status, body);
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

fn now_unix_secs() -> AppResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|err| AppError::Bootstrap(format!("system clock is before unix epoch: {err}")))
}

fn html_response(status: StatusCode, body: impl Into<String>) -> Response {
    let mut response = body_response(status, Body::from(body.into()));
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response
}

fn success_page_html() -> &'static str {
    "<!doctype html><html><head><meta charset=\"utf-8\"><title>rscale login complete</title></head><body><h1>Authentication complete</h1><p>You can return to the Tailscale client.</p></body></html>"
}

fn failure_page_html(message: &str) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>rscale login failed</title></head><body><h1>Authentication failed</h1><p>{}</p></body></html>",
        html_escape(message)
    )
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

async fn request_context(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let request_id = Uuid::new_v4().to_string();
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let started_at = Instant::now();

    request.extensions_mut().insert(RequestContext {
        request_id: request_id.clone(),
    });

    let mut response = next.run(request).await;
    let status = response.status();
    let latency_ms = started_at.elapsed().as_millis() as u64;

    if let Ok(header_value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert(X_REQUEST_ID, header_value);
    }

    state.metrics.record_request(status);
    info!(
        request_id = %request_id,
        method = %method,
        path = %path,
        status = status.as_u16(),
        latency_ms,
        "request completed"
    );

    response
}

async fn admin_authenticate(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let request_id = request
        .extensions()
        .get::<RequestContext>()
        .map(|context| context.request_id.clone());

    let Some(token) = extract_bearer_token(request.headers()) else {
        state.metrics.record_admin_auth_failure();
        if let Some(request_id) = request_id.as_deref() {
            warn!(request_id, "administrator authentication header missing");
        }
        return ApiError::unauthorized("administrator authentication required").into_response();
    };

    match state.admin_auth.authenticate_bearer(token) {
        Ok(actor) => {
            request.extensions_mut().insert(actor);
            next.run(request).await
        }
        Err(_) => {
            state.metrics.record_admin_auth_failure();
            if let Some(request_id) = request_id.as_deref() {
                warn!(request_id, "administrator authentication failed");
            }
            ApiError::unauthorized("administrator authentication failed").into_response()
        }
    }
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    let header = headers.get(AUTHORIZATION)?.to_str().ok()?;
    header.strip_prefix("Bearer ")
}

async fn livez(State(state): State<AppState>) -> Json<LivezResponse> {
    Json(state.health.livez())
}

async fn readyz(State(state): State<AppState>) -> (StatusCode, Json<ReadyzResponse>) {
    let database_ready = match &state.database {
        Some(database) => database.ping().await.is_ok(),
        None => false,
    };

    let payload = Json(state.health.readyz(database_ready));
    let status = if database_ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status, payload)
}

async fn metrics(State(state): State<AppState>) -> (StatusCode, String) {
    let (database_ready, node_count, audit_event_count, active_auth_key_count, route_count) =
        match &state.database {
            Some(database) => {
                let database_ready = database.ping().await.is_ok();
                let node_count = if database_ready {
                    metric_count_or_zero("nodes", database.count_nodes().await)
                } else {
                    0
                };
                let audit_event_count = if database_ready {
                    metric_count_or_zero("audit_events", database.count_audit_events().await)
                } else {
                    0
                };
                let active_auth_key_count = if database_ready {
                    metric_count_or_zero(
                        "active_auth_keys",
                        database.count_active_auth_keys().await,
                    )
                } else {
                    0
                };
                let route_count = if database_ready {
                    metric_count_or_zero("routes", database.count_routes().await)
                } else {
                    0
                };

                (
                    database_ready,
                    node_count,
                    audit_event_count,
                    active_auth_key_count,
                    route_count,
                )
            }
            None => (false, 0, 0, 0, 0),
        };
    let derp_status = state.derp.status();
    let derp_relay = state
        .embedded_derp
        .as_ref()
        .map(EmbeddedDerpServer::metrics_snapshot)
        .unwrap_or_default();

    let body = state.metrics.render(MetricsSnapshot {
        config_has_warnings: state.config_has_warnings,
        database_ready,
        node_count,
        audit_event_count,
        active_auth_key_count,
        route_count,
        derp_region_count: derp_status.effective_region_count,
        derp_source_count: derp_status.source_count,
        derp_refresh_failures_total: derp_status.refresh_failures_total,
        derp_last_refresh_success_unix_secs: derp_status
            .last_refresh_success_unix_secs
            .unwrap_or_default(),
        derp_relay,
    });

    (StatusCode::OK, body)
}

async fn control_public_key(State(state): State<AppState>) -> Json<OverTlsPublicKeyResponse> {
    Json(OverTlsPublicKeyResponse {
        public_key: state.control_public_key.clone(),
        ..OverTlsPublicKeyResponse::default()
    })
}

async fn verify_derp_client(
    State(state): State<AppState>,
    request: Request,
) -> Result<Json<DerpAdmitClientResponse>, ApiError> {
    let database = state.database()?;
    let body = request
        .into_body()
        .collect()
        .await
        .map_err(|err| {
            ApiError::from(AppError::InvalidRequest(format!(
                "failed to read request body: {err}"
            )))
        })?
        .to_bytes();

    if body.len() > VERIFY_BODY_LIMIT {
        return Err(ApiError {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            code: "payload_too_large",
            message: format!("verify request body exceeds limit of {VERIFY_BODY_LIMIT} bytes"),
            www_authenticate: None,
        });
    }

    let request = serde_json::from_slice::<DerpAdmitClientRequest>(&body).map_err(|err| {
        ApiError::from(AppError::InvalidRequest(format!(
            "failed to decode DERP verify request JSON: {err}"
        )))
    })?;
    let allow = database
        .allows_derp_client(&request.node_public)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(DerpAdmitClientResponse { allow }))
}

async fn bootstrap_dns(
    State(state): State<AppState>,
    Query(query): Query<BootstrapDnsQuery>,
) -> Json<BTreeMap<String, Vec<String>>> {
    Json(
        resolve_bootstrap_dns(
            &state.derp,
            state.config.server.public_base_url.as_deref(),
            query.q.as_deref(),
        )
        .await,
    )
}

fn metric_count_or_zero(metric: &str, result: AppResult<u64>) -> u64 {
    match result {
        Ok(count) => count,
        Err(error) => {
            warn!(metric, %error, "failed to collect metric count; using zero");
            0
        }
    }
}

async fn oidc_register(
    State(state): State<AppState>,
    Path(auth_id): Path<String>,
) -> Result<Response, ApiError> {
    let database = state.database()?;
    let oidc = state.oidc()?;
    let pending = database
        .get_oidc_auth_request(&auth_id)
        .await
        .map_err(ApiError::from)?;

    if pending.completed_at_unix_secs.is_some() {
        return Ok(html_response(StatusCode::OK, success_page_html()));
    }

    let redirect = oidc
        .authorization_redirect_url(&pending)
        .map_err(ApiError::from)?;
    let location = HeaderValue::from_str(&redirect).map_err(|err| ApiError {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        code: "invalid_redirect_url",
        message: format!("failed to build OIDC redirect URL: {err}"),
        www_authenticate: None,
    })?;

    Ok(redirect_response(location))
}

async fn ssh_check_auth(
    State(state): State<AppState>,
    Path(auth_id): Path<String>,
) -> Result<Response, ApiError> {
    let database = state.database()?;
    let oidc = state.oidc()?;
    let pending = database
        .get_ssh_auth_request(&auth_id)
        .await
        .map_err(ApiError::from)?;

    match pending.status {
        SshAuthRequestStatus::Approved => {
            return Ok(html_response(StatusCode::OK, success_page_html()));
        }
        SshAuthRequestStatus::Rejected => {
            return Ok(html_response(
                StatusCode::FORBIDDEN,
                failure_page_html(
                    pending
                        .message
                        .as_deref()
                        .unwrap_or("SSH authentication was rejected"),
                ),
            ));
        }
        SshAuthRequestStatus::Pending => {}
    }
    if now_unix_secs().map_err(ApiError::from)? >= pending.expires_at_unix_secs {
        return Ok(html_response(
            StatusCode::FORBIDDEN,
            failure_page_html("SSH authentication request expired"),
        ));
    }

    let redirect = oidc
        .authorization_redirect_url_for_flow(
            &pending.oidc_state,
            &pending.oidc_nonce,
            &pending.pkce_verifier,
        )
        .map_err(ApiError::from)?;
    let location = HeaderValue::from_str(&redirect).map_err(|err| ApiError {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        code: "invalid_redirect_url",
        message: format!("failed to build OIDC redirect URL: {err}"),
        www_authenticate: None,
    })?;

    Ok(redirect_response(location))
}

fn redirect_response(location: HeaderValue) -> Response {
    let mut response = empty_response(StatusCode::FOUND);
    response.headers_mut().insert(LOCATION, location);
    response
}

async fn oidc_callback(
    State(state): State<AppState>,
    Query(query): Query<OidcCallbackQuery>,
) -> Result<Response, ApiError> {
    if let Some(error) = query.error.as_deref() {
        let description = query.error_description.unwrap_or_default();
        if let Some(state_param) = query.state.as_deref()
            && let Ok(database) = state.database()
            && let Ok(pending) = database.find_ssh_auth_request_by_state(state_param).await
        {
            let _ = database
                .reject_ssh_auth_request(
                    &pending.auth_id,
                    &format!("OIDC provider returned {error}: {description}"),
                )
                .await;
        }
        return Ok(html_response(
            StatusCode::BAD_REQUEST,
            failure_page_html(&format!("OIDC provider returned {error}: {description}")),
        ));
    }

    let state_param = query.state.ok_or_else(|| ApiError {
        status: StatusCode::BAD_REQUEST,
        code: "missing_oidc_state",
        message: "missing OIDC state parameter".to_string(),
        www_authenticate: None,
    })?;
    let code = query.code.ok_or_else(|| ApiError {
        status: StatusCode::BAD_REQUEST,
        code: "missing_oidc_code",
        message: "missing OIDC authorization code".to_string(),
        www_authenticate: None,
    })?;

    let database = state.database()?;
    let oidc = state.oidc()?;
    match database.find_ssh_auth_request_by_state(&state_param).await {
        Ok(pending) => {
            return complete_ssh_check_callback(database, oidc, &pending, &code).await;
        }
        Err(AppError::NotFound(_)) => {}
        Err(err) => return Err(ApiError::from(err)),
    }

    let pending = database
        .find_oidc_auth_request_by_state(&state_param)
        .await
        .map_err(ApiError::from)?;
    let principal = oidc
        .complete_authorization(&pending, &code)
        .await
        .map_err(ApiError::from)?;
    let _ = database
        .complete_oidc_auth_request(&pending.auth_id, &principal)
        .await
        .map_err(ApiError::from)?;

    Ok(html_response(StatusCode::OK, success_page_html()))
}

async fn complete_ssh_check_callback(
    database: &PostgresStore,
    oidc: &OidcRuntime,
    pending: &PendingSshAuthRequest,
    code: &str,
) -> Result<Response, ApiError> {
    let principal = oidc
        .complete_authorization_for_flow(&pending.oidc_nonce, &pending.pkce_verifier, code)
        .await
        .map_err(ApiError::from)?;
    let src_node = database
        .get_control_node(pending.src_node_id)
        .await
        .map_err(ApiError::from)?;
    let Some(owner) = src_node.principal else {
        let message = "SSH check source node has no OIDC owner";
        let _ = database
            .reject_ssh_auth_request(&pending.auth_id, message)
            .await;
        return Ok(html_response(
            StatusCode::FORBIDDEN,
            failure_page_html(message),
        ));
    };

    if owner.provider != "oidc"
        || owner.issuer.as_deref() != Some(principal.issuer.as_str())
        || owner.subject.as_deref() != Some(principal.subject.as_str())
    {
        let message = "OIDC user is not the owner of the SSH source node";
        let _ = database
            .reject_ssh_auth_request(&pending.auth_id, message)
            .await;
        return Ok(html_response(
            StatusCode::FORBIDDEN,
            failure_page_html(message),
        ));
    }

    database
        .approve_ssh_auth_request(&pending.auth_id, &principal)
        .await
        .map_err(ApiError::from)?;

    Ok(html_response(StatusCode::OK, success_page_html()))
}

async fn derp_probe() -> Response {
    let mut response = StatusCode::OK.into_response();
    response.headers_mut().insert(
        axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    response
}

async fn generate_204() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn register_node(
    State(state): State<AppState>,
    Json(request): Json<RegisterNodeRequest>,
) -> Result<(StatusCode, Json<NodeRegistration>), ApiError> {
    let database = state.database()?;
    let node = database
        .register_node_with_auth_key(&request.into())
        .await
        .map_err(ApiError::from)?;
    Ok((StatusCode::CREATED, Json(node)))
}

async fn node_heartbeat(
    State(state): State<AppState>,
    Path(id): Path<u64>,
    headers: HeaderMap,
) -> Result<Json<NodeHeartbeat>, ApiError> {
    let session_token = extract_bearer_token(&headers)
        .ok_or_else(|| ApiError::node_unauthorized("node session authentication required"))?;
    let database = state.database()?;
    let heartbeat = database
        .heartbeat_node_session(id, session_token)
        .await
        .map_err(map_node_control_error)?;
    Ok(Json(heartbeat))
}

async fn node_map(
    State(state): State<AppState>,
    Path(id): Path<u64>,
    headers: HeaderMap,
) -> Result<Json<NodeMap>, ApiError> {
    let session_token = extract_bearer_token(&headers)
        .ok_or_else(|| ApiError::node_unauthorized("node session authentication required"))?;
    let database = state.database()?;
    let map = database
        .sync_node_map(id, session_token)
        .await
        .map_err(map_node_control_error)?;
    Ok(Json(map))
}

async fn admin_health(State(state): State<AppState>) -> Json<AdminHealthResponse> {
    let database_ready = match &state.database {
        Some(database) => database.ping().await.is_ok(),
        None => false,
    };

    Json(
        state
            .health
            .admin(database_ready, state.config_has_warnings),
    )
}

async fn admin_config(State(state): State<AppState>) -> Json<AdminConfigResponse> {
    Json(AdminConfigResponse {
        summary: state.config_summary.clone(),
        doctor: state.config_doctor.clone(),
    })
}

async fn admin_derp_map(State(state): State<AppState>) -> Json<DerpRuntimeStatus> {
    Json(state.derp.status())
}

async fn list_nodes(State(state): State<AppState>) -> Result<Json<Vec<Node>>, ApiError> {
    let database = state.database()?;
    let nodes = database.list_admin_nodes().await.map_err(ApiError::from)?;
    Ok(Json(nodes))
}

async fn get_node(
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> Result<Json<Node>, ApiError> {
    let database = state.database()?;
    let node = database.get_admin_node(id).await.map_err(ApiError::from)?;
    Ok(Json(node))
}

async fn create_node(
    State(state): State<AppState>,
    Extension(actor): Extension<AuditActor>,
    Json(request): Json<CreateNodeRequest>,
) -> Result<(StatusCode, Json<Node>), ApiError> {
    let database = state.database()?;
    let node = database
        .create_node(&request.into(), &actor)
        .await
        .map_err(ApiError::from)?;
    let node = database
        .get_admin_node(node.id)
        .await
        .map_err(ApiError::from)?;
    Ok((StatusCode::CREATED, Json(node)))
}

async fn update_node(
    State(state): State<AppState>,
    Extension(actor): Extension<AuditActor>,
    Path(id): Path<u64>,
    Json(request): Json<UpdateNodeRequest>,
) -> Result<Json<Node>, ApiError> {
    let database = state.database()?;
    let node = database
        .update_node(id, &request.into(), &actor)
        .await
        .map_err(ApiError::from)?;
    let node = database
        .get_admin_node(node.id)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(node))
}

async fn disable_node(
    State(state): State<AppState>,
    Extension(actor): Extension<AuditActor>,
    Path(id): Path<u64>,
) -> Result<Json<Node>, ApiError> {
    let database = state.database()?;
    let node = database
        .disable_node(id, &actor)
        .await
        .map_err(ApiError::from)?;
    let node = database
        .get_admin_node(node.id)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(node))
}

async fn list_auth_keys(State(state): State<AppState>) -> Result<Json<Vec<AuthKey>>, ApiError> {
    let database = state.database()?;
    let auth_keys = database.list_auth_keys().await.map_err(ApiError::from)?;
    Ok(Json(auth_keys))
}

async fn create_auth_key(
    State(state): State<AppState>,
    Extension(actor): Extension<AuditActor>,
    Json(request): Json<CreateAuthKeyRequest>,
) -> Result<(StatusCode, Json<IssuedAuthKey>), ApiError> {
    let database = state.database()?;
    let auth_key = database
        .create_auth_key(&request.into(), &actor)
        .await
        .map_err(ApiError::from)?;
    Ok((StatusCode::CREATED, Json(auth_key)))
}

async fn revoke_auth_key(
    State(state): State<AppState>,
    Extension(actor): Extension<AuditActor>,
    Path(id): Path<String>,
) -> Result<Json<AuthKey>, ApiError> {
    let database = state.database()?;
    let auth_key = database
        .revoke_auth_key(&id, &actor)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(auth_key))
}

async fn list_routes(State(state): State<AppState>) -> Result<Json<Vec<Route>>, ApiError> {
    let database = state.database()?;
    let routes = database.list_routes().await.map_err(ApiError::from)?;
    Ok(Json(routes))
}

async fn create_route(
    State(state): State<AppState>,
    Extension(actor): Extension<AuditActor>,
    Json(request): Json<CreateRouteRequest>,
) -> Result<(StatusCode, Json<Route>), ApiError> {
    let database = state.database()?;
    let route = database
        .create_route(&request.into(), &actor)
        .await
        .map_err(ApiError::from)?;
    Ok((StatusCode::CREATED, Json(route)))
}

async fn approve_route(
    State(state): State<AppState>,
    Extension(actor): Extension<AuditActor>,
    Path(id): Path<u64>,
) -> Result<Json<Route>, ApiError> {
    let database = state.database()?;
    let route = database
        .set_route_approval(id, RouteApproval::Approved, &actor)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(route))
}

async fn reject_route(
    State(state): State<AppState>,
    Extension(actor): Extension<AuditActor>,
    Path(id): Path<u64>,
) -> Result<Json<Route>, ApiError> {
    let database = state.database()?;
    let route = database
        .set_route_approval(id, RouteApproval::Rejected, &actor)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(route))
}

async fn get_policy(State(state): State<AppState>) -> Result<Json<AclPolicy>, ApiError> {
    let database = state.database()?;
    let policy = database.load_policy().await.map_err(ApiError::from)?;
    Ok(Json(policy))
}

async fn update_policy(
    State(state): State<AppState>,
    Extension(actor): Extension<AuditActor>,
    Json(policy): Json<AclPolicy>,
) -> Result<Json<AclPolicy>, ApiError> {
    let database = state.database()?;
    let policy = database
        .save_policy(&policy, &actor)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(policy))
}

async fn get_dns(State(state): State<AppState>) -> Result<Json<DnsConfig>, ApiError> {
    let database = state.database()?;
    let dns = database.load_dns_config().await.map_err(ApiError::from)?;
    Ok(Json(dns))
}

async fn update_dns(
    State(state): State<AppState>,
    Extension(actor): Extension<AuditActor>,
    Json(dns): Json<DnsConfig>,
) -> Result<Json<DnsConfig>, ApiError> {
    let database = state.database()?;
    let dns = database
        .save_dns_config(&dns, &actor)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(dns))
}

async fn list_audit_events(
    State(state): State<AppState>,
    Query(query): Query<AuditEventQuery>,
) -> Result<Json<Vec<AuditEvent>>, ApiError> {
    let database = state.database()?;
    let events = database
        .list_audit_events(query.normalized_limit())
        .await
        .map_err(ApiError::from)?;
    Ok(Json(events))
}

async fn export_backup(State(state): State<AppState>) -> Result<Json<BackupSnapshot>, ApiError> {
    let database = state.database()?;
    let snapshot = database.export_backup().await.map_err(ApiError::from)?;
    Ok(Json(snapshot))
}

async fn restore_backup(
    State(state): State<AppState>,
    Extension(actor): Extension<AuditActor>,
    Json(snapshot): Json<BackupSnapshot>,
) -> Result<Json<BackupRestoreResult>, ApiError> {
    let database = state.database()?;
    let result = database
        .restore_backup(&snapshot, &actor)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(result))
}

#[derive(Debug, Clone)]
struct RequestContext {
    request_id: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct AdminConfigResponse {
    summary: ConfigSummary,
    doctor: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
struct BootstrapDnsQuery {
    q: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
struct OidcCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
struct ControlSshActionQuery {
    auth_id: Option<String>,
    ssh_user: Option<String>,
    local_user: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct CreateNodeRequest {
    name: String,
    hostname: String,
    ipv4: Option<String>,
    ipv6: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
}

impl From<CreateNodeRequest> for CreateNodeInput {
    fn from(value: CreateNodeRequest) -> Self {
        Self {
            name: value.name,
            hostname: value.hostname,
            ipv4: value.ipv4,
            ipv6: value.ipv6,
            tags: value.tags,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
struct UpdateNodeRequest {
    name: Option<String>,
    hostname: Option<String>,
    tags: Option<Vec<String>>,
}

impl From<UpdateNodeRequest> for UpdateNodeInput {
    fn from(value: UpdateNodeRequest) -> Self {
        Self {
            name: value.name,
            hostname: value.hostname,
            tags: value.tags,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct CreateAuthKeyRequest {
    description: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    reusable: bool,
    #[serde(default)]
    ephemeral: bool,
    expires_at_unix_secs: Option<u64>,
}

impl From<CreateAuthKeyRequest> for CreateAuthKeyInput {
    fn from(value: CreateAuthKeyRequest) -> Self {
        Self {
            description: value.description,
            tags: value.tags,
            reusable: value.reusable,
            ephemeral: value.ephemeral,
            expires_at_unix_secs: value.expires_at_unix_secs,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct CreateRouteRequest {
    node_id: u64,
    prefix: String,
    #[serde(default = "default_route_advertised")]
    advertised: bool,
    #[serde(default)]
    is_exit_node: bool,
}

impl From<CreateRouteRequest> for CreateRouteInput {
    fn from(value: CreateRouteRequest) -> Self {
        Self {
            node_id: value.node_id,
            prefix: value.prefix,
            advertised: value.advertised,
            is_exit_node: value.is_exit_node,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct RegisterNodeRequest {
    auth_key: String,
    name: Option<String>,
    hostname: String,
    #[serde(default)]
    tags: Vec<String>,
}

impl From<RegisterNodeRequest> for RegisterNodeInput {
    fn from(value: RegisterNodeRequest) -> Self {
        Self {
            auth_key: value.auth_key,
            name: value.name,
            hostname: value.hostname,
            tags: value.tags,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct AuditEventQuery {
    #[serde(default = "default_audit_limit")]
    limit: u32,
}

impl AuditEventQuery {
    fn normalized_limit(&self) -> u32 {
        self.limit.clamp(1, MAX_AUDIT_LIMIT)
    }
}

fn default_audit_limit() -> u32 {
    DEFAULT_AUDIT_LIMIT
}

fn default_route_advertised() -> bool {
    true
}

async fn resolve_bootstrap_dns(
    derp: &DerpMapRuntime,
    public_base_url: Option<&str>,
    requested_host: Option<&str>,
) -> BTreeMap<String, Vec<String>> {
    let allowed_hosts = bootstrap_dns_hosts(derp, public_base_url);
    let selected_hosts = match requested_host
        .map(str::trim)
        .filter(|host| !host.is_empty())
    {
        Some(host) if allowed_hosts.contains(host) => {
            let mut selected = BTreeSet::new();
            selected.insert(host.to_string());
            selected
        }
        Some(_) => return BTreeMap::new(),
        None => allowed_hosts,
    };

    let mut entries = BTreeMap::new();
    for host in selected_hosts {
        let ips = resolve_host_ips(&host).await;
        if !ips.is_empty() {
            entries.insert(host, ips);
        }
    }

    entries
}

fn bootstrap_dns_hosts(derp: &DerpMapRuntime, public_base_url: Option<&str>) -> BTreeSet<String> {
    let mut hosts = BTreeSet::new();
    let derp_map = derp.effective_map();
    for region in derp_map.regions.values() {
        for node in &region.nodes {
            if !node.host_name.trim().is_empty() {
                hosts.insert(node.host_name.clone());
            }
        }
    }

    if let Some(host) = public_base_host(public_base_url) {
        hosts.insert(host);
    }

    hosts
}

fn public_base_host(url: Option<&str>) -> Option<String> {
    let url = url?.trim();
    let authority = url.split("://").nth(1)?.split('/').next()?;
    if authority.is_empty() {
        return None;
    }

    if authority.starts_with('[') {
        return authority
            .strip_prefix('[')
            .and_then(|value| value.split(']').next())
            .map(str::to_string);
    }

    Some(
        authority
            .split_once(':')
            .map_or(authority, |(host, _)| host)
            .to_string(),
    )
}

async fn resolve_host_ips(host: &str) -> Vec<String> {
    match tokio::net::lookup_host((host, 443)).await {
        Ok(addresses) => {
            let mut ips = BTreeSet::new();
            for address in addresses {
                ips.insert(address.ip().to_string());
            }
            ips.into_iter().collect()
        }
        Err(err) => {
            warn!(host, error = %err, "bootstrap DNS lookup failed");
            Vec::new()
        }
    }
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
    www_authenticate: Option<&'static str>,
}

impl ApiError {
    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthorized",
            message: message.into(),
            www_authenticate: Some(ADMIN_WWW_AUTHENTICATE),
        }
    }

    fn node_unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthorized",
            message: message.into(),
            www_authenticate: Some(NODE_WWW_AUTHENTICATE),
        }
    }
}

fn map_node_control_error(error: AppError) -> ApiError {
    match error {
        AppError::Unauthorized(message) => ApiError::node_unauthorized(message),
        other => ApiError::from(other),
    }
}

impl From<AppError> for ApiError {
    fn from(error: AppError) -> Self {
        match error {
            AppError::InvalidRequest(message) => Self {
                status: StatusCode::BAD_REQUEST,
                code: "invalid_request",
                message,
                www_authenticate: None,
            },
            AppError::InvalidConfig(message) => Self {
                status: StatusCode::BAD_REQUEST,
                code: "invalid_config",
                message,
                www_authenticate: None,
            },
            AppError::NotFound(message) => Self {
                status: StatusCode::NOT_FOUND,
                code: "not_found",
                message,
                www_authenticate: None,
            },
            AppError::Conflict(message) => Self {
                status: StatusCode::CONFLICT,
                code: "conflict",
                message,
                www_authenticate: None,
            },
            AppError::Database(error) => Self {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                code: "database_error",
                message: error.to_string(),
                www_authenticate: None,
            },
            AppError::Migration(error) => Self {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                code: "migration_error",
                message: error.to_string(),
                www_authenticate: None,
            },
            AppError::Unauthorized(message) => Self {
                status: StatusCode::UNAUTHORIZED,
                code: "unauthorized",
                message,
                www_authenticate: None,
            },
            AppError::Http(error) => Self {
                status: StatusCode::BAD_GATEWAY,
                code: "upstream_http_error",
                message: error.to_string(),
                www_authenticate: None,
            },
            AppError::Config(error) => Self {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                code: "config_error",
                message: error.to_string(),
                www_authenticate: None,
            },
            AppError::Json(error) => Self {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                code: "json_error",
                message: error.to_string(),
                www_authenticate: None,
            },
            AppError::Io(error) => Self {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                code: "io_error",
                message: error.to_string(),
                www_authenticate: None,
            },
            AppError::Bootstrap(message) => Self {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "bootstrap_error",
                message,
                www_authenticate: None,
            },
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(ErrorBody {
            error: ErrorPayload {
                code: self.code,
                message: self.message,
            },
        });

        let mut response = (self.status, body).into_response();
        if let Some(www_authenticate) = self.www_authenticate {
            response
                .headers_mut()
                .insert(WWW_AUTHENTICATE, HeaderValue::from_static(www_authenticate));
        }

        response
    }
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: ErrorPayload,
}

#[derive(Debug, Serialize)]
struct ErrorPayload {
    code: &'static str,
    message: String,
}

#[derive(Clone)]
struct ServerMetrics {
    started_at: Instant,
    requests_total: Arc<AtomicU64>,
    requests_failed_total: Arc<AtomicU64>,
    admin_auth_failures_total: Arc<AtomicU64>,
}

impl ServerMetrics {
    fn new() -> Self {
        Self {
            started_at: Instant::now(),
            requests_total: Arc::new(AtomicU64::new(0)),
            requests_failed_total: Arc::new(AtomicU64::new(0)),
            admin_auth_failures_total: Arc::new(AtomicU64::new(0)),
        }
    }

    fn record_request(&self, status: StatusCode) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        if status.is_server_error() || status.is_client_error() {
            self.requests_failed_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn record_admin_auth_failure(&self) {
        self.admin_auth_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    fn render(&self, snapshot: MetricsSnapshot) -> String {
        format!(
            concat!(
                "# TYPE rscale_up gauge\n",
                "rscale_up 1\n",
                "# TYPE rscale_uptime_seconds gauge\n",
                "rscale_uptime_seconds {}\n",
                "# TYPE rscale_http_requests_total counter\n",
                "rscale_http_requests_total {}\n",
                "# TYPE rscale_http_requests_failed_total counter\n",
                "rscale_http_requests_failed_total {}\n",
                "# TYPE rscale_admin_auth_failures_total counter\n",
                "rscale_admin_auth_failures_total {}\n",
                "# TYPE rscale_database_ready gauge\n",
                "rscale_database_ready {}\n",
                "# TYPE rscale_nodes_total gauge\n",
                "rscale_nodes_total {}\n",
                "# TYPE rscale_active_auth_keys_total gauge\n",
                "rscale_active_auth_keys_total {}\n",
                "# TYPE rscale_routes_total gauge\n",
                "rscale_routes_total {}\n",
                "# TYPE rscale_audit_events_total gauge\n",
                "rscale_audit_events_total {}\n",
                "# TYPE rscale_derp_regions_total gauge\n",
                "rscale_derp_regions_total {}\n",
                "# TYPE rscale_derp_sources_total gauge\n",
                "rscale_derp_sources_total {}\n",
                "# TYPE rscale_derp_refresh_failures_total counter\n",
                "rscale_derp_refresh_failures_total {}\n",
                "# TYPE rscale_derp_last_refresh_success_unix_seconds gauge\n",
                "rscale_derp_last_refresh_success_unix_seconds {}\n",
                "# TYPE rscale_derp_relay_enabled gauge\n",
                "rscale_derp_relay_enabled {}\n",
                "# TYPE rscale_derp_relay_active_clients gauge\n",
                "rscale_derp_relay_active_clients {}\n",
                "# TYPE rscale_derp_relay_packets_total counter\n",
                "rscale_derp_relay_packets_total {}\n",
                "# TYPE rscale_derp_relay_duplicate_clients_total counter\n",
                "rscale_derp_relay_duplicate_clients_total {}\n",
                "# TYPE rscale_derp_relay_auth_failures_total counter\n",
                "rscale_derp_relay_auth_failures_total {}\n",
                "# TYPE rscale_stun_requests_total counter\n",
                "rscale_stun_requests_total {}\n",
                "# TYPE rscale_stun_responses_total counter\n",
                "rscale_stun_responses_total {}\n",
                "# TYPE rscale_config_warnings gauge\n",
                "rscale_config_warnings {}\n"
            ),
            self.started_at.elapsed().as_secs(),
            self.requests_total.load(Ordering::Relaxed),
            self.requests_failed_total.load(Ordering::Relaxed),
            self.admin_auth_failures_total.load(Ordering::Relaxed),
            u8::from(snapshot.database_ready),
            snapshot.node_count,
            snapshot.active_auth_key_count,
            snapshot.route_count,
            snapshot.audit_event_count,
            snapshot.derp_region_count,
            snapshot.derp_source_count,
            snapshot.derp_refresh_failures_total,
            snapshot.derp_last_refresh_success_unix_secs,
            u8::from(snapshot.derp_relay.enabled),
            snapshot.derp_relay.active_clients,
            snapshot.derp_relay.packets_relayed_total,
            snapshot.derp_relay.duplicate_clients_total,
            snapshot.derp_relay.auth_failures_total,
            snapshot.derp_relay.stun_requests_total,
            snapshot.derp_relay.stun_responses_total,
            u8::from(snapshot.config_has_warnings),
        )
    }
}

#[derive(Debug, Clone, Copy)]
struct MetricsSnapshot {
    config_has_warnings: bool,
    database_ready: bool,
    node_count: u64,
    active_auth_key_count: u64,
    route_count: u64,
    audit_event_count: u64,
    derp_region_count: u32,
    derp_source_count: u32,
    derp_refresh_failures_total: u64,
    derp_last_refresh_success_unix_secs: i64,
    derp_relay: DerpRelaySnapshot,
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use super::*;

    const TEST_ADMIN_TOKEN: &str = "0123456789abcdef01234567";

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    fn test_config() -> AppConfig {
        let mut config = AppConfig::default();
        config.auth.break_glass_token = Some(TEST_ADMIN_TOKEN.to_string());
        config.server.public_base_url = Some("https://localhost".to_string());
        config.derp.regions = vec![crate::config::DerpRegionConfig {
            region_id: 900,
            region_code: "test".to_string(),
            region_name: "Test Region".to_string(),
            nodes: vec![crate::config::DerpNodeConfig {
                name: "900a".to_string(),
                host_name: "localhost".to_string(),
                stun_port: 3478,
                derp_port: 443,
                ..crate::config::DerpNodeConfig::default()
            }],
            ..crate::config::DerpRegionConfig::default()
        }];
        config
    }

    fn authorized_request(uri: &str) -> TestResult<Request<Body>> {
        Ok(Request::builder()
            .uri(uri)
            .header(AUTHORIZATION, format!("Bearer {TEST_ADMIN_TOKEN}"))
            .body(Body::empty())?)
    }

    #[test]
    fn embedded_tls_required_for_insecure_test_derp_nodes() {
        let mut config = test_config();
        config.derp.server.enabled = true;
        config.derp.server.node_name = Some("900a".to_string());
        config.derp.regions[0].nodes[0].derp_port = 8080;
        config.derp.regions[0].nodes[0].insecure_for_tests = true;

        let derp_map = crate::protocol::config_derp_map(&config.derp);
        assert!(embedded_tls_required(&config, &derp_map));
    }

    #[tokio::test]
    async fn livez_returns_ok() -> TestResult {
        let app = router(AppState::without_database(test_config())?);
        let response = app
            .oneshot(Request::builder().uri("/livez").body(Body::empty())?)
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn readyz_without_database_reports_unavailable() -> TestResult {
        let app = router(AppState::without_database(test_config())?);
        let response = app
            .oneshot(Request::builder().uri("/readyz").body(Body::empty())?)
            .await?;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        Ok(())
    }

    #[tokio::test]
    async fn admin_routes_require_authentication() -> TestResult {
        let app = router(AppState::without_database(test_config())?);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/admin/nodes")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn node_routes_require_database_after_authentication() -> TestResult {
        let app = router(AppState::without_database(test_config())?);
        let response = app
            .oneshot(authorized_request("/api/v1/admin/nodes")?)
            .await?;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        Ok(())
    }

    #[tokio::test]
    async fn control_routes_require_node_session_authentication() -> TestResult {
        let app = router(AppState::without_database(test_config())?);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/control/nodes/1/map")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(WWW_AUTHENTICATE),
            Some(&HeaderValue::from_static(NODE_WWW_AUTHENTICATE)),
        );
        Ok(())
    }

    #[tokio::test]
    async fn key_route_exposes_control_public_key() -> TestResult {
        let app = router(AppState::without_database(test_config())?);
        let response = app
            .oneshot(Request::builder().uri("/key").body(Body::empty())?)
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        let json = serde_json::from_slice::<serde_json::Value>(&body)?;
        let public_key = json
            .get("publicKey")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| std::io::Error::other("public key should be present"))?;
        assert!(public_key.starts_with("mkey:"));
        Ok(())
    }

    #[tokio::test]
    async fn derp_probe_routes_return_ok_with_cors() -> TestResult {
        let app = router(AppState::without_database(test_config())?);
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::HEAD)
                    .uri("/derp/probe")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN),
            Some(&HeaderValue::from_static("*")),
        );
        Ok(())
    }

    #[tokio::test]
    async fn generate_204_returns_no_content() -> TestResult {
        let app = router(AppState::without_database(test_config())?);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/generate_204")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        Ok(())
    }

    #[tokio::test]
    async fn bootstrap_dns_returns_resolved_known_hosts() -> TestResult {
        let app = router(AppState::without_database(test_config())?);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/bootstrap-dns?q=localhost")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        let json = serde_json::from_slice::<serde_json::Value>(&body)?;
        assert!(json.get("localhost").is_some());
        Ok(())
    }

    #[tokio::test]
    async fn verify_route_requires_database() -> TestResult {
        let app = router(AppState::without_database(test_config())?);
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/verify")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"NodePublic":"nodekey:test","Source":"127.0.0.1"}"#,
                    ))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        Ok(())
    }

    #[tokio::test]
    async fn admin_derp_map_returns_effective_snapshot() -> TestResult {
        let app = router(AppState::without_database(test_config())?);
        let response = app
            .oneshot(authorized_request("/api/v1/admin/derp-map")?)
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        let json = serde_json::from_slice::<serde_json::Value>(&body)?;
        assert_eq!(
            json.get("effective_region_count")
                .and_then(serde_json::Value::as_u64),
            Some(1),
        );
        assert!(json.get("effective_map").is_some());
        Ok(())
    }

    #[tokio::test]
    async fn metrics_returns_prometheus_payload() -> TestResult {
        let app = router(AppState::without_database(test_config())?);
        let response = app
            .oneshot(Request::builder().uri("/metrics").body(Body::empty())?)
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        let text = String::from_utf8(body.to_vec())?;
        assert!(text.contains("rscale_up 1"));
        assert!(text.contains("rscale_active_auth_keys_total 0"));
        assert!(text.contains("rscale_routes_total 0"));
        assert!(text.contains("rscale_derp_regions_total 1"));
        Ok(())
    }

    #[test]
    fn parse_ssh_action_path_requires_expected_shape() {
        assert_eq!(
            parse_ssh_action_path("/machine/ssh/action/from/10/to/20"),
            Some((10, 20))
        );
        assert_eq!(
            parse_ssh_action_path("/machine/ssh/action/from/not-a-node/to/20"),
            None
        );
        assert_eq!(parse_ssh_action_path("/machine/register"), None);
    }

    #[test]
    fn decode_ssh_action_query_preserves_user_binding() -> TestResult {
        let query = decode_query::<ControlSshActionQuery>(Some(
            "auth_id=auth-123&ssh_user=alice&local_user=postgres",
        ))?;

        assert_eq!(query.auth_id.as_deref(), Some("auth-123"));
        assert_eq!(query.ssh_user.as_deref(), Some("alice"));
        assert_eq!(query.local_user.as_deref(), Some("postgres"));
        Ok(())
    }

    #[test]
    fn parse_initial_http_request_preserves_trailing_bytes() -> TestResult {
        let raw = b"POST /ts2021 HTTP/1.1\r\nHost: example\r\n\r\nextra-bytes".to_vec();
        let request = parse_initial_http_request(raw.clone(), raw.len() - "extra-bytes".len())?;

        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/ts2021");
        assert_eq!(request.trailing, b"extra-bytes");
        Ok(())
    }
}

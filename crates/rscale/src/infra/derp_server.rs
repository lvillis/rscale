use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::http::{HeaderValue, Request as HttpRequest, StatusCode};
use crc32fast::hash as crc32_hash;
use crypto_box::aead::{Aead, generic_array::GenericArray};
use crypto_box::{PublicKey, SalsaBox, SecretKey};
use futures_util::{SinkExt, StreamExt};
use graviola::random;
use hyper::Response as HyperResponse;
use serde::{Deserialize, Serialize};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter, DuplexStream,
};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time;
use tokio_tungstenite::accept_hdr_async;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::handshake::server::{
    Request as WebSocketRequest, Response as WebSocketResponse,
};
use tokio_tungstenite::tungstenite::protocol::Message;
use tracing::{info, warn};

use crate::config::DerpConfig;
use crate::error::{AppError, AppResult};
use crate::infra::db::PostgresStore;
use crate::protocol::{
    ControlDerpMap, ControlDerpNode, node_public_key_from_private, node_public_key_from_raw,
    parse_node_private_key, parse_node_public_key, raw_key_hex,
};

const DERP_MAGIC: &[u8; 8] = b"DERP\xf0\x9f\x94\x91";
const DERP_PROTOCOL_VERSION: u16 = 2;
const DERP_KEY_LEN: usize = 32;
const DERP_NONCE_LEN: usize = 24;
const DERP_MAX_INFO_LEN: usize = 1 << 20;
const DERP_MAX_PACKET_SIZE: usize = 64 << 10;
const DERP_MESH_FRAME_OVERHEAD: usize = DERP_KEY_LEN * 2;
const DERP_WEBSOCKET_BUFFER_SIZE: usize = 128 * 1024;
const STUN_HEADER_LEN: usize = 20;
const STUN_MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];
const STUN_ATTR_SOFTWARE: u16 = 0x8022;
const STUN_ATTR_FINGERPRINT: u16 = 0x8028;
const STUN_ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const STUN_BINDING_REQUEST: [u8; 2] = [0x00, 0x01];
const STUN_BINDING_SUCCESS: [u8; 2] = [0x01, 0x01];
const STUN_FINGERPRINT_LEN: usize = 8;
const STUN_SOFTWARE: &[u8] = b"tailnode";
const DERP_SUBPROTOCOL: &str = "derp";
const FRAME_SERVER_KEY: u8 = 0x01;
const FRAME_CLIENT_INFO: u8 = 0x02;
const FRAME_SERVER_INFO: u8 = 0x03;
const FRAME_SEND_PACKET: u8 = 0x04;
const FRAME_RECV_PACKET: u8 = 0x05;
const FRAME_KEEP_ALIVE: u8 = 0x06;
const FRAME_NOTE_PREFERRED: u8 = 0x07;
const FRAME_PEER_GONE: u8 = 0x08;
const FRAME_PEER_PRESENT: u8 = 0x09;
const FRAME_FORWARD_PACKET: u8 = 0x0a;
const FRAME_WATCH_CONNS: u8 = 0x10;
const FRAME_CLOSE_PEER: u8 = 0x11;
const FRAME_PING: u8 = 0x12;
const FRAME_PONG: u8 = 0x13;
const FRAME_HEALTH: u8 = 0x14;
const PEER_GONE_DISCONNECTED: u8 = 0x00;
const PEER_GONE_NOT_HERE: u8 = 0x01;
const PEER_PRESENT_IS_REGULAR: u8 = 1 << 0;
const PEER_PRESENT_IS_MESH_PEER: u8 = 1 << 1;
const PEER_PRESENT_IS_PROBER: u8 = 1 << 2;
const OUTBOUND_QUEUE_DEPTH: usize = 256;

#[derive(Clone)]
pub struct EmbeddedDerpServer {
    inner: Arc<EmbeddedDerpServerInner>,
}

struct EmbeddedDerpServerInner {
    database: Option<PostgresStore>,
    verify_clients: bool,
    keepalive_interval: Duration,
    mesh_key: Option<[u8; DERP_KEY_LEN]>,
    mesh_key_hex: Option<String>,
    mesh_retry_interval: Duration,
    server_private_key: [u8; DERP_KEY_LEN],
    server_public_key: String,
    server_public_key_raw: [u8; DERP_KEY_LEN],
    relay: RelayState,
    mesh: MeshState,
    metrics: RelayMetrics,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DerpRelaySnapshot {
    pub enabled: bool,
    pub active_clients: u64,
    pub packets_relayed_total: u64,
    pub duplicate_clients_total: u64,
    pub auth_failures_total: u64,
    pub stun_requests_total: u64,
    pub stun_responses_total: u64,
}

#[derive(Clone)]
struct RelayClient {
    client_id: u64,
    public_key: String,
    public_key_raw: [u8; DERP_KEY_LEN],
    sender: mpsc::Sender<OutboundFrame>,
    remote_addr: SocketAddr,
    can_mesh: bool,
    is_prober: bool,
}

#[derive(Clone)]
struct MeshWatcher {
    sender: mpsc::Sender<OutboundFrame>,
}

#[derive(Default)]
struct MeshState {
    routes: RwLock<BTreeMap<String, BTreeMap<String, MeshRoute>>>,
}

#[derive(Default)]
struct RelayState {
    next_client_id: AtomicU64,
    clients: RwLock<BTreeMap<String, RelayClient>>,
    watchers: RwLock<BTreeMap<u64, MeshWatcher>>,
}

#[derive(Default)]
struct RelayMetrics {
    active_clients: AtomicU64,
    packets_relayed_total: AtomicU64,
    duplicate_clients_total: AtomicU64,
    auth_failures_total: AtomicU64,
    stun_requests_total: AtomicU64,
    stun_responses_total: AtomicU64,
}

#[derive(Debug, Clone)]
struct MeshRoute {
    mesh_peer_id: String,
    sender: mpsc::Sender<MeshCommand>,
}

#[derive(Debug, Clone)]
struct MeshPeerSpec {
    peer_id: String,
    url: String,
}

#[derive(Debug)]
enum OutboundFrame {
    RecvPacket {
        src_public_key_raw: [u8; DERP_KEY_LEN],
        packet: Vec<u8>,
    },
    PeerGone {
        peer_public_key_raw: [u8; DERP_KEY_LEN],
        reason: u8,
    },
    PeerPresent {
        peer_public_key_raw: [u8; DERP_KEY_LEN],
        ip_bytes: [u8; 16],
        port: u16,
        flags: u8,
    },
    Pong([u8; 8]),
    Health(String),
    Shutdown,
}

#[derive(Debug)]
enum MeshCommand {
    ForwardPacket {
        src_public_key_raw: [u8; DERP_KEY_LEN],
        dst_public_key_raw: [u8; DERP_KEY_LEN],
        packet: Vec<u8>,
    },
    ClosePeer {
        target_public_key_raw: [u8; DERP_KEY_LEN],
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MeshLoopControl {
    Retry,
    Stop,
}

#[derive(Debug, Clone)]
struct ClientIdentity {
    public_key: String,
    public_key_raw: [u8; DERP_KEY_LEN],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DerpClientInfo {
    #[serde(default)]
    mesh_key: String,
    #[serde(default)]
    version: u16,
    #[serde(default)]
    can_ack_pings: bool,
    #[serde(default)]
    is_prober: bool,
}

#[derive(Debug, Clone, Serialize)]
struct DerpServerInfo {
    version: u16,
}

impl EmbeddedDerpServer {
    pub async fn bootstrap(
        config: &DerpConfig,
        effective_map: &ControlDerpMap,
        database: Option<PostgresStore>,
    ) -> AppResult<Option<Self>> {
        if !config.server.enabled {
            return Ok(None);
        }

        if config.server.verify_clients && database.is_none() {
            return Err(AppError::Bootstrap(
                "embedded DERP relay requires a database when derp.server.verify_clients is enabled"
                    .to_string(),
            ));
        }

        let server_private_key = parse_node_private_key(&config.server.private_key)?;
        let server_public_key = node_public_key_from_private(&server_private_key);
        let server_public_key_raw = parse_node_public_key(&server_public_key)?;
        let mesh_key = config
            .server
            .mesh_key
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .map(parse_mesh_key)
            .transpose()?;
        let mesh_key_hex = config
            .server
            .mesh_key
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let server = Self {
            inner: Arc::new(EmbeddedDerpServerInner {
                database,
                verify_clients: config.server.verify_clients,
                keepalive_interval: Duration::from_secs(config.server.keepalive_interval_secs),
                mesh_key,
                mesh_key_hex,
                mesh_retry_interval: Duration::from_secs(config.server.mesh_retry_interval_secs),
                server_private_key,
                server_public_key,
                server_public_key_raw,
                relay: RelayState::default(),
                mesh: MeshState::default(),
                metrics: RelayMetrics::default(),
            }),
        };

        let mesh_peer_specs = server.resolve_mesh_peer_specs(config, effective_map)?;

        if let Some(bind_addr) = config
            .server
            .stun_bind_addr
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            let bind_addr = bind_addr.parse::<SocketAddr>().map_err(|err| {
                AppError::InvalidConfig(format!("derp.server.stun_bind_addr is invalid: {err}"))
            })?;
            server.spawn_stun_listener(bind_addr);
        }

        server.spawn_mesh_clients(mesh_peer_specs);

        info!(
            server_public_key = %server.inner.server_public_key,
            verify_clients = server.inner.verify_clients,
            mesh_enabled = server.inner.mesh_key.is_some(),
            "embedded DERP relay initialized"
        );

        Ok(Some(server))
    }

    pub fn metrics_snapshot(&self) -> DerpRelaySnapshot {
        DerpRelaySnapshot {
            enabled: true,
            active_clients: self.inner.metrics.active_clients.load(Ordering::Relaxed),
            packets_relayed_total: self
                .inner
                .metrics
                .packets_relayed_total
                .load(Ordering::Relaxed),
            duplicate_clients_total: self
                .inner
                .metrics
                .duplicate_clients_total
                .load(Ordering::Relaxed),
            auth_failures_total: self
                .inner
                .metrics
                .auth_failures_total
                .load(Ordering::Relaxed),
            stun_requests_total: self
                .inner
                .metrics
                .stun_requests_total
                .load(Ordering::Relaxed),
            stun_responses_total: self
                .inner
                .metrics
                .stun_responses_total
                .load(Ordering::Relaxed),
        }
    }

    fn spawn_mesh_clients(&self, mesh_peers: Vec<MeshPeerSpec>) {
        if mesh_peers.is_empty() {
            return;
        }

        info!(
            mesh_peer_count = mesh_peers.len(),
            "starting DERP mesh peer loops"
        );
        for spec in mesh_peers {
            let server = self.clone();
            tokio::spawn(async move {
                server.run_mesh_peer_loop(spec).await;
            });
        }
    }

    fn resolve_mesh_peer_specs(
        &self,
        config: &DerpConfig,
        effective_map: &ControlDerpMap,
    ) -> AppResult<Vec<MeshPeerSpec>> {
        if self.inner.mesh_key.is_none() {
            return Ok(Vec::new());
        }

        let Some(node_name) = config
            .server
            .node_name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return Ok(Vec::new());
        };

        let mut matches = effective_map.regions.values().filter(|region| {
            region
                .nodes
                .iter()
                .any(|node| node.name.as_str() == node_name)
        });
        let Some(region) = matches.next() else {
            return Err(AppError::Bootstrap(format!(
                "DERP mesh node {node_name} is not present in the effective DERP map"
            )));
        };
        if matches.next().is_some() {
            return Err(AppError::Bootstrap(format!(
                "DERP mesh node {node_name} appears in multiple DERP regions"
            )));
        }

        region
            .nodes
            .iter()
            .filter(|node| node.name != node_name)
            .filter(|node| !node.stun_only)
            .map(|node| {
                Ok(MeshPeerSpec {
                    peer_id: node.name.clone(),
                    url: mesh_url_for_node(node, lookup_mesh_url_override(config, &node.name))?,
                })
            })
            .collect()
    }

    async fn run_mesh_peer_loop(&self, spec: MeshPeerSpec) {
        loop {
            match self.run_mesh_peer_connection(&spec).await {
                Ok(MeshLoopControl::Stop) => return,
                Ok(MeshLoopControl::Retry) => {}
                Err(err) => {
                    warn!(peer = %spec.peer_id, url = %spec.url, error = %err, "DERP mesh peer loop failed");
                }
            }

            self.broadcast_removed_mesh_routes(&spec.peer_id).await;
            time::sleep(self.inner.mesh_retry_interval).await;
        }
    }

    async fn run_mesh_peer_connection(&self, spec: &MeshPeerSpec) -> AppResult<MeshLoopControl> {
        let request = HttpRequest::builder()
            .uri(&spec.url)
            .header("Sec-WebSocket-Protocol", DERP_SUBPROTOCOL)
            .body(())
            .map_err(|err| {
                AppError::Bootstrap(format!(
                    "failed to build websocket DERP request for {}: {err}",
                    spec.url
                ))
            })?;
        let (websocket, _) = connect_async(request).await.map_err(|err| {
            AppError::Bootstrap(format!("failed to connect to {}: {err}", spec.url))
        })?;

        let (derp_stream, bridge_task) = spawn_websocket_bridge(websocket);
        let result = self.run_mesh_peer_stream(derp_stream, spec).await;
        bridge_task.abort();
        let _ = bridge_task.await;
        result
    }

    async fn run_mesh_peer_stream<T>(
        &self,
        stream: T,
        spec: &MeshPeerSpec,
    ) -> AppResult<MeshLoopControl>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (read_half, write_half) = tokio::io::split(stream);
        let mut reader = BufReader::new(read_half);
        let mut writer = BufWriter::new(write_half);

        let remote_server_key_raw = read_server_key_frame(&mut reader).await?;
        let remote_server_key = node_public_key_from_raw(&remote_server_key_raw);
        if remote_server_key == self.inner.server_public_key {
            info!(peer = %spec.peer_id, url = %spec.url, "detected DERP mesh self-connect; stopping peer loop");
            return Ok(MeshLoopControl::Stop);
        }

        let mesh_key_hex =
            self.inner.mesh_key_hex.clone().ok_or_else(|| {
                AppError::Bootstrap("DERP mesh key is not configured".to_string())
            })?;
        let client_info = DerpClientInfo {
            mesh_key: mesh_key_hex,
            version: DERP_PROTOCOL_VERSION,
            can_ack_pings: true,
            is_prober: false,
        };
        let client_info_payload = seal_box(
            &self.inner.server_private_key,
            &remote_server_key_raw,
            &serde_json::to_vec(&client_info)?,
        )?;
        let mut frame_payload = Vec::with_capacity(DERP_KEY_LEN + client_info_payload.len());
        frame_payload.extend_from_slice(&self.inner.server_public_key_raw);
        frame_payload.extend_from_slice(&client_info_payload);
        write_frame(&mut writer, FRAME_CLIENT_INFO, &frame_payload).await?;

        let (frame_type, payload) = read_frame(
            &mut reader,
            DERP_MAX_INFO_LEN + DERP_NONCE_LEN + DERP_KEY_LEN,
        )
        .await?;
        if frame_type != FRAME_SERVER_INFO {
            return Err(AppError::InvalidRequest(format!(
                "expected DERP server-info frame from {}, got 0x{frame_type:02x}",
                spec.url
            )));
        }
        let _server_info = open_box(
            &self.inner.server_private_key,
            &remote_server_key_raw,
            &payload,
        )?;

        write_frame(&mut writer, FRAME_WATCH_CONNS, &[]).await?;
        info!(
            peer = %spec.peer_id,
            url = %spec.url,
            server_key = %remote_server_key,
            "connected to DERP mesh peer"
        );

        let (command_sender, mut command_receiver) = mpsc::channel(OUTBOUND_QUEUE_DEPTH);
        loop {
            tokio::select! {
                command = command_receiver.recv() => {
                    let Some(command) = command else {
                        return Ok(MeshLoopControl::Stop);
                    };
                    write_mesh_command(&mut writer, command).await?;
                }
                frame = read_frame(&mut reader, DERP_MESH_FRAME_OVERHEAD + DERP_MAX_PACKET_SIZE + 1024) => {
                    let (frame_type, payload) = match frame {
                        Ok(frame) => frame,
                        Err(AppError::Io(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                            return Ok(MeshLoopControl::Retry);
                        }
                        Err(err) => return Err(err),
                    };
                    match frame_type {
                        FRAME_SERVER_INFO | FRAME_KEEP_ALIVE | FRAME_PONG => {}
                        FRAME_PING => {
                            if payload.len() != 8 {
                                return Err(AppError::InvalidRequest(
                                    "DERP mesh ping frame must contain exactly 8 bytes".to_string(),
                                ));
                            }
                            write_frame(&mut writer, FRAME_PONG, &payload).await?;
                        }
                        FRAME_HEALTH => {
                            if !payload.is_empty() {
                                let message = String::from_utf8_lossy(&payload);
                                warn!(peer = %spec.peer_id, url = %spec.url, health = %message, "DERP mesh peer reported health state");
                            }
                        }
                        FRAME_PEER_PRESENT => {
                            self.handle_mesh_peer_present(spec, &command_sender, &payload)?;
                        }
                        FRAME_PEER_GONE => {
                            self.handle_mesh_peer_gone(spec, &payload).await?;
                        }
                        _ => {
                            warn!(peer = %spec.peer_id, url = %spec.url, frame_type = format_args!("0x{frame_type:02x}"), "ignoring unexpected DERP mesh frame");
                        }
                    }
                }
            }
        }
    }

    fn handle_mesh_peer_present(
        &self,
        spec: &MeshPeerSpec,
        sender: &mpsc::Sender<MeshCommand>,
        payload: &[u8],
    ) -> AppResult<()> {
        if payload.len() < DERP_KEY_LEN {
            return Err(AppError::InvalidRequest(
                "DERP mesh peer-present frame is too short".to_string(),
            ));
        }

        let mut peer_public_key_raw = [0_u8; DERP_KEY_LEN];
        peer_public_key_raw.copy_from_slice(&payload[..DERP_KEY_LEN]);
        let peer_public_key = node_public_key_from_raw(&peer_public_key_raw);
        self.inner.mesh.add_route(
            peer_public_key,
            spec.peer_id.clone(),
            MeshRoute {
                mesh_peer_id: spec.peer_id.clone(),
                sender: sender.clone(),
            },
        );
        Ok(())
    }

    async fn handle_mesh_peer_gone(&self, spec: &MeshPeerSpec, payload: &[u8]) -> AppResult<()> {
        if payload.len() < DERP_KEY_LEN {
            return Err(AppError::InvalidRequest(
                "DERP mesh peer-gone frame is too short".to_string(),
            ));
        }

        let mut peer_public_key_raw = [0_u8; DERP_KEY_LEN];
        peer_public_key_raw.copy_from_slice(&payload[..DERP_KEY_LEN]);
        let peer_public_key = node_public_key_from_raw(&peer_public_key_raw);
        if self
            .inner
            .mesh
            .remove_route(&peer_public_key, &spec.peer_id)
        {
            self.broadcast_peer_gone_to_regular_clients(
                peer_public_key_raw,
                PEER_GONE_DISCONNECTED,
            )
            .await;
        }
        Ok(())
    }

    async fn broadcast_removed_mesh_routes(&self, mesh_peer_id: &str) {
        let removed = self.inner.mesh.remove_mesh_peer(mesh_peer_id);
        for peer_public_key in removed {
            if let Ok(peer_public_key_raw) = parse_node_public_key(&peer_public_key) {
                self.broadcast_peer_gone_to_regular_clients(
                    peer_public_key_raw,
                    PEER_GONE_DISCONNECTED,
                )
                .await;
            }
        }
    }

    async fn broadcast_peer_gone_to_regular_clients(
        &self,
        peer_public_key_raw: [u8; DERP_KEY_LEN],
        reason: u8,
    ) {
        let peers = self.inner.relay.regular_clients();
        for peer in peers {
            let _ = peer
                .sender
                .send(OutboundFrame::PeerGone {
                    peer_public_key_raw,
                    reason,
                })
                .await;
        }
    }

    pub async fn serve_plain_connection<T>(
        &self,
        mut stream: T,
        remote_addr: SocketAddr,
        fast_start: bool,
    ) -> AppResult<()>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        if !fast_start {
            let response = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\nDerp-Version: {DERP_PROTOCOL_VERSION}\r\nDerp-Public-Key: {}\r\n\r\n",
                raw_key_hex(&self.inner.server_public_key_raw)
            );
            stream.write_all(response.as_bytes()).await?;
            stream.flush().await?;
        }

        self.serve_connection(stream, remote_addr).await
    }

    pub async fn serve_websocket_connection<T>(
        &self,
        stream: T,
        remote_addr: SocketAddr,
    ) -> AppResult<()>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let websocket = accept_hdr_async(stream, websocket_derp_callback)
            .await
            .map_err(|err| {
                AppError::InvalidRequest(format!("websocket DERP handshake failed: {err}"))
            })?;

        let (derp_stream, bridge_task) = spawn_websocket_bridge(websocket);
        let result = self.serve_connection(derp_stream, remote_addr).await;
        bridge_task.abort();
        let _ = bridge_task.await;
        result
    }

    async fn serve_connection<T>(&self, stream: T, remote_addr: SocketAddr) -> AppResult<()>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (read_half, write_half) = tokio::io::split(stream);
        let mut reader = BufReader::new(read_half);
        let mut writer = BufWriter::new(write_half);

        write_frame(
            &mut writer,
            FRAME_SERVER_KEY,
            &server_key_payload(&self.inner.server_public_key_raw),
        )
        .await?;

        let (identity, client_info) = self.read_client_info(&mut reader).await?;
        let can_mesh = self.is_mesh_peer(&client_info);
        self.authorize_client(&identity, can_mesh).await?;

        let (sender, receiver) = mpsc::channel(OUTBOUND_QUEUE_DEPTH);
        let relay_client = RelayClient {
            client_id: self.inner.relay.next_client_id(),
            public_key: identity.public_key.clone(),
            public_key_raw: identity.public_key_raw,
            sender: sender.clone(),
            remote_addr,
            can_mesh,
            is_prober: client_info.is_prober,
        };

        let replaced = self.inner.relay.register(relay_client.clone());
        self.inner
            .metrics
            .active_clients
            .store(self.inner.relay.client_count() as u64, Ordering::Relaxed);
        if replaced.is_some() {
            self.inner
                .metrics
                .duplicate_clients_total
                .fetch_add(1, Ordering::Relaxed);
        }

        write_frame(
            &mut writer,
            FRAME_SERVER_INFO,
            &seal_box(
                &self.inner.server_private_key,
                &relay_client.public_key_raw,
                &serde_json::to_vec(&DerpServerInfo {
                    version: DERP_PROTOCOL_VERSION,
                })?,
            )?,
        )
        .await?;

        if let Some(previous) = replaced {
            let _ = previous
                .sender
                .send(OutboundFrame::Health(
                    "duplicate DERP connection replaced by a newer session".to_string(),
                ))
                .await;
        }

        if !relay_client.can_mesh {
            self.send_existing_regular_peers(&relay_client).await;
            self.broadcast_peer_present_to_regular_clients(&relay_client)
                .await;
            self.broadcast_peer_present_to_mesh_watchers(&relay_client)
                .await;
        }

        info!(
            %remote_addr,
            node_public = %relay_client.public_key,
            protocol_version = client_info.version,
            can_ack_pings = client_info.can_ack_pings,
            is_prober = client_info.is_prober,
            can_mesh = relay_client.can_mesh,
            "DERP client connected"
        );

        let read_result = self.read_loop(&mut reader, &relay_client, sender);
        let write_result = self.write_loop(&mut writer, receiver);
        let result = tokio::select! {
            result = read_result => result,
            result = write_result => result,
        };
        self.disconnect_client(&relay_client).await;
        result
    }

    async fn read_client_info<R>(
        &self,
        reader: &mut R,
    ) -> AppResult<(ClientIdentity, DerpClientInfo)>
    where
        R: AsyncRead + Unpin,
    {
        let (frame_type, payload) =
            read_frame(reader, DERP_KEY_LEN + DERP_NONCE_LEN + DERP_MAX_INFO_LEN).await?;
        if frame_type != FRAME_CLIENT_INFO {
            return Err(AppError::Unauthorized(format!(
                "expected DERP client info frame, got 0x{frame_type:02x}"
            )));
        }

        if payload.len() < DERP_KEY_LEN + DERP_NONCE_LEN {
            return Err(AppError::Unauthorized(
                "DERP client info payload is too short".to_string(),
            ));
        }

        let mut client_public_key_raw = [0_u8; DERP_KEY_LEN];
        client_public_key_raw.copy_from_slice(&payload[..DERP_KEY_LEN]);
        if client_public_key_raw.iter().all(|byte| *byte == 0) {
            return Err(AppError::Unauthorized(
                "DERP client public key must not be zero".to_string(),
            ));
        }

        let client_public_key = node_public_key_from_raw(&client_public_key_raw);
        let opened = open_box(
            &self.inner.server_private_key,
            &client_public_key_raw,
            &payload[DERP_KEY_LEN..],
        )?;
        let client_info = serde_json::from_slice::<DerpClientInfo>(&opened).map_err(|err| {
            AppError::Unauthorized(format!("failed to decode DERP client info JSON: {err}"))
        })?;

        Ok((
            ClientIdentity {
                public_key: client_public_key,
                public_key_raw: client_public_key_raw,
            },
            client_info,
        ))
    }

    fn is_mesh_peer(&self, client_info: &DerpClientInfo) -> bool {
        let Some(server_mesh_key) = self.inner.mesh_key else {
            return false;
        };
        let Ok(client_mesh_key) = parse_mesh_key(&client_info.mesh_key) else {
            return false;
        };
        client_mesh_key == server_mesh_key
    }

    async fn authorize_client(&self, client: &ClientIdentity, can_mesh: bool) -> AppResult<()> {
        if can_mesh {
            return Ok(());
        }

        if !self.inner.verify_clients {
            return Ok(());
        }

        let Some(database) = &self.inner.database else {
            self.inner
                .metrics
                .auth_failures_total
                .fetch_add(1, Ordering::Relaxed);
            return Err(AppError::Unauthorized(
                "DERP relay client verification is enabled but no database is configured"
                    .to_string(),
            ));
        };

        if database.allows_derp_client(&client.public_key).await? {
            return Ok(());
        }

        self.inner
            .metrics
            .auth_failures_total
            .fetch_add(1, Ordering::Relaxed);
        Err(AppError::Unauthorized(format!(
            "node {} is not authorized to use DERP",
            client.public_key
        )))
    }

    async fn read_loop<R>(
        &self,
        reader: &mut R,
        client: &RelayClient,
        sender: mpsc::Sender<OutboundFrame>,
    ) -> AppResult<()>
    where
        R: AsyncRead + Unpin,
    {
        loop {
            let (frame_type, payload) = read_frame(
                reader,
                DERP_MESH_FRAME_OVERHEAD + DERP_MAX_PACKET_SIZE + 1024,
            )
            .await?;
            match frame_type {
                FRAME_SEND_PACKET => {
                    if payload.len() < DERP_KEY_LEN {
                        return Err(AppError::InvalidRequest(
                            "DERP send-packet frame is too short".to_string(),
                        ));
                    }

                    let mut dst_public_key_raw = [0_u8; DERP_KEY_LEN];
                    dst_public_key_raw.copy_from_slice(&payload[..DERP_KEY_LEN]);
                    let packet = payload[DERP_KEY_LEN..].to_vec();
                    if packet.len() > DERP_MAX_PACKET_SIZE {
                        return Err(AppError::InvalidRequest(format!(
                            "DERP packet exceeds maximum payload of {DERP_MAX_PACKET_SIZE} bytes"
                        )));
                    }

                    if !self
                        .route_packet(client.public_key_raw, dst_public_key_raw, packet)
                        .await?
                    {
                        let _ = sender
                            .send(OutboundFrame::PeerGone {
                                peer_public_key_raw: dst_public_key_raw,
                                reason: PEER_GONE_NOT_HERE,
                            })
                            .await;
                    }
                }
                FRAME_FORWARD_PACKET => {
                    if !client.can_mesh {
                        return Err(AppError::Unauthorized(
                            "mesh forwarding requires a trusted DERP mesh key".to_string(),
                        ));
                    }
                    self.handle_frame_forward_packet(&payload, &sender).await?;
                }
                FRAME_WATCH_CONNS => {
                    if !client.can_mesh {
                        return Err(AppError::Unauthorized(
                            "watch-conns requires a trusted DERP mesh key".to_string(),
                        ));
                    }
                    if !payload.is_empty() {
                        return Err(AppError::InvalidRequest(
                            "DERP watch-conns frame must be empty".to_string(),
                        ));
                    }

                    self.handle_frame_watch_conns(client, sender.clone()).await;
                }
                FRAME_CLOSE_PEER => {
                    if !client.can_mesh {
                        return Err(AppError::Unauthorized(
                            "close-peer requires a trusted DERP mesh key".to_string(),
                        ));
                    }
                    self.handle_frame_close_peer(&payload).await?;
                }
                FRAME_PING => {
                    if payload.len() != 8 {
                        return Err(AppError::InvalidRequest(
                            "DERP ping frame must contain exactly 8 bytes".to_string(),
                        ));
                    }

                    let mut ping = [0_u8; 8];
                    ping.copy_from_slice(&payload);
                    if sender.send(OutboundFrame::Pong(ping)).await.is_err() {
                        return Ok(());
                    }
                }
                FRAME_PONG | FRAME_KEEP_ALIVE => {}
                FRAME_NOTE_PREFERRED => {
                    if payload.len() != 1 {
                        return Err(AppError::InvalidRequest(
                            "DERP preferred-node frame must contain exactly 1 byte".to_string(),
                        ));
                    }
                }
                _ => {
                    return Err(AppError::InvalidRequest(format!(
                        "unsupported DERP frame type 0x{frame_type:02x}"
                    )));
                }
            }
        }
    }

    async fn handle_frame_watch_conns(
        &self,
        client: &RelayClient,
        sender: mpsc::Sender<OutboundFrame>,
    ) {
        let initial_peers = self.inner.relay.add_watcher(client.client_id, sender);
        for peer in initial_peers {
            let _ = client
                .sender
                .send(OutboundFrame::PeerPresent {
                    peer_public_key_raw: peer.public_key_raw,
                    ip_bytes: socket_addr_ip_bytes(peer.remote_addr),
                    port: peer.remote_addr.port(),
                    flags: peer_present_flags(&peer),
                })
                .await;
        }
    }

    async fn handle_frame_forward_packet(
        &self,
        payload: &[u8],
        sender: &mpsc::Sender<OutboundFrame>,
    ) -> AppResult<()> {
        if payload.len() < DERP_MESH_FRAME_OVERHEAD {
            return Err(AppError::InvalidRequest(
                "DERP forward-packet frame is too short".to_string(),
            ));
        }

        let mut src_public_key_raw = [0_u8; DERP_KEY_LEN];
        src_public_key_raw.copy_from_slice(&payload[..DERP_KEY_LEN]);
        let mut dst_public_key_raw = [0_u8; DERP_KEY_LEN];
        dst_public_key_raw.copy_from_slice(&payload[DERP_KEY_LEN..DERP_MESH_FRAME_OVERHEAD]);
        let packet = payload[DERP_MESH_FRAME_OVERHEAD..].to_vec();
        if packet.len() > DERP_MAX_PACKET_SIZE {
            return Err(AppError::InvalidRequest(format!(
                "DERP forwarded packet exceeds maximum payload of {DERP_MAX_PACKET_SIZE} bytes"
            )));
        }

        if !self
            .route_packet(src_public_key_raw, dst_public_key_raw, packet)
            .await?
        {
            let _ = sender
                .send(OutboundFrame::PeerGone {
                    peer_public_key_raw: dst_public_key_raw,
                    reason: PEER_GONE_NOT_HERE,
                })
                .await;
        }

        Ok(())
    }

    async fn handle_frame_close_peer(&self, payload: &[u8]) -> AppResult<()> {
        if payload.len() != DERP_KEY_LEN {
            return Err(AppError::InvalidRequest(
                "DERP close-peer frame must contain exactly 32 bytes".to_string(),
            ));
        }

        let mut target_public_key_raw = [0_u8; DERP_KEY_LEN];
        target_public_key_raw.copy_from_slice(payload);
        let target_public_key = node_public_key_from_raw(&target_public_key_raw);
        if let Some(target) = self.inner.relay.lookup(&target_public_key) {
            let _ = target.sender.send(OutboundFrame::Shutdown).await;
            return Ok(());
        }

        let routes = self.inner.mesh.routes_for(&target_public_key);
        for route in routes {
            if route
                .sender
                .send(MeshCommand::ClosePeer {
                    target_public_key_raw,
                })
                .await
                .is_ok()
            {
                return Ok(());
            }
            if self
                .inner
                .mesh
                .remove_route(&target_public_key, &route.mesh_peer_id)
            {
                self.broadcast_peer_gone_to_regular_clients(
                    target_public_key_raw,
                    PEER_GONE_DISCONNECTED,
                )
                .await;
            }
        }

        Ok(())
    }

    async fn route_packet(
        &self,
        src_public_key_raw: [u8; DERP_KEY_LEN],
        dst_public_key_raw: [u8; DERP_KEY_LEN],
        packet: Vec<u8>,
    ) -> AppResult<bool> {
        let dst_public_key = node_public_key_from_raw(&dst_public_key_raw);
        if let Some(target) = self.inner.relay.lookup(&dst_public_key) {
            let send_result = target
                .sender
                .send(OutboundFrame::RecvPacket {
                    src_public_key_raw,
                    packet: packet.clone(),
                })
                .await;
            if send_result.is_ok() {
                self.inner
                    .metrics
                    .packets_relayed_total
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(true);
            }

            self.inner
                .relay
                .evict_if_stale(&dst_public_key, target.client_id);
            self.inner
                .metrics
                .active_clients
                .store(self.inner.relay.client_count() as u64, Ordering::Relaxed);
        }

        let routes = self.inner.mesh.routes_for(&dst_public_key);
        for route in routes {
            if route
                .sender
                .send(MeshCommand::ForwardPacket {
                    src_public_key_raw,
                    dst_public_key_raw,
                    packet: packet.clone(),
                })
                .await
                .is_ok()
            {
                self.inner
                    .metrics
                    .packets_relayed_total
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(true);
            }

            if self
                .inner
                .mesh
                .remove_route(&dst_public_key, &route.mesh_peer_id)
            {
                self.broadcast_peer_gone_to_regular_clients(
                    dst_public_key_raw,
                    PEER_GONE_DISCONNECTED,
                )
                .await;
            }
        }

        Ok(false)
    }

    async fn write_loop<W>(
        &self,
        writer: &mut W,
        mut receiver: mpsc::Receiver<OutboundFrame>,
    ) -> AppResult<()>
    where
        W: AsyncWrite + Unpin,
    {
        let mut keepalive = time::interval(self.inner.keepalive_interval);
        keepalive.tick().await;

        loop {
            tokio::select! {
                outbound = receiver.recv() => {
                    let Some(outbound) = outbound else {
                        break;
                    };
                    match outbound {
                        OutboundFrame::Shutdown => break,
                        other => write_outbound_frame(writer, other).await?,
                    }
                }
                _ = keepalive.tick() => {
                    write_frame(writer, FRAME_KEEP_ALIVE, &[]).await?;
                }
            }
        }

        writer.shutdown().await?;
        Ok(())
    }

    async fn disconnect_client(&self, client: &RelayClient) {
        self.inner.relay.remove_watcher(client.client_id);
        let peers = self.inner.relay.unregister(client);
        self.inner
            .metrics
            .active_clients
            .store(self.inner.relay.client_count() as u64, Ordering::Relaxed);

        if !client.can_mesh {
            for peer in peers {
                let _ = peer
                    .sender
                    .send(OutboundFrame::PeerGone {
                        peer_public_key_raw: client.public_key_raw,
                        reason: PEER_GONE_DISCONNECTED,
                    })
                    .await;
            }
            self.broadcast_peer_gone(client).await;
        }

        info!(node_public = %client.public_key, "DERP client disconnected");
    }

    async fn send_existing_regular_peers(&self, client: &RelayClient) {
        let peers = self.inner.relay.regular_clients_except(client.client_id);
        for peer in peers {
            let _ = client
                .sender
                .send(OutboundFrame::PeerPresent {
                    peer_public_key_raw: peer.public_key_raw,
                    ip_bytes: socket_addr_ip_bytes(peer.remote_addr),
                    port: peer.remote_addr.port(),
                    flags: peer_present_flags(&peer),
                })
                .await;
        }
    }

    async fn broadcast_peer_present_to_regular_clients(&self, peer: &RelayClient) {
        let peers = self.inner.relay.regular_clients_except(peer.client_id);
        for client in peers {
            let _ = client
                .sender
                .send(OutboundFrame::PeerPresent {
                    peer_public_key_raw: peer.public_key_raw,
                    ip_bytes: socket_addr_ip_bytes(peer.remote_addr),
                    port: peer.remote_addr.port(),
                    flags: peer_present_flags(peer),
                })
                .await;
        }
    }

    async fn broadcast_peer_present_to_mesh_watchers(&self, peer: &RelayClient) {
        let watchers = self.inner.relay.watchers();
        for watcher in watchers {
            let _ = watcher
                .sender
                .send(OutboundFrame::PeerPresent {
                    peer_public_key_raw: peer.public_key_raw,
                    ip_bytes: socket_addr_ip_bytes(peer.remote_addr),
                    port: peer.remote_addr.port(),
                    flags: peer_present_flags(peer),
                })
                .await;
        }
    }

    async fn broadcast_peer_gone(&self, peer: &RelayClient) {
        let watchers = self.inner.relay.watchers();
        for watcher in watchers {
            let _ = watcher
                .sender
                .send(OutboundFrame::PeerGone {
                    peer_public_key_raw: peer.public_key_raw,
                    reason: PEER_GONE_DISCONNECTED,
                })
                .await;
        }
    }

    fn spawn_stun_listener(&self, bind_addr: SocketAddr) {
        let server = self.clone();
        tokio::spawn(async move {
            if let Err(err) = server.run_stun_listener(bind_addr).await {
                warn!(%bind_addr, error = %err, "STUN listener stopped");
            }
        });
    }

    async fn run_stun_listener(&self, bind_addr: SocketAddr) -> AppResult<()> {
        let socket = UdpSocket::bind(bind_addr).await.map_err(|err| {
            AppError::Bootstrap(format!("failed to bind STUN socket on {bind_addr}: {err}"))
        })?;

        info!(%bind_addr, "embedded DERP STUN listener bound");

        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let (len, peer_addr) = socket.recv_from(&mut buffer).await?;
            let packet = &buffer[..len];
            let Ok(txid) = parse_stun_binding_request(packet) else {
                continue;
            };

            self.inner
                .metrics
                .stun_requests_total
                .fetch_add(1, Ordering::Relaxed);

            let response = build_stun_binding_response(txid, peer_addr);
            if socket.send_to(&response, peer_addr).await.is_ok() {
                self.inner
                    .metrics
                    .stun_responses_total
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[allow(clippy::result_large_err)]
fn websocket_derp_callback(
    request: &WebSocketRequest,
    mut response: WebSocketResponse,
) -> Result<WebSocketResponse, HyperResponse<Option<String>>> {
    let has_derp_protocol = request
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|value| value.to_str().ok())
        .map(protocols_contain_derp)
        .unwrap_or(false);
    if !has_derp_protocol {
        let mut error_response = HyperResponse::new(Some(
            "websocket DERP requires the `derp` subprotocol".to_string(),
        ));
        *error_response.status_mut() = StatusCode::BAD_REQUEST;
        return Err(error_response);
    }

    response.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        HeaderValue::from_static(DERP_SUBPROTOCOL),
    );
    Ok(response)
}

impl RelayState {
    fn next_client_id(&self) -> u64 {
        self.next_client_id.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn register(&self, client: RelayClient) -> Option<RelayClient> {
        self.clients_write()
            .insert(client.public_key.clone(), client)
    }

    fn lookup(&self, public_key: &str) -> Option<RelayClient> {
        self.clients_read().get(public_key).cloned()
    }

    fn unregister(&self, client: &RelayClient) -> Vec<RelayClient> {
        let mut clients = self.clients_write();
        let should_remove = clients
            .get(&client.public_key)
            .is_some_and(|current| current.client_id == client.client_id);
        if !should_remove {
            return Vec::new();
        }

        clients.remove(&client.public_key);
        clients
            .values()
            .filter(|peer| !peer.can_mesh)
            .cloned()
            .collect()
    }

    fn evict_if_stale(&self, public_key: &str, client_id: u64) {
        let mut clients = self.clients_write();
        let should_remove = clients
            .get(public_key)
            .is_some_and(|current| current.client_id == client_id);
        if should_remove {
            clients.remove(public_key);
        }
    }

    fn add_watcher(&self, client_id: u64, sender: mpsc::Sender<OutboundFrame>) -> Vec<RelayClient> {
        self.watchers_write()
            .insert(client_id, MeshWatcher { sender });

        self.clients_read()
            .values()
            .filter(|peer| !peer.can_mesh)
            .cloned()
            .collect()
    }

    fn remove_watcher(&self, client_id: u64) {
        self.watchers_write().remove(&client_id);
    }

    fn watchers(&self) -> Vec<MeshWatcher> {
        self.watchers_read().values().cloned().collect()
    }

    fn regular_clients(&self) -> Vec<RelayClient> {
        self.clients_read()
            .values()
            .filter(|peer| !peer.can_mesh)
            .cloned()
            .collect()
    }

    fn regular_clients_except(&self, client_id: u64) -> Vec<RelayClient> {
        self.clients_read()
            .values()
            .filter(|peer| !peer.can_mesh && peer.client_id != client_id)
            .cloned()
            .collect()
    }

    fn client_count(&self) -> usize {
        self.clients_read().len()
    }

    fn clients_read(&self) -> std::sync::RwLockReadGuard<'_, BTreeMap<String, RelayClient>> {
        self.clients
            .read()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn clients_write(&self) -> std::sync::RwLockWriteGuard<'_, BTreeMap<String, RelayClient>> {
        self.clients
            .write()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn watchers_read(&self) -> std::sync::RwLockReadGuard<'_, BTreeMap<u64, MeshWatcher>> {
        self.watchers
            .read()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn watchers_write(&self) -> std::sync::RwLockWriteGuard<'_, BTreeMap<u64, MeshWatcher>> {
        self.watchers
            .write()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

impl MeshState {
    fn add_route(&self, peer_public_key: String, mesh_peer_id: String, route: MeshRoute) {
        self.routes_write()
            .entry(peer_public_key)
            .or_default()
            .insert(mesh_peer_id, route);
    }

    fn routes_for(&self, peer_public_key: &str) -> Vec<MeshRoute> {
        self.routes_read()
            .get(peer_public_key)
            .map(|routes| routes.values().cloned().collect())
            .unwrap_or_default()
    }

    fn remove_route(&self, peer_public_key: &str, mesh_peer_id: &str) -> bool {
        let mut routes = self.routes_write();
        let Some(peer_routes) = routes.get_mut(peer_public_key) else {
            return false;
        };
        peer_routes.remove(mesh_peer_id);
        if peer_routes.is_empty() {
            routes.remove(peer_public_key);
            return true;
        }
        false
    }

    fn remove_mesh_peer(&self, mesh_peer_id: &str) -> Vec<String> {
        let mut routes = self.routes_write();
        let mut removed = Vec::new();
        let keys: Vec<String> = routes.keys().cloned().collect();
        for key in keys {
            let mut should_remove = false;
            if let Some(peer_routes) = routes.get_mut(&key) {
                peer_routes.remove(mesh_peer_id);
                should_remove = peer_routes.is_empty();
            }
            if should_remove {
                routes.remove(&key);
                removed.push(key);
            }
        }
        removed
    }

    fn routes_read(
        &self,
    ) -> std::sync::RwLockReadGuard<'_, BTreeMap<String, BTreeMap<String, MeshRoute>>> {
        self.routes
            .read()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn routes_write(
        &self,
    ) -> std::sync::RwLockWriteGuard<'_, BTreeMap<String, BTreeMap<String, MeshRoute>>> {
        self.routes
            .write()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

fn protocols_contain_derp(value: &str) -> bool {
    value
        .split(',')
        .any(|protocol| protocol.trim() == DERP_SUBPROTOCOL)
}

fn spawn_websocket_bridge<T>(
    websocket: tokio_tungstenite::WebSocketStream<T>,
) -> (DuplexStream, JoinHandle<AppResult<()>>)
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (derp_stream, bridge_stream) = tokio::io::duplex(DERP_WEBSOCKET_BUFFER_SIZE);
    let task = tokio::spawn(async move { bridge_websocket(websocket, bridge_stream).await });
    (derp_stream, task)
}

async fn bridge_websocket<T>(
    websocket: tokio_tungstenite::WebSocketStream<T>,
    bridge_stream: DuplexStream,
) -> AppResult<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut ws_write, mut ws_read) = websocket.split();
    let (mut bridge_read, mut bridge_write) = tokio::io::split(bridge_stream);

    let incoming = async {
        while let Some(message) = ws_read.next().await {
            let message = message.map_err(map_websocket_error)?;
            match message {
                Message::Binary(payload) => bridge_write.write_all(payload.as_ref()).await?,
                Message::Close(_) => break,
                Message::Ping(_) | Message::Pong(_) => {}
                Message::Text(_) => {
                    return Err(AppError::InvalidRequest(
                        "DERP websocket only accepts binary frames".to_string(),
                    ));
                }
                Message::Frame(_) => {}
            }
        }

        bridge_write.shutdown().await?;
        Ok(())
    };

    let outgoing = async {
        let mut buffer = vec![0_u8; 16 * 1024];
        loop {
            let read = bridge_read.read(&mut buffer).await?;
            if read == 0 {
                break;
            }

            ws_write
                .send(Message::Binary(buffer[..read].to_vec().into()))
                .await
                .map_err(map_websocket_error)?;
        }

        ws_write.close().await.map_err(map_websocket_error)?;
        Ok(())
    };

    tokio::try_join!(incoming, outgoing)?;
    Ok(())
}

fn map_websocket_error(error: tokio_tungstenite::tungstenite::Error) -> AppError {
    AppError::Bootstrap(format!("DERP websocket I/O failed: {error}"))
}

async fn read_frame<R>(reader: &mut R, max_len: usize) -> AppResult<(u8, Vec<u8>)>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; 5];
    reader.read_exact(&mut header).await?;
    let frame_type = header[0];
    let frame_len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if frame_len > max_len {
        return Err(AppError::InvalidRequest(format!(
            "DERP frame length {frame_len} exceeds limit {max_len}"
        )));
    }

    let mut payload = vec![0_u8; frame_len];
    reader.read_exact(&mut payload).await?;
    Ok((frame_type, payload))
}

async fn write_frame<W>(writer: &mut W, frame_type: u8, payload: &[u8]) -> AppResult<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(&[frame_type]).await?;
    writer
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

async fn write_outbound_frame<W>(writer: &mut W, outbound: OutboundFrame) -> AppResult<()>
where
    W: AsyncWrite + Unpin,
{
    match outbound {
        OutboundFrame::RecvPacket {
            src_public_key_raw,
            packet,
        } => {
            let mut payload = Vec::with_capacity(DERP_KEY_LEN + packet.len());
            payload.extend_from_slice(&src_public_key_raw);
            payload.extend_from_slice(&packet);
            write_frame(writer, FRAME_RECV_PACKET, &payload).await
        }
        OutboundFrame::PeerGone {
            peer_public_key_raw,
            reason,
        } => {
            let mut payload = Vec::with_capacity(DERP_KEY_LEN + 1);
            payload.extend_from_slice(&peer_public_key_raw);
            payload.push(reason);
            write_frame(writer, FRAME_PEER_GONE, &payload).await
        }
        OutboundFrame::PeerPresent {
            peer_public_key_raw,
            ip_bytes,
            port,
            flags,
        } => {
            let mut payload = Vec::with_capacity(DERP_KEY_LEN + 16 + 2 + 1);
            payload.extend_from_slice(&peer_public_key_raw);
            payload.extend_from_slice(&ip_bytes);
            payload.extend_from_slice(&port.to_be_bytes());
            payload.push(flags);
            write_frame(writer, FRAME_PEER_PRESENT, &payload).await
        }
        OutboundFrame::Pong(ping) => write_frame(writer, FRAME_PONG, &ping).await,
        OutboundFrame::Health(message) => {
            write_frame(writer, FRAME_HEALTH, message.as_bytes()).await
        }
        OutboundFrame::Shutdown => Ok(()),
    }
}

async fn write_mesh_command<W>(writer: &mut W, command: MeshCommand) -> AppResult<()>
where
    W: AsyncWrite + Unpin,
{
    match command {
        MeshCommand::ForwardPacket {
            src_public_key_raw,
            dst_public_key_raw,
            packet,
        } => {
            let mut payload = Vec::with_capacity(DERP_MESH_FRAME_OVERHEAD + packet.len());
            payload.extend_from_slice(&src_public_key_raw);
            payload.extend_from_slice(&dst_public_key_raw);
            payload.extend_from_slice(&packet);
            write_frame(writer, FRAME_FORWARD_PACKET, &payload).await
        }
        MeshCommand::ClosePeer {
            target_public_key_raw,
        } => write_frame(writer, FRAME_CLOSE_PEER, &target_public_key_raw).await,
    }
}

async fn read_server_key_frame<R>(reader: &mut R) -> AppResult<[u8; DERP_KEY_LEN]>
where
    R: AsyncRead + Unpin,
{
    let (frame_type, payload) = read_frame(reader, DERP_MAGIC.len() + DERP_KEY_LEN).await?;
    if frame_type != FRAME_SERVER_KEY {
        return Err(AppError::Unauthorized(format!(
            "expected DERP server-key frame, got 0x{frame_type:02x}"
        )));
    }
    parse_server_key_payload(&payload)
}

fn server_key_payload(public_key_raw: &[u8; DERP_KEY_LEN]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(DERP_MAGIC.len() + DERP_KEY_LEN);
    payload.extend_from_slice(DERP_MAGIC);
    payload.extend_from_slice(public_key_raw);
    payload
}

fn parse_server_key_payload(payload: &[u8]) -> AppResult<[u8; DERP_KEY_LEN]> {
    if payload.len() != DERP_MAGIC.len() + DERP_KEY_LEN {
        return Err(AppError::Unauthorized(
            "DERP server-key payload length is invalid".to_string(),
        ));
    }
    if &payload[..DERP_MAGIC.len()] != DERP_MAGIC {
        return Err(AppError::Unauthorized(
            "DERP server-key payload magic is invalid".to_string(),
        ));
    }

    let mut public_key_raw = [0_u8; DERP_KEY_LEN];
    public_key_raw.copy_from_slice(&payload[DERP_MAGIC.len()..]);
    Ok(public_key_raw)
}

fn seal_box(
    private_key: &[u8; DERP_KEY_LEN],
    peer_public_key: &[u8; DERP_KEY_LEN],
    plaintext: &[u8],
) -> AppResult<Vec<u8>> {
    let cipher = SalsaBox::new(
        &PublicKey::from(*peer_public_key),
        &SecretKey::from(*private_key),
    );
    let mut nonce_bytes = [0_u8; DERP_NONCE_LEN];
    random::fill(&mut nonce_bytes)
        .map_err(|err| AppError::Bootstrap(format!("failed to generate DERP nonce: {err}")))?;
    let nonce = GenericArray::clone_from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|err| AppError::Bootstrap(format!("failed to encrypt DERP frame: {err}")))?;
    let mut payload = Vec::with_capacity(DERP_NONCE_LEN + ciphertext.len());
    payload.extend_from_slice(&nonce_bytes);
    payload.extend_from_slice(&ciphertext);
    Ok(payload)
}

fn open_box(
    private_key: &[u8; DERP_KEY_LEN],
    peer_public_key: &[u8; DERP_KEY_LEN],
    ciphertext: &[u8],
) -> AppResult<Vec<u8>> {
    if ciphertext.len() < DERP_NONCE_LEN {
        return Err(AppError::Unauthorized(
            "DERP nacl box is missing its nonce".to_string(),
        ));
    }

    let cipher = SalsaBox::new(
        &PublicKey::from(*peer_public_key),
        &SecretKey::from(*private_key),
    );
    let nonce = GenericArray::clone_from_slice(&ciphertext[..DERP_NONCE_LEN]);
    cipher
        .decrypt(&nonce, &ciphertext[DERP_NONCE_LEN..])
        .map_err(|_| AppError::Unauthorized("failed to open DERP client nacl box".to_string()))
}

fn peer_present_flags(client: &RelayClient) -> u8 {
    let mut flags = if client.can_mesh {
        PEER_PRESENT_IS_MESH_PEER
    } else {
        PEER_PRESENT_IS_REGULAR
    };
    if client.is_prober {
        flags |= PEER_PRESENT_IS_PROBER;
    }
    flags
}

fn socket_addr_ip_bytes(addr: SocketAddr) -> [u8; 16] {
    match addr.ip() {
        IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
        IpAddr::V6(ip) => ip.octets(),
    }
}

fn lookup_mesh_url_override<'a>(config: &'a DerpConfig, node_name: &str) -> Option<&'a str> {
    config
        .regions
        .iter()
        .flat_map(|region| region.nodes.iter())
        .find(|node| node.name == node_name)
        .and_then(|node| node.mesh_url.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn mesh_url_for_node(node: &ControlDerpNode, mesh_url_override: Option<&str>) -> AppResult<String> {
    if let Some(mesh_url_override) = mesh_url_override {
        return normalize_mesh_url(mesh_url_override);
    }

    let scheme = if node.insecure_for_tests { "ws" } else { "wss" };
    let default_port = if scheme == "wss" { 443 } else { 80 };
    let authority = if node.derp_port == 0 || node.derp_port == default_port {
        node.host_name.clone()
    } else {
        format!("{}:{}", node.host_name, node.derp_port)
    };
    Ok(format!("{scheme}://{authority}/derp"))
}

fn normalize_mesh_url(value: &str) -> AppResult<String> {
    let trimmed = value.trim();
    let normalized = if let Some(rest) = trimmed.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = trimmed.strip_prefix("http://") {
        format!("ws://{rest}")
    } else if trimmed.starts_with("wss://") || trimmed.starts_with("ws://") {
        trimmed.to_string()
    } else {
        return Err(AppError::InvalidConfig(format!(
            "DERP mesh URL must use http, https, ws, or wss: {trimmed}"
        )));
    };

    let Some((_, after_scheme)) = normalized.split_once("://") else {
        return Err(AppError::InvalidConfig(format!(
            "DERP mesh URL must contain a scheme separator: {trimmed}"
        )));
    };
    let has_path = after_scheme.contains('/');
    if has_path {
        Ok(normalized)
    } else {
        Ok(format!("{normalized}/derp"))
    }
}

fn parse_mesh_key(value: &str) -> AppResult<[u8; DERP_KEY_LEN]> {
    let trimmed = value.trim();
    if trimmed.len() != 64 {
        return Err(AppError::InvalidConfig(
            "DERP mesh key must contain exactly 64 hex characters".to_string(),
        ));
    }

    let mut mesh_key = [0_u8; DERP_KEY_LEN];
    for (index, byte) in mesh_key.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&trimmed[offset..offset + 2], 16).map_err(|err| {
            AppError::InvalidConfig(format!("failed to decode DERP mesh key: {err}"))
        })?;
    }
    Ok(mesh_key)
}

fn parse_stun_binding_request(packet: &[u8]) -> Result<[u8; 12], &'static str> {
    if !is_stun(packet) {
        return Err("not a STUN packet");
    }

    if packet[..2] != STUN_BINDING_REQUEST {
        return Err("not a STUN binding request");
    }

    let attrs_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if STUN_HEADER_LEN + attrs_len > packet.len() {
        return Err("STUN packet attributes are truncated");
    }

    let mut txid = [0_u8; 12];
    txid.copy_from_slice(&packet[8..20]);

    let mut software_ok = false;
    let mut last_attr = None;
    let mut fingerprint = None;
    foreach_stun_attr(
        &packet[STUN_HEADER_LEN..STUN_HEADER_LEN + attrs_len],
        |attr_type, attr_value| {
            last_attr = Some(attr_type);
            if attr_type == STUN_ATTR_SOFTWARE && attr_value == STUN_SOFTWARE {
                software_ok = true;
            }
            if attr_type == STUN_ATTR_FINGERPRINT && attr_value.len() == 4 {
                fingerprint = Some(u32::from_be_bytes([
                    attr_value[0],
                    attr_value[1],
                    attr_value[2],
                    attr_value[3],
                ]));
            }
            Ok(())
        },
    )?;

    if !software_ok {
        return Err("STUN binding request did not include the expected SOFTWARE attribute");
    }

    if last_attr != Some(STUN_ATTR_FINGERPRINT) {
        return Err("STUN binding request did not end with a fingerprint");
    }

    let fingerprint = fingerprint.ok_or("STUN binding request fingerprint is missing")?;
    let expected = stun_fingerprint(&packet[..packet.len() - STUN_FINGERPRINT_LEN]);
    if fingerprint != expected {
        return Err("STUN binding request fingerprint did not match");
    }

    Ok(txid)
}

fn build_stun_binding_response(txid: [u8; 12], addr: SocketAddr) -> Vec<u8> {
    let ip = match addr.ip() {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    };
    let family = match addr.ip() {
        IpAddr::V4(_) => 0x01,
        IpAddr::V6(_) => 0x02,
    };
    let attr_len = 4 + ip.len();
    let message_len = 4 + attr_len;
    let mut response = Vec::with_capacity(STUN_HEADER_LEN + message_len);
    response.extend_from_slice(&STUN_BINDING_SUCCESS);
    response.extend_from_slice(&(message_len as u16).to_be_bytes());
    response.extend_from_slice(&STUN_MAGIC_COOKIE);
    response.extend_from_slice(&txid);
    response.extend_from_slice(&STUN_ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
    response.extend_from_slice(&(attr_len as u16).to_be_bytes());
    response.push(0);
    response.push(family);
    response.extend_from_slice(&(addr.port() ^ 0x2112).to_be_bytes());
    for (index, byte) in ip.iter().enumerate() {
        let mask = if index < STUN_MAGIC_COOKIE.len() {
            STUN_MAGIC_COOKIE[index]
        } else {
            txid[index - STUN_MAGIC_COOKIE.len()]
        };
        response.push(byte ^ mask);
    }
    response
}

fn is_stun(packet: &[u8]) -> bool {
    packet.len() >= STUN_HEADER_LEN
        && packet[0] & 0b1100_0000 == 0
        && packet[4..8] == STUN_MAGIC_COOKIE
}

fn stun_fingerprint(packet: &[u8]) -> u32 {
    crc32_hash(packet) ^ 0x5354_554e
}

fn foreach_stun_attr(
    mut payload: &[u8],
    mut callback: impl FnMut(u16, &[u8]) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    while !payload.is_empty() {
        if payload.len() < 4 {
            return Err("STUN attribute header is truncated");
        }
        let attr_type = u16::from_be_bytes([payload[0], payload[1]]);
        let attr_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
        let padded_len = (attr_len + 3) & !3;
        payload = &payload[4..];
        if padded_len > payload.len() {
            return Err("STUN attribute payload is truncated");
        }
        callback(attr_type, &payload[..attr_len])?;
        payload = &payload[padded_len..];
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    #[test]
    fn stun_binding_request_round_trip() -> TestResult {
        let txid = [7_u8; 12];
        let request = build_stun_binding_request(txid);
        let parsed = parse_stun_binding_request(&request)?;
        assert_eq!(parsed, txid);

        let response = build_stun_binding_response(txid, "203.0.113.10:41641".parse()?);
        assert_eq!(&response[..2], &STUN_BINDING_SUCCESS);
        assert_eq!(&response[4..8], &STUN_MAGIC_COOKIE);
        assert_eq!(&response[8..20], &txid);

        Ok(())
    }

    #[test]
    fn derp_nacl_box_round_trip() -> TestResult {
        let private_a = parse_node_private_key(
            "privkey:1111111111111111111111111111111111111111111111111111111111111111",
        )?;
        let public_a = parse_node_public_key(&node_public_key_from_private(&private_a))?;
        let private_b = parse_node_private_key(
            "privkey:2222222222222222222222222222222222222222222222222222222222222222",
        )?;
        let public_b = parse_node_public_key(&node_public_key_from_private(&private_b))?;

        let sealed = seal_box(&private_a, &public_b, b"hello derp")?;
        let opened = open_box(&private_b, &public_a, &sealed)?;
        assert_eq!(opened, b"hello derp");

        Ok(())
    }

    #[test]
    fn websocket_protocol_parser_accepts_derp() {
        assert!(protocols_contain_derp("derp"));
        assert!(protocols_contain_derp("chat, derp"));
        assert!(!protocols_contain_derp("chat"));
    }

    #[test]
    fn mesh_key_parser_requires_32_bytes_of_hex() {
        assert!(
            parse_mesh_key("3333333333333333333333333333333333333333333333333333333333333333")
                .is_ok()
        );
        assert!(parse_mesh_key("nope").is_err());
    }

    #[test]
    fn normalize_mesh_url_converts_http_variants() -> TestResult {
        assert_eq!(
            normalize_mesh_url("https://derp.example.com")?,
            "wss://derp.example.com/derp"
        );
        assert_eq!(
            normalize_mesh_url("http://derp.example.com/derp")?,
            "ws://derp.example.com/derp"
        );

        Ok(())
    }

    #[test]
    fn mesh_url_for_node_defaults_to_wss() -> TestResult {
        let node = ControlDerpNode {
            name: "900b".to_string(),
            host_name: "derp-b.example.com".to_string(),
            derp_port: 443,
            ..ControlDerpNode::default()
        };

        assert_eq!(
            mesh_url_for_node(&node, None)?,
            "wss://derp-b.example.com/derp"
        );

        Ok(())
    }

    #[tokio::test]
    async fn regular_clients_receive_existing_peers_and_new_peer_broadcast() -> TestResult {
        let server_private_key = parse_node_private_key(
            "privkey:1111111111111111111111111111111111111111111111111111111111111111",
        )?;
        let server_public_key = node_public_key_from_private(&server_private_key);
        let server_public_key_raw = parse_node_public_key(&server_public_key)?;
        let server = EmbeddedDerpServer {
            inner: Arc::new(EmbeddedDerpServerInner {
                database: None,
                verify_clients: false,
                keepalive_interval: Duration::from_secs(60),
                mesh_key: None,
                mesh_key_hex: None,
                mesh_retry_interval: Duration::from_secs(60),
                server_private_key,
                server_public_key,
                server_public_key_raw,
                relay: RelayState::default(),
                mesh: MeshState::default(),
                metrics: RelayMetrics::default(),
            }),
        };

        let (sender_a, mut receiver_a) = mpsc::channel(4);
        let (sender_b, mut receiver_b) = mpsc::channel(4);
        let client_a = RelayClient {
            client_id: 1,
            public_key: node_public_key_from_private(&parse_node_private_key(
                "privkey:2222222222222222222222222222222222222222222222222222222222222222",
            )?),
            public_key_raw: parse_node_public_key(&node_public_key_from_private(
                &parse_node_private_key(
                    "privkey:2222222222222222222222222222222222222222222222222222222222222222",
                )?,
            ))?,
            sender: sender_a,
            remote_addr: "203.0.113.10:41641".parse()?,
            can_mesh: false,
            is_prober: false,
        };
        let client_b = RelayClient {
            client_id: 2,
            public_key: node_public_key_from_private(&parse_node_private_key(
                "privkey:3333333333333333333333333333333333333333333333333333333333333333",
            )?),
            public_key_raw: parse_node_public_key(&node_public_key_from_private(
                &parse_node_private_key(
                    "privkey:3333333333333333333333333333333333333333333333333333333333333333",
                )?,
            ))?,
            sender: sender_b,
            remote_addr: "203.0.113.11:41642".parse()?,
            can_mesh: false,
            is_prober: false,
        };

        server.inner.relay.register(client_a.clone());
        server.inner.relay.register(client_b.clone());

        server.send_existing_regular_peers(&client_b).await;
        let frame_for_b = receiver_b
            .recv()
            .await
            .ok_or_else(|| std::io::Error::other("missing peer-present for new client"))?;
        match frame_for_b {
            OutboundFrame::PeerPresent {
                peer_public_key_raw,
                port,
                ..
            } => {
                assert_eq!(peer_public_key_raw, client_a.public_key_raw);
                assert_eq!(port, client_a.remote_addr.port());
            }
            other => {
                return Err(std::io::Error::other(format!(
                    "unexpected frame for new client: {other:?}"
                ))
                .into());
            }
        }

        server
            .broadcast_peer_present_to_regular_clients(&client_b)
            .await;
        let frame_for_a = receiver_a
            .recv()
            .await
            .ok_or_else(|| std::io::Error::other("missing peer-present for existing client"))?;
        match frame_for_a {
            OutboundFrame::PeerPresent {
                peer_public_key_raw,
                port,
                ..
            } => {
                assert_eq!(peer_public_key_raw, client_b.public_key_raw);
                assert_eq!(port, client_b.remote_addr.port());
            }
            other => {
                return Err(std::io::Error::other(format!(
                    "unexpected frame for existing client: {other:?}"
                ))
                .into());
            }
        }

        Ok(())
    }

    fn build_stun_binding_request(txid: [u8; 12]) -> Vec<u8> {
        let software_attr_len = 4 + STUN_SOFTWARE.len();
        let mut request =
            Vec::with_capacity(STUN_HEADER_LEN + software_attr_len + STUN_FINGERPRINT_LEN);
        request.extend_from_slice(&STUN_BINDING_REQUEST);
        request
            .extend_from_slice(&((software_attr_len + STUN_FINGERPRINT_LEN) as u16).to_be_bytes());
        request.extend_from_slice(&STUN_MAGIC_COOKIE);
        request.extend_from_slice(&txid);
        request.extend_from_slice(&STUN_ATTR_SOFTWARE.to_be_bytes());
        request.extend_from_slice(&(STUN_SOFTWARE.len() as u16).to_be_bytes());
        request.extend_from_slice(STUN_SOFTWARE);
        let fingerprint = stun_fingerprint(&request);
        request.extend_from_slice(&STUN_ATTR_FINGERPRINT.to_be_bytes());
        request.extend_from_slice(&4_u16.to_be_bytes());
        request.extend_from_slice(&fingerprint.to_be_bytes());
        request
    }
}

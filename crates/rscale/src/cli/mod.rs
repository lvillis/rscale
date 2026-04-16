use std::env;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use reqx::prelude::{Client, RetryPolicy};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use tracing::{info, warn};
use uuid::Uuid;

use crate::config::AppConfig;
use crate::domain::{AclPolicy, BackupSnapshot, DnsConfig};
use crate::error::{AppError, AppResult};
use crate::infra::{auth::oidc, telemetry};
use crate::server;
use crate::{SERVICE_NAME, VERSION};

#[derive(Debug, Parser)]
#[command(name = "rscale", version = VERSION, about = "Control plane server and administrative CLI for rscale")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    Server(ServerArgs),
    Version,
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    Admin(AdminArgs),
    Register(RegisterArgs),
}

#[derive(Debug, Args)]
struct AdminArgs {
    #[arg(long, env = "RSCALE_API_URL")]
    api_url: String,
    #[arg(long, env = "RSCALE_ADMIN_TOKEN")]
    token: String,
    #[command(subcommand)]
    command: AdminCommand,
}

#[derive(Debug, Args)]
struct RegisterArgs {
    #[arg(long, env = "RSCALE_API_URL")]
    api_url: String,
    #[arg(long, env = "RSCALE_AUTH_KEY")]
    auth_key: Option<String>,
    #[command(subcommand)]
    command: RegisterCommand,
}

#[derive(Debug, Args, Default)]
struct ServerArgs {
    #[arg(long, env = "RSCALE_CONFIG")]
    config: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    Validate {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Doctor {
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum AdminCommand {
    Health,
    Config,
    DerpMap,
    Nodes {
        #[command(subcommand)]
        command: NodeCommand,
    },
    AuthKeys {
        #[command(subcommand)]
        command: AuthKeyCommand,
    },
    Routes {
        #[command(subcommand)]
        command: RouteCommand,
    },
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    Dns {
        #[command(subcommand)]
        command: DnsCommand,
    },
    Audit {
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    Backup {
        #[command(subcommand)]
        command: BackupCommand,
    },
}

#[derive(Debug, Subcommand)]
enum NodeCommand {
    List,
    Get { id: u64 },
    Create(CreateNodeArgs),
    Update(UpdateNodeArgs),
    Disable { id: u64 },
}

#[derive(Debug, Subcommand)]
enum AuthKeyCommand {
    List,
    Create(CreateAuthKeyArgs),
    Revoke { id: String },
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    Get,
    Apply {
        #[arg(long)]
        input: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum DnsCommand {
    Get,
    Apply {
        #[arg(long)]
        input: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum BackupCommand {
    Export {
        #[arg(long)]
        output: Option<PathBuf>,
    },
    Restore {
        #[arg(long)]
        input: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum RegisterCommand {
    Node(RegisterNodeArgs),
    Heartbeat(NodeSessionArgs),
    Map(NodeSessionArgs),
}

#[derive(Debug, Args)]
struct CreateNodeArgs {
    #[arg(long)]
    name: String,
    #[arg(long)]
    hostname: String,
    #[arg(long)]
    ipv4: Option<String>,
    #[arg(long)]
    ipv6: Option<String>,
    #[arg(long = "tag")]
    tags: Vec<String>,
}

#[derive(Debug, Args)]
struct UpdateNodeArgs {
    #[arg(long)]
    id: u64,
    #[arg(long)]
    name: Option<String>,
    #[arg(long)]
    hostname: Option<String>,
    #[arg(long = "tag")]
    tags: Vec<String>,
    #[arg(long, default_value_t = false)]
    clear_tags: bool,
}

#[derive(Debug, Args)]
struct CreateAuthKeyArgs {
    #[arg(long)]
    description: Option<String>,
    #[arg(long = "tag")]
    tags: Vec<String>,
    #[arg(long, default_value_t = false)]
    reusable: bool,
    #[arg(long, default_value_t = false)]
    ephemeral: bool,
    #[arg(long)]
    expires_at_unix_secs: Option<u64>,
}

#[derive(Debug, Args)]
struct RegisterNodeArgs {
    #[arg(long)]
    hostname: String,
    #[arg(long)]
    name: Option<String>,
    #[arg(long = "tag")]
    tags: Vec<String>,
}

#[derive(Debug, Subcommand)]
enum RouteCommand {
    List,
    Create(CreateRouteArgs),
    Approve { id: u64 },
    Reject { id: u64 },
}

#[derive(Debug, Args)]
struct CreateRouteArgs {
    #[arg(long)]
    node_id: u64,
    #[arg(long)]
    prefix: String,
    #[arg(long, action = clap::ArgAction::Set, default_value_t = true)]
    advertised: bool,
    #[arg(long, default_value_t = false)]
    is_exit_node: bool,
}

#[derive(Debug, Args)]
struct NodeSessionArgs {
    #[arg(long)]
    node_id: u64,
    #[arg(long, env = "RSCALE_SESSION_TOKEN")]
    session_token: String,
}

pub async fn run() -> AppResult<()> {
    let cli = Cli::parse();

    match cli
        .command
        .unwrap_or(Command::Server(ServerArgs::default()))
    {
        Command::Server(args) => run_server(args).await,
        Command::Version => {
            println!("{SERVICE_NAME} {VERSION}");
            Ok(())
        }
        Command::Config { command } => run_config(command),
        Command::Admin(args) => run_admin(args).await,
        Command::Register(args) => run_register(args).await,
    }
}

async fn run_server(args: ServerArgs) -> AppResult<()> {
    let loaded = AppConfig::load_with_report(args.config.as_deref())?;
    let config = loaded.config().clone();

    telemetry::init(&config.telemetry)?;

    if loaded.report().has_warnings() {
        warn!("{}", loaded.report().doctor());
    } else {
        info!("configuration loaded without warnings");
    }

    if let Some(discovery) = oidc::bootstrap(&config.auth.oidc).await? {
        info!(
            issuer = %discovery.issuer,
            authorization_endpoint = %discovery.authorization_endpoint,
            token_endpoint = %discovery.token_endpoint,
            "OIDC discovery validated"
        );
    }

    server::serve(loaded).await
}

fn run_config(command: ConfigCommand) -> AppResult<()> {
    match command {
        ConfigCommand::Validate { config } => {
            let loaded = AppConfig::load_with_report(config.as_deref())?;
            println!("{}", serde_json::to_string_pretty(&loaded.summary())?);
            if loaded.report().has_warnings() {
                eprintln!("{}", loaded.report().doctor());
            }
            Ok(())
        }
        ConfigCommand::Doctor { config } => {
            let loaded = AppConfig::load_with_report(config.as_deref())?;
            println!("{}", loaded.report().doctor_json_pretty());
            Ok(())
        }
    }
}

async fn run_admin(args: AdminArgs) -> AppResult<()> {
    let client = AdminClient::new(args.api_url, args.token)?;

    match args.command {
        AdminCommand::Health => print_json(client.get("/api/v1/admin/health").await?),
        AdminCommand::Config => print_json(client.get("/api/v1/admin/config").await?),
        AdminCommand::DerpMap => print_json(client.get("/api/v1/admin/derp-map").await?),
        AdminCommand::Nodes { command } => run_nodes(&client, command).await,
        AdminCommand::AuthKeys { command } => run_auth_keys(&client, command).await,
        AdminCommand::Routes { command } => run_routes(&client, command).await,
        AdminCommand::Policy { command } => run_policy(&client, command).await,
        AdminCommand::Dns { command } => run_dns(&client, command).await,
        AdminCommand::Audit { limit } => print_json(
            client
                .get(&format!("/api/v1/admin/audit-events?limit={limit}"))
                .await?,
        ),
        AdminCommand::Backup { command } => run_backup(&client, command).await,
    }
}

async fn run_register(args: RegisterArgs) -> AppResult<()> {
    let client = RegistrationClient::new(args.api_url)?;

    match args.command {
        RegisterCommand::Node(command) => {
            let payload = RegisterNodePayload {
                auth_key: resolve_registration_auth_key(args.auth_key)?,
                hostname: command.hostname,
                name: command.name,
                tags: command.tags,
            };
            print_json(client.post("/api/v1/register/nodes", &payload).await?)
        }
        RegisterCommand::Heartbeat(command) => {
            let session_token = resolve_session_token(command.session_token)?;
            print_json(
                client
                    .post_empty_with_bearer(
                        &format!("/api/v1/control/nodes/{}/heartbeat", command.node_id),
                        &session_token,
                    )
                    .await?,
            )
        }
        RegisterCommand::Map(command) => {
            let session_token = resolve_session_token(command.session_token)?;
            print_json(
                client
                    .get_with_bearer(
                        &format!("/api/v1/control/nodes/{}/map", command.node_id),
                        &session_token,
                    )
                    .await?,
            )
        }
    }
}

async fn run_nodes(client: &AdminClient, command: NodeCommand) -> AppResult<()> {
    match command {
        NodeCommand::List => print_json(client.get("/api/v1/admin/nodes").await?),
        NodeCommand::Get { id } => {
            print_json(client.get(&format!("/api/v1/admin/nodes/{id}")).await?)
        }
        NodeCommand::Create(args) => {
            let payload = CreateNodePayload {
                name: args.name,
                hostname: args.hostname,
                ipv4: args.ipv4,
                ipv6: args.ipv6,
                tags: args.tags,
            };
            print_json(client.post("/api/v1/admin/nodes", &payload).await?)
        }
        NodeCommand::Update(args) => {
            let payload = UpdateNodePayload {
                name: args.name,
                hostname: args.hostname,
                tags: if args.clear_tags || !args.tags.is_empty() {
                    Some(args.tags)
                } else {
                    None
                },
            };
            print_json(
                client
                    .patch(&format!("/api/v1/admin/nodes/{}", args.id), &payload)
                    .await?,
            )
        }
        NodeCommand::Disable { id } => print_json(
            client
                .post_empty(&format!("/api/v1/admin/nodes/{id}/disable"))
                .await?,
        ),
    }
}

async fn run_auth_keys(client: &AdminClient, command: AuthKeyCommand) -> AppResult<()> {
    match command {
        AuthKeyCommand::List => print_json(client.get("/api/v1/admin/auth-keys").await?),
        AuthKeyCommand::Create(args) => {
            let payload = CreateAuthKeyPayload {
                description: args.description,
                tags: args.tags,
                reusable: args.reusable,
                ephemeral: args.ephemeral,
                expires_at_unix_secs: args.expires_at_unix_secs,
            };
            print_json(client.post("/api/v1/admin/auth-keys", &payload).await?)
        }
        AuthKeyCommand::Revoke { id } => print_json(
            client
                .post_empty(&format!("/api/v1/admin/auth-keys/{id}/revoke"))
                .await?,
        ),
    }
}

async fn run_routes(client: &AdminClient, command: RouteCommand) -> AppResult<()> {
    match command {
        RouteCommand::List => print_json(client.get("/api/v1/admin/routes").await?),
        RouteCommand::Create(args) => {
            let payload = CreateRoutePayload {
                node_id: args.node_id,
                prefix: args.prefix,
                advertised: args.advertised,
                is_exit_node: args.is_exit_node,
            };
            print_json(client.post("/api/v1/admin/routes", &payload).await?)
        }
        RouteCommand::Approve { id } => print_json(
            client
                .post_empty(&format!("/api/v1/admin/routes/{id}/approve"))
                .await?,
        ),
        RouteCommand::Reject { id } => print_json(
            client
                .post_empty(&format!("/api/v1/admin/routes/{id}/reject"))
                .await?,
        ),
    }
}

async fn run_policy(client: &AdminClient, command: PolicyCommand) -> AppResult<()> {
    match command {
        PolicyCommand::Get => print_json(client.get("/api/v1/admin/policy").await?),
        PolicyCommand::Apply { input } => {
            let policy = read_json_input::<AclPolicy>(&input)?;
            print_json(client.put("/api/v1/admin/policy", &policy).await?)
        }
    }
}

async fn run_dns(client: &AdminClient, command: DnsCommand) -> AppResult<()> {
    match command {
        DnsCommand::Get => print_json(client.get("/api/v1/admin/dns").await?),
        DnsCommand::Apply { input } => {
            let dns = read_json_input::<DnsConfig>(&input)?;
            print_json(client.put("/api/v1/admin/dns", &dns).await?)
        }
    }
}

async fn run_backup(client: &AdminClient, command: BackupCommand) -> AppResult<()> {
    match command {
        BackupCommand::Export { output } => {
            let snapshot = client
                .get_typed::<BackupSnapshot>("/api/v1/admin/backup/export")
                .await?;
            write_json_output(&snapshot, output.as_deref())
        }
        BackupCommand::Restore { input } => {
            let snapshot = read_json_input::<BackupSnapshot>(&input)?;
            print_json(
                client
                    .post("/api/v1/admin/backup/restore", &snapshot)
                    .await?,
            )
        }
    }
}

fn print_json(value: Value) -> AppResult<()> {
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

fn read_json_input<T>(path: &Path) -> AppResult<T>
where
    T: DeserializeOwned,
{
    let contents = if path == Path::new("-") {
        let mut buffer = String::new();
        io::stdin().read_to_string(&mut buffer)?;
        buffer
    } else {
        std::fs::read_to_string(path)?
    };

    Ok(serde_json::from_str(&contents)?)
}

fn write_json_output<T>(value: &T, output: Option<&Path>) -> AppResult<()>
where
    T: Serialize,
{
    let encoded = serde_json::to_string_pretty(value)?;
    match output {
        Some(path) => std::fs::write(path, format!("{encoded}\n"))?,
        None => println!("{encoded}"),
    }
    Ok(())
}

#[derive(Clone)]
struct AdminClient {
    client: Client,
}

impl AdminClient {
    fn new(api_url: String, token: String) -> AppResult<Self> {
        let token = resolve_admin_token(token)?;
        let client = Client::builder(api_url)
            .client_name("rscale-cli")
            .request_timeout(Duration::from_secs(5))
            .total_timeout(Duration::from_secs(15))
            .retry_policy(
                RetryPolicy::standard()
                    .max_attempts(2)
                    .base_backoff(Duration::from_millis(100))
                    .max_backoff(Duration::from_millis(500)),
            )
            .try_default_header("authorization", &format!("Bearer {token}"))?
            .try_default_header("accept", "application/json")?
            .build()
            .map_err(|err| {
                AppError::Bootstrap(format!("failed to build CLI HTTP client: {err}"))
            })?;

        Ok(Self { client })
    }

    async fn get(&self, path: &str) -> AppResult<Value> {
        Ok(self.client.get(path).send_json().await?)
    }

    async fn get_typed<T>(&self, path: &str) -> AppResult<T>
    where
        T: DeserializeOwned,
    {
        Ok(self.client.get(path).send_json().await?)
    }

    async fn post<T>(&self, path: &str, payload: &T) -> AppResult<Value>
    where
        T: Serialize,
    {
        Ok(self
            .client
            .post(path)
            .idempotency_key(&Uuid::new_v4().to_string())?
            .json(payload)?
            .send_json()
            .await?)
    }

    async fn post_empty(&self, path: &str) -> AppResult<Value> {
        Ok(self
            .client
            .post(path)
            .idempotency_key(&Uuid::new_v4().to_string())?
            .send_json()
            .await?)
    }

    async fn put<T>(&self, path: &str, payload: &T) -> AppResult<Value>
    where
        T: Serialize,
    {
        Ok(self
            .client
            .put(path)
            .idempotency_key(&Uuid::new_v4().to_string())?
            .json(payload)?
            .send_json()
            .await?)
    }

    async fn patch<T>(&self, path: &str, payload: &T) -> AppResult<Value>
    where
        T: Serialize,
    {
        Ok(self
            .client
            .patch(path)
            .idempotency_key(&Uuid::new_v4().to_string())?
            .json(payload)?
            .send_json()
            .await?)
    }
}

#[derive(Clone)]
struct RegistrationClient {
    client: Client,
}

impl RegistrationClient {
    fn new(api_url: String) -> AppResult<Self> {
        let client = Client::builder(api_url)
            .client_name("rscale-register")
            .request_timeout(Duration::from_secs(5))
            .total_timeout(Duration::from_secs(15))
            .retry_policy(
                RetryPolicy::standard()
                    .max_attempts(2)
                    .base_backoff(Duration::from_millis(100))
                    .max_backoff(Duration::from_millis(500)),
            )
            .try_default_header("accept", "application/json")?
            .build()
            .map_err(|err| {
                AppError::Bootstrap(format!("failed to build registration HTTP client: {err}"))
            })?;

        Ok(Self { client })
    }

    async fn post<T>(&self, path: &str, payload: &T) -> AppResult<Value>
    where
        T: Serialize,
    {
        Ok(self
            .client
            .post(path)
            .idempotency_key(&Uuid::new_v4().to_string())?
            .json(payload)?
            .send_json()
            .await?)
    }

    async fn post_empty_with_bearer(&self, path: &str, token: &str) -> AppResult<Value> {
        Ok(self
            .client
            .post(path)
            .idempotency_key(&Uuid::new_v4().to_string())?
            .try_header("authorization", &format!("Bearer {token}"))?
            .send_json()
            .await?)
    }

    async fn get_with_bearer(&self, path: &str, token: &str) -> AppResult<Value> {
        Ok(self
            .client
            .get(path)
            .try_header("authorization", &format!("Bearer {token}"))?
            .send_json()
            .await?)
    }
}

fn resolve_admin_token(token: String) -> AppResult<String> {
    resolve_secret_input("administrator token", token)
}

fn resolve_registration_auth_key(auth_key: Option<String>) -> AppResult<String> {
    let auth_key = auth_key.ok_or_else(|| {
        AppError::InvalidConfig(
            "registration auth key is required for node registration".to_string(),
        )
    })?;
    resolve_secret_input("registration auth key", auth_key)
}

fn resolve_session_token(session_token: String) -> AppResult<String> {
    resolve_secret_input("node session token", session_token)
}

fn resolve_secret_input(label: &str, value: String) -> AppResult<String> {
    if let Some(path) = value.strip_prefix('@') {
        let contents = std::fs::read_to_string(path)?;
        let trimmed = contents.trim().to_string();
        if trimmed.is_empty() {
            return Err(AppError::InvalidConfig(format!("{label} file is empty")));
        }

        return Ok(trimmed);
    }

    if value.starts_with("env:") {
        let variable = value.trim_start_matches("env:");
        let resolved = env::var(variable).map_err(|_| {
            AppError::InvalidConfig(format!(
                "{label} environment variable {variable} is not set"
            ))
        })?;

        if resolved.trim().is_empty() {
            return Err(AppError::InvalidConfig(format!(
                "{label} environment variable {variable} is empty"
            )));
        }

        return Ok(resolved);
    }

    if value.trim().is_empty() {
        return Err(AppError::InvalidConfig(format!(
            "{label} must not be empty"
        )));
    }

    Ok(value)
}

#[derive(Debug, Clone, Serialize)]
struct CreateNodePayload {
    name: String,
    hostname: String,
    ipv4: Option<String>,
    ipv6: Option<String>,
    tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct UpdateNodePayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize)]
struct CreateAuthKeyPayload {
    description: Option<String>,
    tags: Vec<String>,
    reusable: bool,
    ephemeral: bool,
    expires_at_unix_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
struct CreateRoutePayload {
    node_id: u64,
    prefix: String,
    advertised: bool,
    is_exit_node: bool,
}

#[derive(Debug, Clone, Serialize)]
struct RegisterNodePayload {
    auth_key: String,
    hostname: String,
    name: Option<String>,
    tags: Vec<String>,
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fs;

    use super::*;

    #[test]
    fn cli_parses_register_node_command() -> Result<(), Box<dyn Error>> {
        let cli = Cli::try_parse_from([
            "rscale",
            "register",
            "--api-url",
            "http://127.0.0.1:8080",
            "--auth-key",
            "tskey-auth-123",
            "node",
            "--hostname",
            "builder-01",
            "--name",
            "builder",
            "--tag",
            "tag:prod",
        ])?;

        let Some(Command::Register(RegisterArgs {
            api_url,
            auth_key,
            command:
                RegisterCommand::Node(RegisterNodeArgs {
                    hostname,
                    name,
                    tags,
                }),
        })) = cli.command
        else {
            return Err(std::io::Error::other("unexpected CLI parse result").into());
        };

        assert_eq!(api_url, "http://127.0.0.1:8080");
        assert_eq!(auth_key.as_deref(), Some("tskey-auth-123"));
        assert_eq!(hostname, "builder-01");
        assert_eq!(name.as_deref(), Some("builder"));
        assert_eq!(tags, vec!["tag:prod"]);
        Ok(())
    }

    #[test]
    fn cli_parses_admin_route_creation_flags() -> Result<(), Box<dyn Error>> {
        let cli = Cli::try_parse_from([
            "rscale",
            "admin",
            "--api-url",
            "http://127.0.0.1:8080",
            "--token",
            "secret-token",
            "routes",
            "create",
            "--node-id",
            "7",
            "--prefix",
            "10.0.0.0/24",
            "--advertised=false",
            "--is-exit-node",
        ])?;

        let Some(Command::Admin(AdminArgs {
            api_url,
            token,
            command:
                AdminCommand::Routes {
                    command:
                        RouteCommand::Create(CreateRouteArgs {
                            node_id,
                            prefix,
                            advertised,
                            is_exit_node,
                        }),
                },
        })) = cli.command
        else {
            return Err(std::io::Error::other("unexpected CLI parse result").into());
        };

        assert_eq!(api_url, "http://127.0.0.1:8080");
        assert_eq!(token, "secret-token");
        assert_eq!(node_id, 7);
        assert_eq!(prefix, "10.0.0.0/24");
        assert!(!advertised);
        assert!(is_exit_node);
        Ok(())
    }

    #[test]
    fn cli_allows_implicit_server_mode() -> Result<(), Box<dyn Error>> {
        let cli = Cli::try_parse_from(["rscale"])?;
        assert!(cli.command.is_none());
        Ok(())
    }

    #[test]
    fn resolve_secret_input_accepts_inline_file_and_env_sources() -> Result<(), Box<dyn Error>> {
        let temp_path = temp_path("secret.txt");
        fs::write(&temp_path, "line-from-file\n")?;
        assert_eq!(
            resolve_secret_input("secret", format!("@{}", temp_path.display()))?,
            "line-from-file"
        );
        fs::remove_file(&temp_path)?;

        let (env_key, env_value) = env::vars()
            .find(|(_, value)| !value.trim().is_empty())
            .ok_or_else(|| {
                std::io::Error::other(
                    "test process should expose at least one non-empty environment variable",
                )
            })?;
        assert_eq!(
            resolve_secret_input("secret", format!("env:{env_key}"))?,
            env_value
        );
        Ok(())
    }

    #[test]
    fn resolve_secret_input_rejects_missing_or_empty_sources() -> Result<(), Box<dyn Error>> {
        let missing_env = format!("RSCALE_TEST_SECRET_MISSING_{}", Uuid::new_v4().simple());
        let missing = match resolve_secret_input("secret", format!("env:{missing_env}")) {
            Ok(_) => return Err(std::io::Error::other("missing env var should fail").into()),
            Err(err) => err,
        };
        assert!(
            matches!(missing, AppError::InvalidConfig(message) if message.contains("is not set"))
        );

        let empty_path = temp_path("empty-secret.txt");
        fs::write(&empty_path, "\n")?;
        let empty_file = match resolve_secret_input("secret", format!("@{}", empty_path.display()))
        {
            Ok(_) => return Err(std::io::Error::other("empty file should fail").into()),
            Err(err) => err,
        };
        assert!(
            matches!(empty_file, AppError::InvalidConfig(message) if message.contains("file is empty"))
        );
        fs::remove_file(&empty_path)?;

        let blank = match resolve_secret_input("secret", "   ".to_string()) {
            Ok(_) => return Err(std::io::Error::other("blank inline secret should fail").into()),
            Err(err) => err,
        };
        assert!(
            matches!(blank, AppError::InvalidConfig(message) if message.contains("must not be empty"))
        );
        Ok(())
    }

    #[test]
    fn resolve_registration_auth_key_requires_a_value() -> Result<(), Box<dyn Error>> {
        let err = match resolve_registration_auth_key(None) {
            Ok(_) => {
                return Err(std::io::Error::other("missing auth key should be rejected").into());
            }
            Err(err) => err,
        };
        assert!(
            matches!(err, AppError::InvalidConfig(message) if message.contains("registration auth key is required"))
        );
        Ok(())
    }

    #[test]
    fn read_json_input_reads_files_and_write_json_output_appends_newline()
    -> Result<(), Box<dyn Error>> {
        let input_path = temp_path("input.json");
        fs::write(&input_path, "{\"hello\":\"world\"}\n")?;
        let value: Value = read_json_input(&input_path)?;
        assert_eq!(value["hello"], "world");

        let output_path = temp_path("output.json");
        write_json_output(&value, Some(&output_path))?;
        let written = fs::read_to_string(&output_path)?;
        assert!(written.ends_with('\n'));
        assert_eq!(serde_json::from_str::<Value>(&written)?, value);

        fs::remove_file(&input_path)?;
        fs::remove_file(&output_path)?;
        Ok(())
    }

    fn temp_path(name: &str) -> PathBuf {
        env::temp_dir().join(format!("rscale-cli-{}-{name}", Uuid::new_v4()))
    }
}

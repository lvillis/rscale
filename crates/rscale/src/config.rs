use std::collections::BTreeMap;
use std::env;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use tier::{ConfigLoader, EnvSource, LoadedConfig, TierConfig, ValidationErrors};

use crate::error::{AppError, AppResult};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default, TierConfig)]
#[serde(default)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub network: NetworkConfig,
    pub database: DatabaseConfig,
    pub auth: AuthConfig,
    pub control: ControlConfig,
    pub derp: DerpConfig,
    pub telemetry: TelemetryConfig,
}

impl AppConfig {
    pub fn load(config_path: Option<&Path>) -> AppResult<Self> {
        Ok(Self::load_with_report(config_path)?.into_inner())
    }

    pub fn load_with_report(config_path: Option<&Path>) -> AppResult<LoadedConfig<Self>> {
        let loader = Self::loader(config_path)?;
        Ok(loader.load()?)
    }

    pub fn validate(&self) -> AppResult<()> {
        Self::validate_bind_addr(self).map_err(|err| AppError::InvalidConfig(err.to_string()))?;
        Self::validate_server(self).map_err(|err| AppError::InvalidConfig(err.to_string()))?;
        Self::validate_network(self).map_err(|err| AppError::InvalidConfig(err.to_string()))?;
        Self::validate_database(self).map_err(|err| AppError::InvalidConfig(err.to_string()))?;
        Self::validate_auth(self).map_err(|err| AppError::InvalidConfig(err.to_string()))?;
        Self::validate_oidc(self).map_err(|err| AppError::InvalidConfig(err.to_string()))?;
        Self::validate_control(self).map_err(|err| AppError::InvalidConfig(err.to_string()))?;
        Self::validate_derp(self).map_err(|err| AppError::InvalidConfig(err.to_string()))?;
        Ok(())
    }

    pub fn bind_addr(&self) -> AppResult<SocketAddr> {
        self.server
            .bind_addr
            .parse::<SocketAddr>()
            .map_err(|err| AppError::InvalidConfig(format!("server.bind_addr is invalid: {err}")))
    }

    pub fn summary(&self) -> ConfigSummary {
        ConfigSummary {
            bind_addr: self.server.bind_addr.clone(),
            web_root_configured: self
                .server
                .web_root
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty()),
            control_protocol_enabled: !self.server.control_private_key.is_empty(),
            tailnet_ipv4_range: self.network.tailnet_ipv4_range.clone(),
            tailnet_ipv6_range: self.network.tailnet_ipv6_range.clone(),
            database_configured: self.database.url.is_some(),
            derp_region_count: self.derp.regions.len() as u32,
            derp_url_count: self.derp.urls.len() as u32,
            derp_path_count: self.derp.paths.len() as u32,
            derp_omit_default_regions: self.derp.omit_default_regions,
            derp_refresh_interval_secs: self.derp.refresh_interval_secs,
            derp_embedded_relay_enabled: self.derp.server.enabled,
            derp_stun_bind_addr: self.derp.server.stun_bind_addr.clone(),
            derp_verify_clients: self.derp.server.verify_clients,
            admin_auth_configured: self.auth.break_glass_token.is_some(),
            oidc_enabled: self.auth.oidc.enabled,
            oidc_discovery_validation: self.auth.oidc.validate_discovery_on_startup,
            control_display_message_count: self.control.display_messages.len() as u32,
            control_dial_candidate_count: self.control.dial_plan.candidates.len() as u32,
            control_client_version_configured: self.control.client_version.latest_version.is_some(),
            control_collect_services_configured: self.control.collect_services.is_some(),
            control_node_attr_count: self.control.node_attrs.enabled_count(),
            control_pop_browser_url_configured: self.control.pop_browser_url.is_some(),
            log_filter: self.telemetry.filter.clone(),
            log_format: self.telemetry.format.as_str().to_string(),
            log_timezone: self.telemetry.timezone.as_str().to_string(),
        }
    }

    fn loader(config_path: Option<&Path>) -> AppResult<ConfigLoader<Self>> {
        let mut loader = ConfigLoader::new(Self::default())
            .derive_metadata()
            .secret_path("server.control_private_key")
            .secret_path("auth.break_glass_token")
            .secret_path("auth.oidc.client_secret")
            .secret_path("derp.server.private_key")
            .secret_path("derp.server.mesh_key")
            .env(Self::env_source())
            .validator("rscale.server.bind_addr", Self::validate_bind_addr)
            .validator("rscale.server", Self::validate_server)
            .validator("rscale.network", Self::validate_network)
            .validator("rscale.database", Self::validate_database)
            .validator("rscale.auth", Self::validate_auth)
            .validator("rscale.auth.oidc", Self::validate_oidc)
            .validator("rscale.control", Self::validate_control)
            .validator("rscale.derp", Self::validate_derp);

        if let Some(path) = Self::resolve_path(config_path)? {
            loader = loader.file(path);
        } else {
            loader = loader
                .optional_file("config.toml")
                .optional_file("config/config.toml")
                .optional_file("rscale.toml")
                .optional_file("config/rscale.toml");
        }

        Ok(loader)
    }

    fn env_source() -> EnvSource {
        Self::env_source_from_pairs(env::vars())
    }

    fn env_source_from_pairs<I, K, V>(iter: I) -> EnvSource
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        EnvSource::from_pairs(iter.into_iter().filter_map(|(name, value)| {
            let name = name.into();
            if name == "RSCALE_CONFIG" {
                None
            } else {
                Some((name, value.into()))
            }
        }))
        .prefix("RSCALE")
        .with_alias("RSCALE_BIND_ADDR", "server.bind_addr")
        .with_alias("RSCALE_WEB_ROOT", "server.web_root")
        .with_alias("RSCALE_CONTROL_PRIVATE_KEY", "server.control_private_key")
        .with_alias("RSCALE_TAILNET_IPV4_RANGE", "network.tailnet_ipv4_range")
        .with_alias("RSCALE_TAILNET_IPV6_RANGE", "network.tailnet_ipv6_range")
        .with_alias("RSCALE_DATABASE_URL", "database.url")
        .with_alias("RSCALE_BREAK_GLASS_TOKEN", "auth.break_glass_token")
        .with_alias("RSCALE_OIDC_ENABLED", "auth.oidc.enabled")
        .with_alias("RSCALE_OIDC_ISSUER_URL", "auth.oidc.issuer_url")
        .with_alias("RSCALE_OIDC_CLIENT_ID", "auth.oidc.client_id")
        .with_alias("RSCALE_OIDC_CLIENT_SECRET", "auth.oidc.client_secret")
        .with_alias(
            "RSCALE_CONTROL_DIAL_CANDIDATE_IP",
            "control.dial_plan.candidates[0].ip",
        )
        .with_alias(
            "RSCALE_CONTROL_TAILNET_DISPLAY_NAME",
            "control.node_attrs.tailnet_display_name",
        )
        .with_alias(
            "RSCALE_CONTROL_CLIENT_LATEST_VERSION",
            "control.client_version.latest_version",
        )
        .with_alias(
            "RSCALE_CONTROL_COLLECT_SERVICES",
            "control.collect_services",
        )
        .with_alias("RSCALE_CONTROL_POP_BROWSER_URL", "control.pop_browser_url")
        .with_alias("RSCALE_DERP_SERVER_ENABLED", "derp.server.enabled")
        .with_alias("RSCALE_DERP_SERVER_PRIVATE_KEY", "derp.server.private_key")
        .with_alias("RSCALE_DERP_SERVER_MESH_KEY", "derp.server.mesh_key")
        .with_alias("RSCALE_DERP_SERVER_NODE_NAME", "derp.server.node_name")
        .with_alias("RSCALE_DERP_STUN_BIND_ADDR", "derp.server.stun_bind_addr")
        .with_alias("RSCALE_LOG_FILTER", "telemetry.filter")
        .with_alias("RSCALE_LOG_FORMAT", "telemetry.format")
        .with_alias("RSCALE_LOG_TIMEZONE", "telemetry.timezone")
    }

    fn resolve_path(config_path: Option<&Path>) -> AppResult<Option<PathBuf>> {
        if let Some(path) = config_path {
            return Ok(Some(path.to_path_buf()));
        }

        match env::var_os("RSCALE_CONFIG") {
            Some(path) if !path.is_empty() => Ok(Some(PathBuf::from(path))),
            Some(_) => Err(AppError::InvalidConfig(
                "RSCALE_CONFIG must not be empty".to_string(),
            )),
            None => Ok(None),
        }
    }

    fn validate_bind_addr(config: &Self) -> Result<(), ValidationErrors> {
        match config.server.bind_addr.parse::<SocketAddr>() {
            Ok(_) => Ok(()),
            Err(err) => Err(ValidationErrors::from_message(
                "server.bind_addr",
                format!("must be a valid socket address: {err}"),
            )),
        }
    }

    fn validate_server(config: &Self) -> Result<(), ValidationErrors> {
        let control_private_key = config.server.control_private_key.trim();
        if control_private_key.is_empty() {
            return Err(ValidationErrors::from_message(
                "server.control_private_key",
                "is required for TS2021 control-plane compatibility",
            ));
        }

        validate_machine_private_key(control_private_key)
            .map_err(|err| ValidationErrors::from_message("server.control_private_key", err))?;

        if config.server.map_poll_interval_secs == 0 {
            return Err(ValidationErrors::from_message(
                "server.map_poll_interval_secs",
                "must be greater than zero",
            ));
        }

        if config.server.map_keepalive_interval_secs == 0 {
            return Err(ValidationErrors::from_message(
                "server.map_keepalive_interval_secs",
                "must be greater than zero",
            ));
        }

        Ok(())
    }

    fn validate_database(config: &Self) -> Result<(), ValidationErrors> {
        if config.database.max_connections == 0 {
            return Err(ValidationErrors::from_message(
                "database.max_connections",
                "must be greater than zero",
            ));
        }

        if config.database.url.as_deref().is_none_or(str::is_empty) {
            return Err(ValidationErrors::from_message(
                "database.url",
                "is required for production startup",
            ));
        }

        Ok(())
    }

    fn validate_network(config: &Self) -> Result<(), ValidationErrors> {
        validate_ipv4_cidr(&config.network.tailnet_ipv4_range)
            .map_err(|err| ValidationErrors::from_message("network.tailnet_ipv4_range", err))?;

        validate_ipv6_cidr(&config.network.tailnet_ipv6_range)
            .map_err(|err| ValidationErrors::from_message("network.tailnet_ipv6_range", err))?;

        if config.network.node_online_window_secs == 0 {
            return Err(ValidationErrors::from_message(
                "network.node_online_window_secs",
                "must be greater than zero",
            ));
        }

        if config.network.node_session_ttl_secs == 0 {
            return Err(ValidationErrors::from_message(
                "network.node_session_ttl_secs",
                "must be greater than zero",
            ));
        }

        Ok(())
    }

    fn validate_auth(config: &Self) -> Result<(), ValidationErrors> {
        if config.auth.break_glass_username.trim().is_empty() {
            return Err(ValidationErrors::from_message(
                "auth.break_glass_username",
                "must not be empty",
            ));
        }

        let Some(token) = config.auth.break_glass_token.as_deref() else {
            return Err(ValidationErrors::from_message(
                "auth.break_glass_token",
                "is required for authenticated administration",
            ));
        };

        if token.trim().is_empty() {
            return Err(ValidationErrors::from_message(
                "auth.break_glass_token",
                "must not be empty",
            ));
        }

        if token.len() < 24 {
            return Err(ValidationErrors::from_message(
                "auth.break_glass_token",
                "must be at least 24 characters long",
            ));
        }

        Ok(())
    }

    fn validate_oidc(config: &Self) -> Result<(), ValidationErrors> {
        let oidc = &config.auth.oidc;

        if !oidc.enabled {
            return Ok(());
        }

        if oidc.issuer_url.as_deref().is_none_or(str::is_empty) {
            return Err(ValidationErrors::from_message(
                "auth.oidc.issuer_url",
                "is required when OIDC is enabled",
            ));
        }

        if oidc.client_id.as_deref().is_none_or(str::is_empty) {
            return Err(ValidationErrors::from_message(
                "auth.oidc.client_id",
                "is required when OIDC is enabled",
            ));
        }

        if oidc.client_secret.as_deref().is_none_or(str::is_empty) {
            return Err(ValidationErrors::from_message(
                "auth.oidc.client_secret",
                "is required when OIDC is enabled",
            ));
        }

        if oidc.request_timeout_secs == 0 {
            return Err(ValidationErrors::from_message(
                "auth.oidc.request_timeout_secs",
                "must be greater than zero",
            ));
        }

        if oidc.total_timeout_secs == 0 {
            return Err(ValidationErrors::from_message(
                "auth.oidc.total_timeout_secs",
                "must be greater than zero",
            ));
        }

        if oidc.total_timeout_secs < oidc.request_timeout_secs {
            return Err(ValidationErrors::from_message(
                "auth.oidc.total_timeout_secs",
                "must be greater than or equal to auth.oidc.request_timeout_secs",
            ));
        }

        if oidc.auth_flow_ttl_secs == 0 {
            return Err(ValidationErrors::from_message(
                "auth.oidc.auth_flow_ttl_secs",
                "must be greater than zero",
            ));
        }

        if oidc.scopes.is_empty() {
            return Err(ValidationErrors::from_message(
                "auth.oidc.scopes",
                "must contain at least one scope when OIDC is enabled",
            ));
        }

        if oidc.scopes.iter().any(|scope| scope.trim().is_empty()) {
            return Err(ValidationErrors::from_message(
                "auth.oidc.scopes",
                "must not contain empty scope values",
            ));
        }

        if oidc
            .allowed_domains
            .iter()
            .any(|value| value.trim().is_empty())
        {
            return Err(ValidationErrors::from_message(
                "auth.oidc.allowed_domains",
                "must not contain empty values",
            ));
        }

        if oidc
            .allowed_users
            .iter()
            .any(|value| value.trim().is_empty())
        {
            return Err(ValidationErrors::from_message(
                "auth.oidc.allowed_users",
                "must not contain empty values",
            ));
        }

        if oidc
            .allowed_groups
            .iter()
            .any(|value| value.trim().is_empty())
        {
            return Err(ValidationErrors::from_message(
                "auth.oidc.allowed_groups",
                "must not contain empty values",
            ));
        }

        if oidc
            .extra_params
            .keys()
            .any(|value| value.trim().is_empty())
        {
            return Err(ValidationErrors::from_message(
                "auth.oidc.extra_params",
                "must not contain empty parameter names",
            ));
        }

        let Some(public_base_url) = config.server.public_base_url.as_deref() else {
            return Err(ValidationErrors::from_message(
                "server.public_base_url",
                "is required when OIDC is enabled",
            ));
        };

        if public_base_url.trim().is_empty() {
            return Err(ValidationErrors::from_message(
                "server.public_base_url",
                "must not be empty when OIDC is enabled",
            ));
        }

        if !is_secure_or_local_http_url(public_base_url) {
            return Err(ValidationErrors::from_message(
                "server.public_base_url",
                "must use https unless it points to a local development endpoint",
            ));
        }

        Ok(())
    }

    fn validate_control(config: &Self) -> Result<(), ValidationErrors> {
        for candidate in &config.control.dial_plan.candidates {
            let ip = candidate.ip.as_deref().map(str::trim).unwrap_or_default();
            let ace_host = candidate
                .ace_host
                .as_deref()
                .map(str::trim)
                .unwrap_or_default();

            if ip.is_empty() && ace_host.is_empty() {
                return Err(ValidationErrors::from_message(
                    "control.dial_plan.candidates[]",
                    "must define at least one of ip or ace_host",
                ));
            }

            if !ip.is_empty() {
                ip.parse::<std::net::IpAddr>().map_err(|err| {
                    ValidationErrors::from_message(
                        "control.dial_plan.candidates[].ip",
                        format!("must be a valid IP address: {err}"),
                    )
                })?;
            }

            if candidate.ip.as_deref().is_some() && ip.is_empty() {
                return Err(ValidationErrors::from_message(
                    "control.dial_plan.candidates[].ip",
                    "must not be empty when configured",
                ));
            }

            if candidate.ace_host.as_deref().is_some() && ace_host.is_empty() {
                return Err(ValidationErrors::from_message(
                    "control.dial_plan.candidates[].ace_host",
                    "must not be empty when configured",
                ));
            }

            if let Some(delay) = candidate.dial_start_delay_secs
                && (!delay.is_finite() || delay < 0.0)
            {
                return Err(ValidationErrors::from_message(
                    "control.dial_plan.candidates[].dial_start_delay_secs",
                    "must be a finite number greater than or equal to zero",
                ));
            }

            if let Some(timeout) = candidate.dial_timeout_secs
                && (!timeout.is_finite() || timeout <= 0.0)
            {
                return Err(ValidationErrors::from_message(
                    "control.dial_plan.candidates[].dial_timeout_secs",
                    "must be a finite number greater than zero",
                ));
            }
        }

        for (id, message) in &config.control.display_messages {
            if id.trim().is_empty() {
                return Err(ValidationErrors::from_message(
                    "control.display_messages",
                    "message ids must not be empty",
                ));
            }

            if id == "*" {
                return Err(ValidationErrors::from_message(
                    "control.display_messages",
                    "message id '*' is reserved for control-plane clear-all patches",
                ));
            }

            if message.title.trim().is_empty() {
                return Err(ValidationErrors::from_message(
                    "control.display_messages[].title",
                    format!("display message {id} must define a non-empty title"),
                ));
            }

            if message.text.trim().is_empty() {
                return Err(ValidationErrors::from_message(
                    "control.display_messages[].text",
                    format!("display message {id} must define a non-empty text"),
                ));
            }

            if let Some(action) = &message.primary_action {
                if action.url.trim().is_empty() {
                    return Err(ValidationErrors::from_message(
                        "control.display_messages[].primary_action.url",
                        format!("display message {id} primary action URL must not be empty"),
                    ));
                }

                if !is_secure_or_local_http_url(&action.url) {
                    return Err(ValidationErrors::from_message(
                        "control.display_messages[].primary_action.url",
                        format!(
                            "display message {id} primary action URL must use https unless it points to a local endpoint"
                        ),
                    ));
                }

                if action.label.trim().is_empty() {
                    return Err(ValidationErrors::from_message(
                        "control.display_messages[].primary_action.label",
                        format!("display message {id} primary action label must not be empty"),
                    ));
                }
            }
        }

        let attrs = &config.control.node_attrs;
        if attrs
            .tailnet_display_name
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(ValidationErrors::from_message(
                "control.node_attrs.tailnet_display_name",
                "must not be empty when configured",
            ));
        }

        if attrs.max_key_duration_secs == Some(0) {
            return Err(ValidationErrors::from_message(
                "control.node_attrs.max_key_duration_secs",
                "must be greater than zero when configured",
            ));
        }

        let client_version = &config.control.client_version;
        if let Some(version) = client_version.latest_version.as_deref() {
            if version.trim().is_empty() {
                return Err(ValidationErrors::from_message(
                    "control.client_version.latest_version",
                    "must not be empty when configured",
                ));
            }
            validate_release_version(version).map_err(|err| {
                ValidationErrors::from_message("control.client_version.latest_version", err)
            })?;
        }

        if let Some(url) = client_version.notify_url.as_deref() {
            if url.trim().is_empty() {
                return Err(ValidationErrors::from_message(
                    "control.client_version.notify_url",
                    "must not be empty when configured",
                ));
            }

            if !is_secure_or_local_http_url(url) {
                return Err(ValidationErrors::from_message(
                    "control.client_version.notify_url",
                    "must use https unless it points to a local endpoint",
                ));
            }
        }

        if client_version
            .notify_text
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(ValidationErrors::from_message(
                "control.client_version.notify_text",
                "must not be empty when configured",
            ));
        }

        if (client_version.notify
            || client_version.notify_url.is_some()
            || client_version.notify_text.is_some()
            || client_version.urgent_security_update)
            && client_version.latest_version.is_none()
        {
            return Err(ValidationErrors::from_message(
                "control.client_version.latest_version",
                "is required when client version notification settings are configured",
            ));
        }

        if let Some(url) = config.control.pop_browser_url.as_deref() {
            if url.trim().is_empty() {
                return Err(ValidationErrors::from_message(
                    "control.pop_browser_url",
                    "must not be empty when configured",
                ));
            }

            if !is_secure_or_local_http_url(url) {
                return Err(ValidationErrors::from_message(
                    "control.pop_browser_url",
                    "must use https unless it points to a local endpoint",
                ));
            }
        }

        Ok(())
    }

    fn validate_derp(config: &Self) -> Result<(), ValidationErrors> {
        let has_external_sources = !config.derp.urls.is_empty() || !config.derp.paths.is_empty();
        if config.derp.regions.is_empty() && !has_external_sources {
            return Err(ValidationErrors::from_message(
                "derp",
                "must configure at least one inline DERP region or one external DERP source",
            ));
        }

        let mut region_ids = std::collections::BTreeSet::new();
        let mut node_names = std::collections::BTreeSet::new();

        for region in &config.derp.regions {
            if region.region_id == 0 {
                return Err(ValidationErrors::from_message(
                    "derp.regions[].region_id",
                    "must be greater than zero",
                ));
            }

            if !region_ids.insert(region.region_id) {
                return Err(ValidationErrors::from_message(
                    "derp.regions[].region_id",
                    format!("duplicate DERP region id {}", region.region_id),
                ));
            }

            if region.region_code.trim().is_empty() {
                return Err(ValidationErrors::from_message(
                    "derp.regions[].region_code",
                    "must not be empty",
                ));
            }

            if region.region_name.trim().is_empty() {
                return Err(ValidationErrors::from_message(
                    "derp.regions[].region_name",
                    "must not be empty",
                ));
            }

            if region.nodes.is_empty() {
                return Err(ValidationErrors::from_message(
                    "derp.regions[].nodes",
                    format!(
                        "DERP region {} must contain at least one node",
                        region.region_id
                    ),
                ));
            }

            if let Some(latitude) = region.latitude
                && (!latitude.is_finite() || !(-90.0..=90.0).contains(&latitude))
            {
                return Err(ValidationErrors::from_message(
                    "derp.regions[].latitude",
                    format!(
                        "latitude for DERP region {} must be within [-90, 90]",
                        region.region_id
                    ),
                ));
            }

            if let Some(longitude) = region.longitude
                && (!longitude.is_finite() || !(-180.0..=180.0).contains(&longitude))
            {
                return Err(ValidationErrors::from_message(
                    "derp.regions[].longitude",
                    format!(
                        "longitude for DERP region {} must be within [-180, 180]",
                        region.region_id
                    ),
                ));
            }

            for node in &region.nodes {
                if node.name.trim().is_empty() {
                    return Err(ValidationErrors::from_message(
                        "derp.regions[].nodes[].name",
                        "must not be empty",
                    ));
                }

                if !node_names.insert(node.name.clone()) {
                    return Err(ValidationErrors::from_message(
                        "derp.regions[].nodes[].name",
                        format!("duplicate DERP node name {}", node.name),
                    ));
                }

                if node.host_name.trim().is_empty() {
                    return Err(ValidationErrors::from_message(
                        "derp.regions[].nodes[].host_name",
                        "must not be empty",
                    ));
                }

                if let Some(ipv4) = node.ipv4.as_deref().filter(|value| *value != "none") {
                    ipv4.parse::<std::net::Ipv4Addr>().map_err(|err| {
                        ValidationErrors::from_message(
                            "derp.regions[].nodes[].ipv4",
                            format!("invalid IPv4 address {ipv4}: {err}"),
                        )
                    })?;
                }

                if let Some(ipv6) = node.ipv6.as_deref().filter(|value| *value != "none") {
                    ipv6.parse::<std::net::Ipv6Addr>().map_err(|err| {
                        ValidationErrors::from_message(
                            "derp.regions[].nodes[].ipv6",
                            format!("invalid IPv6 address {ipv6}: {err}"),
                        )
                    })?;
                }

                if let Some(stun_test_ip) = node
                    .stun_test_ip
                    .as_deref()
                    .filter(|value| !value.is_empty())
                {
                    stun_test_ip.parse::<std::net::IpAddr>().map_err(|err| {
                        ValidationErrors::from_message(
                            "derp.regions[].nodes[].stun_test_ip",
                            format!("invalid STUN test IP {stun_test_ip}: {err}"),
                        )
                    })?;
                }

                if node.stun_port < -1 {
                    return Err(ValidationErrors::from_message(
                        "derp.regions[].nodes[].stun_port",
                        "must be -1 or greater",
                    ));
                }
            }
        }

        for url in &config.derp.urls {
            if url.trim().is_empty() {
                return Err(ValidationErrors::from_message(
                    "derp.urls[]",
                    "must not be empty",
                ));
            }

            if !is_secure_or_local_url(url) {
                return Err(ValidationErrors::from_message(
                    "derp.urls[]",
                    format!(
                        "DERP source URL must use https unless it points to a local endpoint: {url}"
                    ),
                ));
            }
        }

        for path in &config.derp.paths {
            if path.trim().is_empty() {
                return Err(ValidationErrors::from_message(
                    "derp.paths[]",
                    "must not be empty",
                ));
            }
        }

        if has_external_sources && config.derp.refresh_interval_secs == 0 {
            return Err(ValidationErrors::from_message(
                "derp.refresh_interval_secs",
                "must be greater than zero when DERP URLs or paths are configured",
            ));
        }

        if !config.derp.urls.is_empty() && config.derp.request_timeout_secs == 0 {
            return Err(ValidationErrors::from_message(
                "derp.request_timeout_secs",
                "must be greater than zero when DERP URLs are configured",
            ));
        }

        if !config.derp.urls.is_empty() && config.derp.total_timeout_secs == 0 {
            return Err(ValidationErrors::from_message(
                "derp.total_timeout_secs",
                "must be greater than zero when DERP URLs are configured",
            ));
        }

        if !config.derp.urls.is_empty()
            && config.derp.total_timeout_secs < config.derp.request_timeout_secs
        {
            return Err(ValidationErrors::from_message(
                "derp.total_timeout_secs",
                "must be greater than or equal to derp.request_timeout_secs",
            ));
        }

        if config.derp.server.enabled {
            let private_key = config.derp.server.private_key.trim();
            if private_key.is_empty() {
                return Err(ValidationErrors::from_message(
                    "derp.server.private_key",
                    "is required when the embedded DERP relay is enabled",
                ));
            }

            validate_machine_private_key(private_key)
                .map_err(|err| ValidationErrors::from_message("derp.server.private_key", err))?;

            if let Some(bind_addr) = config.derp.server.stun_bind_addr.as_deref()
                && !bind_addr.trim().is_empty()
            {
                bind_addr.parse::<SocketAddr>().map_err(|err| {
                    ValidationErrors::from_message(
                        "derp.server.stun_bind_addr",
                        format!("must be a valid socket address: {err}"),
                    )
                })?;
            }

            if config.derp.server.keepalive_interval_secs == 0 {
                return Err(ValidationErrors::from_message(
                    "derp.server.keepalive_interval_secs",
                    "must be greater than zero when the embedded DERP relay is enabled",
                ));
            }
        }

        if let Some(mesh_key) = config.derp.server.mesh_key.as_deref()
            && !mesh_key.trim().is_empty()
        {
            validate_derp_mesh_key(mesh_key)
                .map_err(|err| ValidationErrors::from_message("derp.server.mesh_key", err))?;

            let node_name = config
                .derp
                .server
                .node_name
                .as_deref()
                .map(str::trim)
                .unwrap_or_default();
            if node_name.is_empty() {
                return Err(ValidationErrors::from_message(
                    "derp.server.node_name",
                    "is required when derp.server.mesh_key is configured",
                ));
            }

            if config.derp.server.mesh_retry_interval_secs == 0 {
                return Err(ValidationErrors::from_message(
                    "derp.server.mesh_retry_interval_secs",
                    "must be greater than zero when derp.server.mesh_key is configured",
                ));
            }

            let node_matches = config
                .derp
                .regions
                .iter()
                .flat_map(|region| region.nodes.iter())
                .filter(|node| node.name == node_name)
                .count();
            if !config.derp.regions.is_empty() && node_matches == 0 {
                return Err(ValidationErrors::from_message(
                    "derp.server.node_name",
                    format!("references unknown DERP node {node_name}"),
                ));
            }
            if node_matches > 1 {
                return Err(ValidationErrors::from_message(
                    "derp.server.node_name",
                    format!("DERP node name {node_name} must be unique"),
                ));
            }
        }

        for region in &config.derp.regions {
            for node in &region.nodes {
                if let Some(mesh_url) = node.mesh_url.as_deref()
                    && !mesh_url.trim().is_empty()
                {
                    validate_derp_mesh_url(mesh_url).map_err(|err| {
                        ValidationErrors::from_message("derp.regions[].nodes[].mesh_url", err)
                    })?;
                }
            }
        }

        for (region_id, score) in &config.derp.home_params.region_score {
            if *region_id == 0 {
                return Err(ValidationErrors::from_message(
                    "derp.home_params.region_score",
                    "region score keys must be greater than zero",
                ));
            }

            if !has_external_sources && !region_ids.contains(region_id) {
                return Err(ValidationErrors::from_message(
                    "derp.home_params.region_score",
                    format!("region score references unknown DERP region {region_id}"),
                ));
            }

            if *score <= 0.0 || !score.is_finite() {
                return Err(ValidationErrors::from_message(
                    "derp.home_params.region_score",
                    format!("region score for {region_id} must be a positive finite number"),
                ));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TierConfig)]
#[serde(default)]
pub struct ServerConfig {
    pub bind_addr: String,
    pub web_root: Option<String>,
    pub public_base_url: Option<String>,
    pub control_private_key: String,
    pub map_poll_interval_secs: u64,
    pub map_keepalive_interval_secs: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:8080".to_string(),
            web_root: None,
            public_base_url: None,
            control_private_key: String::new(),
            map_poll_interval_secs: 5,
            map_keepalive_interval_secs: 50,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TierConfig)]
#[serde(default)]
pub struct NetworkConfig {
    pub tailnet_ipv4_range: String,
    pub tailnet_ipv6_range: String,
    pub node_online_window_secs: u64,
    pub node_session_ttl_secs: u64,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            tailnet_ipv4_range: "100.64.0.0/10".to_string(),
            tailnet_ipv6_range: "fd7a:115c:a1e0::/48".to_string(),
            node_online_window_secs: 120,
            node_session_ttl_secs: 604800,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TierConfig)]
#[serde(default)]
pub struct DatabaseConfig {
    pub url: Option<String>,
    pub max_connections: u32,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: None,
            max_connections: 20,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default, TierConfig)]
#[serde(default)]
pub struct ControlConfig {
    pub dial_plan: ControlDialPlanConfig,
    pub display_messages: BTreeMap<String, ControlDisplayMessageConfig>,
    pub client_version: ControlClientVersionConfig,
    pub collect_services: Option<bool>,
    pub node_attrs: ControlNodeAttrsConfig,
    pub pop_browser_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default, TierConfig)]
#[serde(default)]
pub struct ControlDialPlanConfig {
    pub candidates: Vec<ControlDialCandidateConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default, TierConfig)]
#[serde(default)]
pub struct ControlDialCandidateConfig {
    pub ip: Option<String>,
    pub ace_host: Option<String>,
    pub dial_start_delay_secs: Option<f64>,
    pub dial_timeout_secs: Option<f64>,
    pub priority: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default, TierConfig)]
#[serde(default)]
pub struct ControlDisplayMessageConfig {
    pub title: String,
    pub text: String,
    pub severity: ControlDisplayMessageSeverityConfig,
    pub impacts_connectivity: bool,
    pub primary_action: Option<ControlDisplayMessageActionConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default, TierConfig)]
#[serde(default)]
pub struct ControlDisplayMessageActionConfig {
    pub url: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default, TierConfig)]
#[serde(default)]
pub struct ControlClientVersionConfig {
    pub latest_version: Option<String>,
    pub urgent_security_update: bool,
    pub notify: bool,
    pub notify_url: Option<String>,
    pub notify_text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default, TierConfig)]
#[serde(default)]
pub struct ControlNodeAttrsConfig {
    pub tailnet_display_name: Option<String>,
    pub default_auto_update: Option<bool>,
    pub max_key_duration_secs: Option<u64>,
    pub cache_network_maps: bool,
    pub disable_hosts_file_updates: bool,
    pub force_register_magicdns_ipv4_only: bool,
    pub magicdns_peer_aaaa: bool,
    pub user_dial_use_routes: bool,
    pub disable_captive_portal_detection: bool,
    pub client_side_reachability: bool,
}

impl ControlNodeAttrsConfig {
    pub fn enabled_count(&self) -> u32 {
        let mut count = 0;
        count += u32::from(self.tailnet_display_name.is_some());
        count += u32::from(self.default_auto_update.is_some());
        count += u32::from(self.max_key_duration_secs.is_some());
        count += u32::from(self.cache_network_maps);
        count += u32::from(self.disable_hosts_file_updates);
        count += u32::from(self.force_register_magicdns_ipv4_only);
        count += u32::from(self.magicdns_peer_aaaa);
        count += u32::from(self.user_dial_use_routes);
        count += u32::from(self.disable_captive_portal_detection);
        count += u32::from(self.client_side_reachability);
        count
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default, TierConfig)]
#[serde(rename_all = "snake_case")]
pub enum ControlDisplayMessageSeverityConfig {
    High,
    #[default]
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TierConfig)]
#[serde(default)]
pub struct AuthConfig {
    pub break_glass_username: String,
    pub break_glass_token: Option<String>,
    pub oidc: OidcConfig,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            break_glass_username: "admin".to_string(),
            break_glass_token: None,
            oidc: OidcConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TierConfig)]
#[serde(default)]
pub struct OidcConfig {
    pub enabled: bool,
    pub issuer_url: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub scopes: Vec<String>,
    pub allowed_domains: Vec<String>,
    pub allowed_users: Vec<String>,
    pub allowed_groups: Vec<String>,
    pub extra_params: BTreeMap<String, String>,
    pub request_timeout_secs: u64,
    pub total_timeout_secs: u64,
    pub auth_flow_ttl_secs: u64,
    pub validate_discovery_on_startup: bool,
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            issuer_url: None,
            client_id: None,
            client_secret: None,
            scopes: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
            allowed_domains: Vec::new(),
            allowed_users: Vec::new(),
            allowed_groups: Vec::new(),
            extra_params: BTreeMap::new(),
            request_timeout_secs: 5,
            total_timeout_secs: 15,
            auth_flow_ttl_secs: 600,
            validate_discovery_on_startup: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TierConfig)]
#[serde(default)]
pub struct TelemetryConfig {
    pub filter: String,
    pub format: LogFormat,
    pub timezone: LogTimezone,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, TierConfig)]
#[serde(default)]
pub struct DerpConfig {
    pub omit_default_regions: bool,
    pub urls: Vec<String>,
    pub paths: Vec<String>,
    pub refresh_interval_secs: u64,
    pub request_timeout_secs: u64,
    pub total_timeout_secs: u64,
    pub server: DerpServerConfig,
    pub home_params: DerpHomeParamsConfig,
    pub regions: Vec<DerpRegionConfig>,
}

impl Default for DerpConfig {
    fn default() -> Self {
        Self {
            omit_default_regions: false,
            urls: Vec::new(),
            paths: Vec::new(),
            refresh_interval_secs: 300,
            request_timeout_secs: 5,
            total_timeout_secs: 15,
            server: DerpServerConfig::default(),
            home_params: DerpHomeParamsConfig::default(),
            regions: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TierConfig)]
#[serde(default)]
pub struct DerpServerConfig {
    pub enabled: bool,
    pub private_key: String,
    pub mesh_key: Option<String>,
    pub node_name: Option<String>,
    pub stun_bind_addr: Option<String>,
    pub verify_clients: bool,
    pub keepalive_interval_secs: u64,
    pub mesh_retry_interval_secs: u64,
}

impl Default for DerpServerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            private_key: String::new(),
            mesh_key: None,
            node_name: None,
            stun_bind_addr: Some("0.0.0.0:3478".to_string()),
            verify_clients: true,
            keepalive_interval_secs: 60,
            mesh_retry_interval_secs: 5,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default, TierConfig)]
#[serde(default)]
pub struct DerpHomeParamsConfig {
    pub region_score: BTreeMap<u32, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default, TierConfig)]
#[serde(default)]
pub struct DerpRegionConfig {
    pub region_id: u32,
    pub region_code: String,
    pub region_name: String,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub avoid: bool,
    pub no_measure_no_home: bool,
    pub nodes: Vec<DerpNodeConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default, TierConfig)]
#[serde(default)]
pub struct DerpNodeConfig {
    pub name: String,
    pub host_name: String,
    pub cert_name: Option<String>,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub stun_port: i32,
    pub stun_only: bool,
    pub derp_port: u16,
    pub insecure_for_tests: bool,
    pub stun_test_ip: Option<String>,
    pub can_port80: bool,
    pub mesh_url: Option<String>,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            filter: "info".to_string(),
            format: LogFormat::Pretty,
            timezone: LogTimezone::Utc,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default, TierConfig)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    Json,
    #[default]
    Pretty,
    Compact,
}

impl LogFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Pretty => "pretty",
            Self::Compact => "compact",
        }
    }
}

impl FromStr for LogFormat {
    type Err = AppError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "json" => Ok(Self::Json),
            "pretty" => Ok(Self::Pretty),
            "compact" => Ok(Self::Compact),
            _ => Err(AppError::InvalidConfig(format!(
                "unsupported log format: {value}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default, TierConfig)]
#[serde(rename_all = "snake_case")]
pub enum LogTimezone {
    #[default]
    Utc,
    Local,
}

impl LogTimezone {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Utc => "utc",
            Self::Local => "local",
        }
    }
}

impl FromStr for LogTimezone {
    type Err = AppError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "utc" => Ok(Self::Utc),
            "local" => Ok(Self::Local),
            _ => Err(AppError::InvalidConfig(format!(
                "unsupported log timezone: {value}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ConfigSummary {
    pub bind_addr: String,
    pub web_root_configured: bool,
    pub control_protocol_enabled: bool,
    pub tailnet_ipv4_range: String,
    pub tailnet_ipv6_range: String,
    pub database_configured: bool,
    pub derp_region_count: u32,
    pub derp_url_count: u32,
    pub derp_path_count: u32,
    pub derp_omit_default_regions: bool,
    pub derp_refresh_interval_secs: u64,
    pub derp_embedded_relay_enabled: bool,
    pub derp_stun_bind_addr: Option<String>,
    pub derp_verify_clients: bool,
    pub admin_auth_configured: bool,
    pub oidc_enabled: bool,
    pub oidc_discovery_validation: bool,
    pub control_display_message_count: u32,
    pub control_dial_candidate_count: u32,
    pub control_client_version_configured: bool,
    pub control_collect_services_configured: bool,
    pub control_node_attr_count: u32,
    pub control_pop_browser_url_configured: bool,
    pub log_filter: String,
    pub log_format: String,
    pub log_timezone: String,
}

fn validate_machine_private_key(value: &str) -> Result<(), String> {
    const PREFIX: &str = "privkey:";

    let encoded = value
        .strip_prefix(PREFIX)
        .ok_or_else(|| format!("must start with {PREFIX}"))?;

    if encoded.len() != 64 {
        return Err("must contain exactly 32 bytes encoded as 64 hex characters".to_string());
    }

    if !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("must be hexadecimal".to_string());
    }

    Ok(())
}

fn validate_derp_mesh_key(value: &str) -> Result<(), String> {
    if value.len() != 64 {
        return Err("must contain exactly 64 hex characters".to_string());
    }

    if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("must be hex-encoded".to_string());
    }

    Ok(())
}

fn validate_derp_mesh_url(value: &str) -> Result<(), String> {
    let trimmed = value.trim();
    let Some(scheme_end) = trimmed.find("://") else {
        return Err("must include a scheme".to_string());
    };

    let scheme = &trimmed[..scheme_end];
    if !matches!(scheme, "http" | "https" | "ws" | "wss") {
        return Err("scheme must be one of http, https, ws, or wss".to_string());
    }

    if trimmed[scheme_end + 3..].trim().is_empty() {
        return Err("must include a host".to_string());
    }

    Ok(())
}

fn is_secure_or_local_http_url(value: &str) -> bool {
    value.starts_with("https://")
        || value.starts_with("http://127.0.0.1")
        || value.starts_with("http://localhost")
        || value.starts_with("http://[::1]")
}

fn validate_ipv4_cidr(value: &str) -> Result<(), String> {
    let (address, prefix_len) = value
        .split_once('/')
        .ok_or_else(|| "must be in CIDR notation".to_string())?;

    let _: std::net::Ipv4Addr = address
        .parse()
        .map_err(|err| format!("invalid IPv4 address: {err}"))?;
    let prefix_len: u8 = prefix_len
        .parse()
        .map_err(|err| format!("invalid IPv4 prefix length: {err}"))?;

    if prefix_len > 30 {
        return Err("must allow at least two usable IPv4 host addresses".to_string());
    }

    Ok(())
}

fn validate_ipv6_cidr(value: &str) -> Result<(), String> {
    let (address, prefix_len) = value
        .split_once('/')
        .ok_or_else(|| "must be in CIDR notation".to_string())?;

    let _: std::net::Ipv6Addr = address
        .parse()
        .map_err(|err| format!("invalid IPv6 address: {err}"))?;
    let prefix_len: u8 = prefix_len
        .parse()
        .map_err(|err| format!("invalid IPv6 prefix length: {err}"))?;

    if prefix_len > 127 {
        return Err("must allow at least one allocatable IPv6 address".to_string());
    }

    Ok(())
}

fn validate_release_version(value: &str) -> Result<(), String> {
    let trimmed = value.trim();
    let core = trimmed
        .split_once('-')
        .map_or(trimmed, |(prefix, _)| prefix);
    let core = core.split_once('+').map_or(core, |(prefix, _)| prefix);
    let mut seen = 0_u8;

    for part in core.split('.') {
        if part.is_empty() {
            return Err("must use dot-separated numeric segments".to_string());
        }
        part.parse::<u64>()
            .map_err(|err| format!("contains an invalid numeric segment: {err}"))?;
        seen += 1;
    }

    if seen < 2 {
        return Err("must contain at least major.minor segments".to_string());
    }

    Ok(())
}

fn is_secure_or_local_url(value: &str) -> bool {
    value.starts_with("https://")
        || value.starts_with("http://127.0.0.1")
        || value.starts_with("http://localhost")
        || value.starts_with("http://[::1]")
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn write_temp_config(contents: &str) -> Result<PathBuf, Box<dyn Error>> {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = env::temp_dir().join(format!("rscale-config-{unique}.toml"));
        std::fs::write(&path, contents)?;
        Ok(path)
    }

    #[test]
    fn default_config_requires_explicit_runtime_secrets() {
        let config = AppConfig::default();
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_loads_via_tier_from_file() -> Result<(), Box<dyn Error>> {
        let path = write_temp_config(
            r#"
[server]
bind_addr = "0.0.0.0:9090"
public_base_url = "https://rscale.example.com"
control_private_key = "privkey:1111111111111111111111111111111111111111111111111111111111111111"

[network]
tailnet_ipv4_range = "100.64.0.0/10"
tailnet_ipv6_range = "fd7a:115c:a1e0::/48"

[database]
url = "postgres://localhost/rscale"
max_connections = 32

[auth]
break_glass_username = "bootstrap-admin"
break_glass_token = "0123456789abcdef01234567"

[auth.oidc]
enabled = true
issuer_url = "https://issuer.example.com"
client_id = "rscale"
client_secret = "secret"
request_timeout_secs = 3
total_timeout_secs = 10

[control]

[control.display_messages.maintenance]
title = "Scheduled maintenance"
text = "Control plane maintenance is in progress."
severity = "medium"
impacts_connectivity = false

[control.display_messages.maintenance.primary_action]
url = "https://status.example.com"
label = "Status page"

[derp]
omit_default_regions = true

[[derp.regions]]
region_id = 900
region_code = "test"
region_name = "Test Region"

[[derp.regions.nodes]]
name = "900a"
host_name = "derp.example.com"
stun_port = 3478
derp_port = 443

[telemetry]
filter = "debug"
format = "json"
timezone = "local"
"#,
        )?;

        let loaded = AppConfig::load_with_report(Some(&path))?;

        assert_eq!(loaded.server.bind_addr, "0.0.0.0:9090");
        assert_eq!(loaded.network.tailnet_ipv4_range, "100.64.0.0/10");
        assert_eq!(loaded.database.max_connections, 32);
        assert_eq!(loaded.telemetry.format, LogFormat::Json);
        assert_eq!(loaded.telemetry.timezone, LogTimezone::Local);
        assert!(loaded.config().validate().is_ok());
        assert!(!loaded.report().has_warnings());

        std::fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn env_source_ignores_rscale_config_path_variable() -> Result<(), Box<dyn Error>> {
        let loaded = ConfigLoader::new(AppConfig::default())
            .derive_metadata()
            .env(AppConfig::env_source_from_pairs([
                ("RSCALE_CONFIG", "/tmp/rscale.toml"),
                ("RSCALE_BIND_ADDR", "0.0.0.0:9090"),
                (
                    "RSCALE_CONTROL_PRIVATE_KEY",
                    "privkey:1111111111111111111111111111111111111111111111111111111111111111",
                ),
                ("RSCALE_DATABASE_URL", "postgres://localhost/rscale"),
                ("RSCALE_BREAK_GLASS_TOKEN", "0123456789abcdef01234567"),
            ]))
            .load()?;

        assert_eq!(loaded.server.bind_addr, "0.0.0.0:9090");
        assert_eq!(
            loaded.database.url.as_deref(),
            Some("postgres://localhost/rscale")
        );
        Ok(())
    }

    #[test]
    fn invalid_bind_addr_is_rejected() {
        let config = AppConfig {
            server: ServerConfig {
                bind_addr: "not-an-address".to_string(),
                web_root: None,
                public_base_url: None,
                control_private_key:
                    "privkey:1111111111111111111111111111111111111111111111111111111111111111"
                        .to_string(),
                map_poll_interval_secs: 5,
                map_keepalive_interval_secs: 50,
            },
            ..AppConfig::default()
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn derp_accepts_external_sources_without_inline_regions() {
        let mut config = AppConfig::default();
        config.server.control_private_key =
            "privkey:1111111111111111111111111111111111111111111111111111111111111111".to_string();
        config.database.url = Some("postgres://localhost/rscale".to_string());
        config.auth.break_glass_token = Some("0123456789abcdef01234567".to_string());
        config.derp.urls = vec!["https://controlplane.tailscale.com/derpmap/default".to_string()];
        config.derp.regions.clear();

        assert!(config.validate().is_ok());
    }

    #[test]
    fn embedded_derp_requires_private_key() {
        let mut config = AppConfig::default();
        config.server.control_private_key =
            "privkey:1111111111111111111111111111111111111111111111111111111111111111".to_string();
        config.database.url = Some("postgres://localhost/rscale".to_string());
        config.auth.break_glass_token = Some("0123456789abcdef01234567".to_string());
        config.derp.server.enabled = true;
        config.derp.regions = vec![DerpRegionConfig {
            region_id: 900,
            region_code: "sha".to_string(),
            region_name: "Shanghai".to_string(),
            nodes: vec![DerpNodeConfig {
                name: "900a".to_string(),
                host_name: "derp.example.com".to_string(),
                stun_port: 3478,
                derp_port: 443,
                ..DerpNodeConfig::default()
            }],
            ..DerpRegionConfig::default()
        }];

        assert!(config.validate().is_err());
    }

    #[test]
    fn embedded_derp_accepts_valid_stun_bind_addr() {
        let mut config = AppConfig::default();
        config.server.control_private_key =
            "privkey:1111111111111111111111111111111111111111111111111111111111111111".to_string();
        config.database.url = Some("postgres://localhost/rscale".to_string());
        config.auth.break_glass_token = Some("0123456789abcdef01234567".to_string());
        config.derp.server.enabled = true;
        config.derp.server.private_key =
            "privkey:2222222222222222222222222222222222222222222222222222222222222222".to_string();
        config.derp.server.stun_bind_addr = Some("0.0.0.0:3478".to_string());
        config.derp.regions = vec![DerpRegionConfig {
            region_id: 900,
            region_code: "sha".to_string(),
            region_name: "Shanghai".to_string(),
            nodes: vec![DerpNodeConfig {
                name: "900a".to_string(),
                host_name: "derp.example.com".to_string(),
                stun_port: 3478,
                derp_port: 443,
                ..DerpNodeConfig::default()
            }],
            ..DerpRegionConfig::default()
        }];

        assert!(config.validate().is_ok());
    }

    #[test]
    fn embedded_derp_mesh_requires_node_name() {
        let mut config = AppConfig::default();
        config.server.control_private_key =
            "privkey:1111111111111111111111111111111111111111111111111111111111111111".to_string();
        config.database.url = Some("postgres://localhost/rscale".to_string());
        config.auth.break_glass_token = Some("0123456789abcdef01234567".to_string());
        config.derp.server.enabled = true;
        config.derp.server.private_key =
            "privkey:2222222222222222222222222222222222222222222222222222222222222222".to_string();
        config.derp.server.mesh_key =
            Some("3333333333333333333333333333333333333333333333333333333333333333".to_string());
        config.derp.regions = vec![DerpRegionConfig {
            region_id: 900,
            region_code: "sha".to_string(),
            region_name: "Shanghai".to_string(),
            nodes: vec![DerpNodeConfig {
                name: "900a".to_string(),
                host_name: "derp.example.com".to_string(),
                stun_port: 3478,
                derp_port: 443,
                ..DerpNodeConfig::default()
            }],
            ..DerpRegionConfig::default()
        }];

        assert!(config.validate().is_err());
    }

    #[test]
    fn control_display_message_requires_https_action_url() {
        let mut config = AppConfig::default();
        config.server.control_private_key =
            "privkey:1111111111111111111111111111111111111111111111111111111111111111".to_string();
        config.database.url = Some("postgres://localhost/rscale".to_string());
        config.auth.break_glass_token = Some("0123456789abcdef01234567".to_string());
        config.derp.urls = vec!["https://controlplane.tailscale.com/derpmap/default".to_string()];
        config.derp.regions.clear();
        config.control.display_messages.insert(
            "maintenance".to_string(),
            ControlDisplayMessageConfig {
                title: "Maintenance".to_string(),
                text: "Scheduled work".to_string(),
                severity: ControlDisplayMessageSeverityConfig::Medium,
                impacts_connectivity: false,
                primary_action: Some(ControlDisplayMessageActionConfig {
                    url: "http://example.com".to_string(),
                    label: "View status".to_string(),
                }),
            },
        );

        assert!(config.validate().is_err());
    }

    #[test]
    fn control_dial_candidate_requires_endpoint() {
        let mut config = AppConfig::default();
        config.server.control_private_key =
            "privkey:1111111111111111111111111111111111111111111111111111111111111111".to_string();
        config.database.url = Some("postgres://localhost/rscale".to_string());
        config.auth.break_glass_token = Some("0123456789abcdef01234567".to_string());
        config.derp.urls = vec!["https://controlplane.tailscale.com/derpmap/default".to_string()];
        config.derp.regions.clear();
        config
            .control
            .dial_plan
            .candidates
            .push(ControlDialCandidateConfig::default());

        assert!(config.validate().is_err());
    }

    #[test]
    fn control_node_attrs_validate_non_empty_and_positive_values() {
        let mut config = AppConfig::default();
        config.server.control_private_key =
            "privkey:1111111111111111111111111111111111111111111111111111111111111111".to_string();
        config.database.url = Some("postgres://localhost/rscale".to_string());
        config.auth.break_glass_token = Some("0123456789abcdef01234567".to_string());
        config.derp.urls = vec!["https://controlplane.tailscale.com/derpmap/default".to_string()];
        config.derp.regions.clear();
        config.control.node_attrs.tailnet_display_name = Some("   ".to_string());
        config.control.node_attrs.max_key_duration_secs = Some(0);

        assert!(config.validate().is_err());
    }

    #[test]
    fn control_client_version_requires_latest_version_when_enabled() {
        let mut config = AppConfig::default();
        config.server.control_private_key =
            "privkey:1111111111111111111111111111111111111111111111111111111111111111".to_string();
        config.database.url = Some("postgres://localhost/rscale".to_string());
        config.auth.break_glass_token = Some("0123456789abcdef01234567".to_string());
        config.derp.urls = vec!["https://controlplane.tailscale.com/derpmap/default".to_string()];
        config.derp.regions.clear();
        config.control.client_version.notify = true;

        assert!(config.validate().is_err());
    }

    #[test]
    fn control_client_version_rejects_insecure_notify_url() {
        let mut config = AppConfig::default();
        config.server.control_private_key =
            "privkey:1111111111111111111111111111111111111111111111111111111111111111".to_string();
        config.database.url = Some("postgres://localhost/rscale".to_string());
        config.auth.break_glass_token = Some("0123456789abcdef01234567".to_string());
        config.derp.urls = vec!["https://controlplane.tailscale.com/derpmap/default".to_string()];
        config.derp.regions.clear();
        config.control.client_version.latest_version = Some("1.82.0".to_string());
        config.control.client_version.notify = true;
        config.control.client_version.notify_url = Some("http://example.com".to_string());

        assert!(config.validate().is_err());
    }

    #[test]
    fn control_pop_browser_url_requires_secure_or_local_http() {
        let mut config = AppConfig::default();
        config.server.control_private_key =
            "privkey:1111111111111111111111111111111111111111111111111111111111111111".to_string();
        config.database.url = Some("postgres://localhost/rscale".to_string());
        config.auth.break_glass_token = Some("0123456789abcdef01234567".to_string());
        config.derp.urls = vec!["https://controlplane.tailscale.com/derpmap/default".to_string()];
        config.derp.regions.clear();
        config.control.pop_browser_url = Some("http://example.com".to_string());

        assert!(config.validate().is_err());
    }
}

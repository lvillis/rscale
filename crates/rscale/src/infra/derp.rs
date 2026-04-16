use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Duration;

use ::time::OffsetDateTime;
use reqx::TlsVersion;
use reqx::prelude::{Client, RetryPolicy};
use serde::{Deserialize, Serialize};
use tokio::time;
use tracing::{info, warn};

use crate::config::DerpConfig;
use crate::error::{AppError, AppResult};
use crate::protocol::{ControlDerpHomeParams, ControlDerpMap, ControlDerpRegion, config_derp_map};

#[derive(Clone)]
pub struct DerpMapRuntime {
    state: Arc<RwLock<DerpRuntimeState>>,
}

#[derive(Debug)]
struct DerpRuntimeState {
    status: DerpRuntimeStatus,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DerpRuntimeStatus {
    pub effective_map: ControlDerpMap,
    pub effective_region_count: u32,
    pub source_count: u32,
    pub source_urls: Vec<String>,
    pub source_paths: Vec<String>,
    pub refresh_enabled: bool,
    pub refresh_interval_secs: u64,
    pub last_refresh_attempt_unix_secs: Option<i64>,
    pub last_refresh_success_unix_secs: Option<i64>,
    pub last_refresh_error: Option<String>,
    pub refresh_failures_total: u64,
}

impl DerpMapRuntime {
    pub fn from_static_config(config: &DerpConfig) -> Self {
        let effective_map = config_derp_map(config);
        Self::from_effective_map(config, effective_map, false)
    }

    pub async fn bootstrap(config: &DerpConfig) -> AppResult<Self> {
        let effective_map = load_effective_map(config).await?;
        let refresh_enabled = !config.urls.is_empty() || !config.paths.is_empty();
        let runtime = Self::from_effective_map(config, effective_map, refresh_enabled);

        if refresh_enabled {
            info!(
                source_count = runtime.status().source_count,
                refresh_interval_secs = config.refresh_interval_secs,
                "initialized DERP runtime with external sources"
            );
            runtime.spawn_refresh_loop(config.clone());
        } else {
            info!(
                region_count = runtime.status().effective_region_count,
                "initialized DERP runtime from inline configuration"
            );
        }

        Ok(runtime)
    }

    pub fn effective_map(&self) -> ControlDerpMap {
        self.read_state().status.effective_map.clone()
    }

    pub fn status(&self) -> DerpRuntimeStatus {
        self.read_state().status.clone()
    }

    fn from_effective_map(
        config: &DerpConfig,
        effective_map: ControlDerpMap,
        refreshed: bool,
    ) -> Self {
        let now = refreshed.then(now_unix_secs);
        let status = DerpRuntimeStatus {
            effective_region_count: effective_map.regions.len() as u32,
            effective_map,
            source_count: (config.urls.len() + config.paths.len()) as u32,
            source_urls: config.urls.clone(),
            source_paths: config.paths.clone(),
            refresh_enabled: !config.urls.is_empty() || !config.paths.is_empty(),
            refresh_interval_secs: config.refresh_interval_secs,
            last_refresh_attempt_unix_secs: now,
            last_refresh_success_unix_secs: now,
            last_refresh_error: None,
            refresh_failures_total: 0,
        };

        Self {
            state: Arc::new(RwLock::new(DerpRuntimeState { status })),
        }
    }

    fn spawn_refresh_loop(&self, config: DerpConfig) {
        let runtime = self.clone();
        tokio::spawn(async move {
            let mut ticker = time::interval(Duration::from_secs(config.refresh_interval_secs));
            ticker.tick().await;

            loop {
                ticker.tick().await;
                match load_effective_map(&config).await {
                    Ok(effective_map) => {
                        runtime.record_refresh_success(effective_map);
                    }
                    Err(err) => {
                        runtime.record_refresh_failure(err.to_string());
                    }
                }
            }
        });
    }

    fn record_refresh_success(&self, effective_map: ControlDerpMap) {
        let region_count = effective_map.regions.len() as u32;
        let now = now_unix_secs();
        let mut state = self.write_state();
        state.status.effective_map = effective_map;
        state.status.effective_region_count = region_count;
        state.status.last_refresh_attempt_unix_secs = Some(now);
        state.status.last_refresh_success_unix_secs = Some(now);
        state.status.last_refresh_error = None;

        info!(region_count, "refreshed DERP map");
    }

    fn record_refresh_failure(&self, error: String) {
        let now = now_unix_secs();
        let mut state = self.write_state();
        state.status.last_refresh_attempt_unix_secs = Some(now);
        state.status.last_refresh_error = Some(error.clone());
        state.status.refresh_failures_total += 1;

        warn!(error = %error, "failed to refresh DERP map; keeping last successful snapshot");
    }

    fn read_state(&self) -> RwLockReadGuard<'_, DerpRuntimeState> {
        self.state
            .read()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn write_state(&self) -> RwLockWriteGuard<'_, DerpRuntimeState> {
        self.state
            .write()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
struct DerpSourceMap {
    #[serde(rename = "HomeParams", default)]
    home_params: Option<ControlDerpHomeParams>,
    #[serde(rename = "Regions", default)]
    regions: std::collections::BTreeMap<u32, Option<ControlDerpRegion>>,
}

async fn load_effective_map(config: &DerpConfig) -> AppResult<ControlDerpMap> {
    let mut effective_map = config_derp_map(config);

    for url in &config.urls {
        let source = load_derp_map_from_url(url, config).await?;
        apply_source(&mut effective_map, source)?;
    }

    for path in &config.paths {
        let source = load_derp_map_from_path(path)?;
        apply_source(&mut effective_map, source)?;
    }

    validate_effective_map(&effective_map)?;
    Ok(effective_map)
}

async fn load_derp_map_from_url(url: &str, config: &DerpConfig) -> AppResult<DerpSourceMap> {
    let (origin, path) = split_url(url)?;
    let client = Client::builder(origin.clone())
        .client_name("rscale-derp")
        .request_timeout(Duration::from_secs(config.request_timeout_secs))
        .total_timeout(Duration::from_secs(config.total_timeout_secs))
        .retry_policy(
            RetryPolicy::standard()
                .max_attempts(2)
                .base_backoff(Duration::from_millis(100))
                .max_backoff(Duration::from_millis(500)),
        )
        .tls_min_version(TlsVersion::V1_2)
        .build()
        .map_err(|err| {
            AppError::Bootstrap(format!(
                "failed to build DERP HTTP client for {origin}: {err}"
            ))
        })?;

    client
        .get(&path)
        .send_json()
        .await
        .map_err(|err| AppError::Bootstrap(format!("failed to load DERP map from {url}: {err}")))
}

fn load_derp_map_from_path(path: &str) -> AppResult<DerpSourceMap> {
    let contents = std::fs::read_to_string(path).map_err(|err| {
        AppError::Bootstrap(format!("failed to read DERP map from {path}: {err}"))
    })?;
    serde_json::from_str(&contents).map_err(|err| {
        AppError::Bootstrap(format!("failed to parse DERP map JSON from {path}: {err}"))
    })
}

fn apply_source(target: &mut ControlDerpMap, source: DerpSourceMap) -> AppResult<()> {
    if let Some(home_params) = source.home_params {
        target.home_params = if home_params.region_score.is_empty() {
            None
        } else {
            Some(home_params)
        };
    }

    for (region_id, region) in source.regions {
        match region {
            Some(mut region) => {
                normalize_region(region_id, &mut region)?;
                target.regions.insert(region_id, region);
            }
            None => {
                target.regions.remove(&region_id);
            }
        }
    }

    Ok(())
}

fn normalize_region(region_id: u32, region: &mut ControlDerpRegion) -> AppResult<()> {
    if region.region_id != 0 && region.region_id != region_id {
        return Err(AppError::Bootstrap(format!(
            "DERP region key {region_id} does not match RegionID {}",
            region.region_id
        )));
    }

    region.region_id = region_id;
    for node in &mut region.nodes {
        if node.region_id != 0 && node.region_id != region_id {
            return Err(AppError::Bootstrap(format!(
                "DERP node {} declares RegionID {} but belongs to region {region_id}",
                node.name, node.region_id
            )));
        }

        node.region_id = region_id;
    }

    Ok(())
}

fn validate_effective_map(map: &ControlDerpMap) -> AppResult<()> {
    if map.regions.is_empty() {
        return Err(AppError::Bootstrap(
            "effective DERP map must contain at least one region".to_string(),
        ));
    }

    let mut node_names = BTreeSet::new();
    for (region_id, region) in &map.regions {
        if *region_id == 0 {
            return Err(AppError::Bootstrap(
                "DERP region ids must be greater than zero".to_string(),
            ));
        }

        if region.region_id != *region_id {
            return Err(AppError::Bootstrap(format!(
                "DERP region key {region_id} does not match RegionID {}",
                region.region_id
            )));
        }

        if region.region_code.trim().is_empty() {
            return Err(AppError::Bootstrap(format!(
                "DERP region {region_id} must define RegionCode"
            )));
        }

        if region.region_name.trim().is_empty() {
            return Err(AppError::Bootstrap(format!(
                "DERP region {region_id} must define RegionName"
            )));
        }

        if region.nodes.is_empty() {
            return Err(AppError::Bootstrap(format!(
                "DERP region {region_id} must contain at least one node"
            )));
        }

        if let Some(latitude) = region.latitude
            && (!latitude.is_finite() || !(-90.0..=90.0).contains(&latitude))
        {
            return Err(AppError::Bootstrap(format!(
                "DERP region {region_id} latitude must be within [-90, 90]"
            )));
        }

        if let Some(longitude) = region.longitude
            && (!longitude.is_finite() || !(-180.0..=180.0).contains(&longitude))
        {
            return Err(AppError::Bootstrap(format!(
                "DERP region {region_id} longitude must be within [-180, 180]"
            )));
        }

        for node in &region.nodes {
            if node.name.trim().is_empty() {
                return Err(AppError::Bootstrap(format!(
                    "DERP region {region_id} contains a node without Name"
                )));
            }

            if !node_names.insert(node.name.clone()) {
                return Err(AppError::Bootstrap(format!(
                    "duplicate DERP node name {}",
                    node.name
                )));
            }

            if node.region_id != *region_id {
                return Err(AppError::Bootstrap(format!(
                    "DERP node {} declares RegionID {} but belongs to region {region_id}",
                    node.name, node.region_id
                )));
            }

            if node.host_name.trim().is_empty() {
                return Err(AppError::Bootstrap(format!(
                    "DERP node {} must define HostName",
                    node.name
                )));
            }

            if !node.ipv4.is_empty() && node.ipv4 != "none" {
                node.ipv4.parse::<Ipv4Addr>().map_err(|err| {
                    AppError::Bootstrap(format!(
                        "DERP node {} has invalid IPv4 {}: {err}",
                        node.name, node.ipv4
                    ))
                })?;
            }

            if !node.ipv6.is_empty() && node.ipv6 != "none" {
                node.ipv6.parse::<Ipv6Addr>().map_err(|err| {
                    AppError::Bootstrap(format!(
                        "DERP node {} has invalid IPv6 {}: {err}",
                        node.name, node.ipv6
                    ))
                })?;
            }

            if !node.stun_test_ip.is_empty() {
                node.stun_test_ip.parse::<IpAddr>().map_err(|err| {
                    AppError::Bootstrap(format!(
                        "DERP node {} has invalid STUNTestIP {}: {err}",
                        node.name, node.stun_test_ip
                    ))
                })?;
            }

            if node.stun_port < -1 {
                return Err(AppError::Bootstrap(format!(
                    "DERP node {} STUNPort must be -1 or greater",
                    node.name
                )));
            }
        }
    }

    if let Some(home_params) = &map.home_params {
        for (region_id, score) in &home_params.region_score {
            if !map.regions.contains_key(region_id) {
                return Err(AppError::Bootstrap(format!(
                    "DERP HomeParams references unknown region {region_id}"
                )));
            }

            if *score <= 0.0 || !score.is_finite() {
                return Err(AppError::Bootstrap(format!(
                    "DERP HomeParams score for region {region_id} must be a positive finite number"
                )));
            }
        }
    }

    Ok(())
}

fn split_url(url: &str) -> AppResult<(String, String)> {
    let Some(scheme_end) = url.find("://") else {
        return Err(AppError::InvalidConfig(format!(
            "DERP URL must include a scheme: {url}"
        )));
    };
    let authority_start = scheme_end + 3;
    let path_start = url[authority_start..]
        .find('/')
        .map(|offset| authority_start + offset)
        .unwrap_or(url.len());
    let origin = url[..path_start].to_string();
    let path = if path_start == url.len() {
        "/".to_string()
    } else {
        url[path_start..].to_string()
    };

    Ok((origin, path))
}

fn now_unix_secs() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use axum::Json;
    use axum::routing::get;
    use serde_json::json;
    use tokio::net::TcpListener;

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    fn base_config() -> DerpConfig {
        DerpConfig {
            omit_default_regions: false,
            regions: vec![crate::config::DerpRegionConfig {
                region_id: 900,
                region_code: "sha".to_string(),
                region_name: "Shanghai".to_string(),
                nodes: vec![crate::config::DerpNodeConfig {
                    name: "900a".to_string(),
                    host_name: "derp-sha.example.com".to_string(),
                    stun_port: 3478,
                    derp_port: 443,
                    ..crate::config::DerpNodeConfig::default()
                }],
                ..crate::config::DerpRegionConfig::default()
            }],
            ..DerpConfig::default()
        }
    }

    #[test]
    fn path_source_can_remove_regions() -> TestResult {
        let mut map = config_derp_map(&base_config());
        apply_source(
            &mut map,
            serde_json::from_value(json!({
                "Regions": {
                    "900": null
                }
            }))?,
        )?;

        assert!(map.regions.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn bootstrap_loads_external_derp_url() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let app = axum::Router::new().route(
            "/derpmap/default",
            get(|| async {
                Json(json!({
                    "Regions": {
                        "901": {
                            "RegionID": 901,
                            "RegionCode": "tyo",
                            "RegionName": "Tokyo",
                            "Nodes": [
                                {
                                    "Name": "901a",
                                    "RegionID": 901,
                                    "HostName": "derp-tyo.example.com",
                                    "DERPPort": 443,
                                    "STUNPort": 3478
                                }
                            ]
                        }
                    }
                }))
            }),
        );

        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let mut config = base_config();
        config.urls = vec![format!("http://{addr}/derpmap/default")];
        let runtime = DerpMapRuntime::bootstrap(&config).await?;

        let effective = runtime.effective_map();
        assert!(effective.regions.contains_key(&900));
        assert!(effective.regions.contains_key(&901));

        server.abort();
        Ok(())
    }
}

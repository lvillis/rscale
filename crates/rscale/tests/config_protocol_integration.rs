use std::{error::Error, fs};

use rscale::VERSION;
use rscale::config::AppConfig;
use rscale::protocol::{
    EarlyNoise, MapResponse, config_derp_map, default_home_derp, encode_json_body,
    encode_map_response_frame, keep_alive_response, legacy_derp, preferred_derp,
};

#[test]
fn app_config_loads_from_file_and_derp_helpers_use_public_types() -> Result<(), Box<dyn Error>> {
    let path = std::env::temp_dir().join(format!("{VERSION}-rscale-config.toml"));
    let config = r#"
[server]
bind_addr = "127.0.0.1:9443"
public_base_url = "https://control.example.com"
control_private_key = "privkey:39db4bc58516d4d4be0d8e476c1a498c6ac0e44ef92ef4628c4f4578890e4f4f"

[network]
tailnet_ipv4_range = "100.64.0.0/10"
tailnet_ipv6_range = "fd7a:115c:a1e0::/48"

[database]
url = "postgres://rscale:rscale@127.0.0.1/rscale"

[auth]
break_glass_token = "break-glass-token-for-tests"

[auth.oidc]
enabled = false

[derp]
refresh_interval_secs = 300

[[derp.regions]]
region_id = 900
region_code = "test-a"
region_name = "Test Region A"
avoid = false
no_measure_no_home = true

[[derp.regions.nodes]]
name = "a-1"
host_name = "derp-a.example.com"
cert_name = "derp-a.example.com"
derp_port = 443
stun_port = 3478

[[derp.regions]]
region_id = 901
region_code = "test-b"
region_name = "Test Region B"
avoid = false
no_measure_no_home = false

[[derp.regions.nodes]]
name = "b-1"
host_name = "derp-b.example.com"
cert_name = "derp-b.example.com"
derp_port = 443
stun_port = 3478

[telemetry]
filter = "info"
"#;

    fs::write(&path, config)?;

    let loaded = AppConfig::load_with_report(Some(&path))?;
    assert!(loaded.summary().derp_region_count >= 2);
    assert_eq!(loaded.config().server.bind_addr, "127.0.0.1:9443");

    let derp_map = config_derp_map(&loaded.config().derp);
    assert_eq!(default_home_derp(&derp_map), 901);

    let preferred = preferred_derp(
        Some(&serde_json::json!({
            "NetInfo": {
                "PreferredDERP": 901
            }
        })),
        &derp_map,
    );
    assert_eq!(preferred, 901);

    let fallback = preferred_derp(
        Some(&serde_json::json!({
            "NetInfo": {
                "PreferredDERP": 999
            }
        })),
        &derp_map,
    );
    assert_eq!(fallback, 901);
    assert_eq!(legacy_derp(901), "127.3.3.40:901");

    fs::remove_file(path)?;
    Ok(())
}

#[test]
fn public_protocol_helpers_encode_frames_and_json() -> Result<(), Box<dyn Error>> {
    let response = MapResponse {
        collect_services: Some(true),
        ..keep_alive_response()
    };
    let plain = encode_map_response_frame(&response, "")?;
    let compressed = encode_map_response_frame(&response, "zstd")?;

    assert!(!plain.is_empty());
    assert!(!compressed.is_empty());
    assert_ne!(plain, compressed);

    let early = EarlyNoise {
        node_key_challenge: "challenge:deadbeef".to_owned(),
    };
    let early_json = encode_json_body(&early)?;
    let decoded_early: EarlyNoise = serde_json::from_slice(&early_json)?;
    assert_eq!(decoded_early.node_key_challenge, "challenge:deadbeef");

    Ok(())
}

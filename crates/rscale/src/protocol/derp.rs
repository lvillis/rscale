use crate::config::{DerpConfig, DerpRegionConfig};

use super::types::{ControlDerpHomeParams, ControlDerpMap, ControlDerpNode, ControlDerpRegion};

pub fn config_derp_map(config: &DerpConfig) -> ControlDerpMap {
    ControlDerpMap {
        home_params: (!config.home_params.region_score.is_empty()).then(|| ControlDerpHomeParams {
            region_score: config.home_params.region_score.clone(),
        }),
        regions: config
            .regions
            .iter()
            .map(|region| (region.region_id, to_control_derp_region(region)))
            .collect(),
        omit_default_regions: config.omit_default_regions,
    }
}

pub fn preferred_derp(hostinfo: Option<&serde_json::Value>, derp_map: &ControlDerpMap) -> i32 {
    let preferred = hostinfo
        .and_then(|hostinfo| hostinfo.get("NetInfo"))
        .and_then(|netinfo| netinfo.get("PreferredDERP"))
        .and_then(serde_json::Value::as_i64)
        .and_then(|value| i32::try_from(value).ok());

    if let Some(preferred) = preferred.filter(|preferred| *preferred > 0)
        && let Ok(region_id) = u32::try_from(preferred)
        && derp_map.regions.contains_key(&region_id)
    {
        return preferred;
    }

    default_home_derp(derp_map)
}

pub fn default_home_derp(derp_map: &ControlDerpMap) -> i32 {
    derp_map
        .regions
        .values()
        .find(|region| !region.no_measure_no_home)
        .or_else(|| derp_map.regions.values().next())
        .and_then(|region| i32::try_from(region.region_id).ok())
        .unwrap_or_default()
}

pub fn legacy_derp(home_derp: i32) -> String {
    if home_derp > 0 {
        format!("127.3.3.40:{home_derp}")
    } else {
        String::new()
    }
}

fn to_control_derp_region(region: &DerpRegionConfig) -> ControlDerpRegion {
    ControlDerpRegion {
        region_id: region.region_id,
        region_code: region.region_code.clone(),
        region_name: region.region_name.clone(),
        latitude: region.latitude,
        longitude: region.longitude,
        avoid: region.avoid,
        no_measure_no_home: region.no_measure_no_home,
        nodes: region
            .nodes
            .iter()
            .map(|node| ControlDerpNode {
                name: node.name.clone(),
                region_id: region.region_id,
                host_name: node.host_name.clone(),
                cert_name: node.cert_name.clone().unwrap_or_default(),
                ipv4: node.ipv4.clone().unwrap_or_default(),
                ipv6: node.ipv6.clone().unwrap_or_default(),
                stun_port: node.stun_port,
                stun_only: node.stun_only,
                derp_port: node.derp_port,
                insecure_for_tests: node.insecure_for_tests,
                stun_test_ip: node.stun_test_ip.clone().unwrap_or_default(),
                can_port80: node.can_port80,
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn preferred_derp_falls_back_to_first_home_region() {
        let map = ControlDerpMap {
            regions: BTreeMap::from([
                (
                    900,
                    ControlDerpRegion {
                        region_id: 900,
                        region_code: "sha".to_string(),
                        region_name: "Shanghai".to_string(),
                        no_measure_no_home: true,
                        ..ControlDerpRegion::default()
                    },
                ),
                (
                    901,
                    ControlDerpRegion {
                        region_id: 901,
                        region_code: "tyo".to_string(),
                        region_name: "Tokyo".to_string(),
                        ..ControlDerpRegion::default()
                    },
                ),
            ]),
            ..ControlDerpMap::default()
        };

        assert_eq!(preferred_derp(None, &map), 901);
    }
}

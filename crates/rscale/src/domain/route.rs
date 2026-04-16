use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Route {
    pub id: u64,
    pub node_id: u64,
    pub prefix: String,
    pub advertised: bool,
    pub approval: RouteApproval,
    #[serde(default)]
    pub approved_by_policy: bool,
    pub is_exit_node: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RouteApproval {
    Pending,
    Approved,
    Rejected,
}

impl RouteApproval {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "approved" => Some(Self::Approved),
            "rejected" => Some(Self::Rejected),
            _ => None,
        }
    }
}

impl Route {
    pub fn validate(&self) -> AppResult<()> {
        validate_route_prefix(&self.prefix)
    }
}

pub fn validate_route_prefix(prefix: &str) -> AppResult<()> {
    let (address, prefix_len) = prefix
        .split_once('/')
        .ok_or_else(|| AppError::InvalidRequest(format!("route prefix must be CIDR: {prefix}")))?;

    if let Ok(ipv4) = address.parse::<std::net::Ipv4Addr>() {
        let prefix_len: u8 = prefix_len.parse().map_err(|err| {
            AppError::InvalidRequest(format!("invalid IPv4 route prefix {prefix}: {err}"))
        })?;
        if prefix_len > 32 {
            return Err(AppError::InvalidRequest(format!(
                "invalid IPv4 route prefix length: {prefix}"
            )));
        }

        let _ = ipv4;
        return Ok(());
    }

    if let Ok(ipv6) = address.parse::<std::net::Ipv6Addr>() {
        let prefix_len: u8 = prefix_len.parse().map_err(|err| {
            AppError::InvalidRequest(format!("invalid IPv6 route prefix {prefix}: {err}"))
        })?;
        if prefix_len > 128 {
            return Err(AppError::InvalidRequest(format!(
                "invalid IPv6 route prefix length: {prefix}"
            )));
        }

        let _ = ipv6;
        return Ok(());
    }

    Err(AppError::InvalidRequest(format!(
        "route prefix must contain a valid IP network: {prefix}"
    )))
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    #[test]
    fn route_approval_round_trips_to_strings() {
        for (approval, expected) in [
            (RouteApproval::Pending, "pending"),
            (RouteApproval::Approved, "approved"),
            (RouteApproval::Rejected, "rejected"),
        ] {
            assert_eq!(approval.as_str(), expected);
            assert_eq!(RouteApproval::parse(expected), Some(approval));
        }
        assert_eq!(RouteApproval::parse("unknown"), None);
    }

    #[test]
    fn validate_route_prefix_accepts_ipv4_and_ipv6_cidrs() -> Result<(), Box<dyn Error>> {
        validate_route_prefix("10.0.0.0/24")?;
        validate_route_prefix("fd7a:115c:a1e0::/48")?;
        Ok(())
    }

    #[test]
    fn validate_route_prefix_rejects_invalid_networks() -> Result<(), Box<dyn Error>> {
        let not_cidr = match validate_route_prefix("10.0.0.1") {
            Ok(()) => return Err(std::io::Error::other("CIDR separator is required").into()),
            Err(err) => err,
        };
        assert!(
            matches!(not_cidr, AppError::InvalidRequest(message) if message.contains("must be CIDR"))
        );

        let bad_length = match validate_route_prefix("10.0.0.0/33") {
            Ok(()) => {
                return Err(std::io::Error::other("invalid IPv4 prefix length should fail").into());
            }
            Err(err) => err,
        };
        assert!(
            matches!(bad_length, AppError::InvalidRequest(message) if message.contains("prefix length"))
        );

        let bad_ip = match validate_route_prefix("not-an-ip/24") {
            Ok(()) => return Err(std::io::Error::other("invalid IP should fail").into()),
            Err(err) => err,
        };
        assert!(
            matches!(bad_ip, AppError::InvalidRequest(message) if message.contains("valid IP network"))
        );
        Ok(())
    }
}

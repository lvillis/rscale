use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DnsConfig {
    pub magic_dns: bool,
    pub base_domain: Option<String>,
    pub nameservers: Vec<String>,
    pub search_domains: Vec<String>,
}

impl DnsConfig {
    pub fn validate(&self) -> AppResult<()> {
        if self.magic_dns && self.base_domain.as_deref().is_none_or(str::is_empty) {
            return Err(AppError::InvalidRequest(
                "dns.base_domain is required when magic_dns is enabled".to_string(),
            ));
        }

        if self.base_domain.as_deref().is_some_and(str::is_empty) {
            return Err(AppError::InvalidRequest(
                "dns.base_domain must not be empty".to_string(),
            ));
        }

        if self.nameservers.iter().any(|value| value.trim().is_empty()) {
            return Err(AppError::InvalidRequest(
                "dns.nameservers must not contain empty values".to_string(),
            ));
        }

        if self
            .search_domains
            .iter()
            .any(|value| value.trim().is_empty())
        {
            return Err(AppError::InvalidRequest(
                "dns.search_domains must not contain empty values".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    #[test]
    fn dns_config_rejects_magic_dns_without_base_domain() -> Result<(), Box<dyn Error>> {
        let err = match (DnsConfig {
            magic_dns: true,
            base_domain: None,
            nameservers: Vec::new(),
            search_domains: Vec::new(),
        })
        .validate()
        {
            Ok(()) => {
                return Err(
                    std::io::Error::other("magic DNS without base domain should fail").into(),
                );
            }
            Err(err) => err,
        };
        assert!(
            matches!(err, AppError::InvalidRequest(message) if message.contains("base_domain is required"))
        );
        Ok(())
    }

    #[test]
    fn dns_config_rejects_empty_nameserver_or_search_domain_entries() -> Result<(), Box<dyn Error>>
    {
        let nameserver_err = match (DnsConfig {
            magic_dns: false,
            base_domain: Some("tailnet.example.com".to_string()),
            nameservers: vec!["".to_string()],
            search_domains: Vec::new(),
        })
        .validate()
        {
            Ok(()) => return Err(std::io::Error::other("empty nameserver should fail").into()),
            Err(err) => err,
        };
        assert!(
            matches!(nameserver_err, AppError::InvalidRequest(message) if message.contains("nameservers"))
        );

        let search_domain_err = match (DnsConfig {
            magic_dns: false,
            base_domain: Some("tailnet.example.com".to_string()),
            nameservers: Vec::new(),
            search_domains: vec![" ".to_string()],
        })
        .validate()
        {
            Ok(()) => return Err(std::io::Error::other("empty search domain should fail").into()),
            Err(err) => err,
        };
        assert!(
            matches!(search_domain_err, AppError::InvalidRequest(message) if message.contains("search_domains"))
        );
        Ok(())
    }

    #[test]
    fn dns_config_accepts_valid_magic_dns_setup() -> Result<(), Box<dyn Error>> {
        DnsConfig {
            magic_dns: true,
            base_domain: Some("tailnet.example.com".to_string()),
            nameservers: vec!["1.1.1.1".to_string()],
            search_domains: vec!["svc.tailnet.example.com".to_string()],
        }
        .validate()?;
        Ok(())
    }
}

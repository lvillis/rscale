use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::config::{LogFormat, LogTimezone, TelemetryConfig};
use crate::error::{AppError, AppResult};

pub fn init(config: &TelemetryConfig) -> AppResult<()> {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(config.filter.clone()))
        .map_err(|err| AppError::Bootstrap(format!("invalid log filter: {err}")))?;

    match (config.format.clone(), config.timezone.clone()) {
        (LogFormat::Json, LogTimezone::Utc) => tracing_subscriber::registry()
            .with(filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_timer(tracing_subscriber::fmt::time::UtcTime::rfc_3339()),
            )
            .try_init(),
        (LogFormat::Pretty, LogTimezone::Utc) => tracing_subscriber::registry()
            .with(filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .pretty()
                    .with_timer(tracing_subscriber::fmt::time::UtcTime::rfc_3339()),
            )
            .try_init(),
        (LogFormat::Compact, LogTimezone::Utc) => tracing_subscriber::registry()
            .with(filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .compact()
                    .with_timer(tracing_subscriber::fmt::time::UtcTime::rfc_3339()),
            )
            .try_init(),
        (LogFormat::Json, LogTimezone::Local) => tracing_subscriber::registry()
            .with(filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_timer(local_rfc3339_timer()?),
            )
            .try_init(),
        (LogFormat::Pretty, LogTimezone::Local) => tracing_subscriber::registry()
            .with(filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .pretty()
                    .with_timer(local_rfc3339_timer()?),
            )
            .try_init(),
        (LogFormat::Compact, LogTimezone::Local) => tracing_subscriber::registry()
            .with(filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .compact()
                    .with_timer(local_rfc3339_timer()?),
            )
            .try_init(),
    }
    .map_err(|err| AppError::Bootstrap(format!("failed to initialize telemetry: {err}")))?;

    Ok(())
}

fn local_rfc3339_timer() -> AppResult<
    tracing_subscriber::fmt::time::OffsetTime<time::format_description::well_known::Rfc3339>,
> {
    tracing_subscriber::fmt::time::OffsetTime::local_rfc_3339().map_err(|err| {
        AppError::Bootstrap(format!(
            "failed to determine local timezone offset for log timestamps: {err}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::sync::OnceLock;

    use super::*;

    static TELEMETRY_INIT_RESULT: OnceLock<Result<(), String>> = OnceLock::new();
    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    #[test]
    fn init_accepts_default_config() {
        let result = TELEMETRY_INIT_RESULT
            .get_or_init(|| init(&TelemetryConfig::default()).map_err(|err| err.to_string()));
        assert!(
            result.is_ok(),
            "default telemetry config should initialize successfully: {result:?}"
        );
    }

    #[test]
    fn init_rejects_invalid_filter_expression() -> TestResult {
        let err = match init(&TelemetryConfig {
            filter: "[".to_string(),
            format: LogFormat::Json,
            timezone: LogTimezone::Utc,
        }) {
            Ok(_) => return Err(std::io::Error::other("invalid filter should be rejected").into()),
            Err(err) => err,
        };
        assert!(
            matches!(err, AppError::Bootstrap(message) if message.contains("invalid log filter"))
        );
        Ok(())
    }
}

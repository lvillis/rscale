use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::config::{LogFormat, TelemetryConfig};
use crate::error::{AppError, AppResult};

pub fn init(config: &TelemetryConfig) -> AppResult<()> {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(config.filter.clone()))
        .map_err(|err| AppError::Bootstrap(format!("invalid log filter: {err}")))?;

    match config.format {
        LogFormat::Json => tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().json())
            .try_init(),
        LogFormat::Pretty => tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().pretty())
            .try_init(),
        LogFormat::Compact => tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().compact())
            .try_init(),
    }
    .map_err(|err| AppError::Bootstrap(format!("failed to initialize telemetry: {err}")))?;

    Ok(())
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

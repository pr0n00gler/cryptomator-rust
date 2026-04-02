use tracing_subscriber::{EnvFilter, prelude::*};

/// Initializes the global tracing subscriber.
///
/// The log filter is resolved in priority order:
/// 1. The `RUST_LOG` environment variable (if set and valid).
/// 2. The `log_level` argument passed by the caller.
/// 3. The hard-coded default `"info"`.
///
/// Returns a [`WorkerGuard`] that must be kept alive for the duration of the
/// program — dropping it flushes and shuts down the background logging thread.
pub fn init_logger(log_level: &str) -> tracing_appender::non_blocking::WorkerGuard {
    let registry = tracing_subscriber::registry();
    let (non_blocking, guard) = tracing_appender::non_blocking(std::io::stdout());
    let fmt_layer = tracing_subscriber::fmt::layer().with_writer(non_blocking);
    // Prefer the RUST_LOG env var if already set, then fall back to the CLI
    // argument, then to "info".  This avoids mutating the process environment
    // (which is not thread-safe in an async program).
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(log_level))
        .unwrap_or_else(|_| EnvFilter::new("info"));
    registry.with(filter).with(fmt_layer).init();
    guard
}

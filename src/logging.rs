use tracing_subscriber::{EnvFilter, prelude::*};

pub fn init_logger() -> tracing_appender::non_blocking::WorkerGuard {
    let registry = tracing_subscriber::registry();
    let (non_blocking, guard) = tracing_appender::non_blocking(std::io::stdout());
    let fmt_layer = tracing_subscriber::fmt::layer().with_writer(non_blocking);
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    registry.with(filter).with(fmt_layer).init();
    guard
}

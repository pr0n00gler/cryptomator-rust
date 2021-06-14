use tracing_subscriber::{prelude::*, EnvFilter};

pub fn init_logger() -> tracing_appender::non_blocking::WorkerGuard {
    let registry = tracing_subscriber::registry();
    let (non_blocking, guard) = tracing_appender::non_blocking(std::io::stdout());
    let stdout_subscriber = tracing_subscriber::fmt::subscriber().with_writer(non_blocking);
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    registry.with(stdout_subscriber).with(filter).init();
    guard
}

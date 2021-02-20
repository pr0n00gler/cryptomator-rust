use slog::Drain;
use std::env;

pub fn init_logger() -> (slog_scope::GlobalLoggerGuard, slog_async::AsyncGuard) {
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info")
    }
    let decorator = slog_term::TermDecorator::new().build();
    let term_drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_envlogger::new(term_drain);
    let (drain, async_guard) = slog_async::Async::new(drain)
        .thread_name("cryptomator_logger".to_string())
        .build_with_guard();
    let log = slog::Logger::root(drain.fuse(), slog::slog_o!());
    let scope_guard = slog_scope::set_global_logger(log);
    slog_stdlog::init().unwrap();
    (scope_guard, async_guard)
}

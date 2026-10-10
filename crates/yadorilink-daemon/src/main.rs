//! Long-running sync daemon entry point.
//!
//! This is deliberately thin: it builds the real (production) multi-threaded
//! tokio runtime and hands off to [`yadorilink_daemon::app::run`], which
//! holds the entire daemon lifecycle. Keeping the lifecycle in the library
//! is what lets a test drive an in-process daemon instance by calling
//! `run(..)` directly with its own `DaemonConfig`, instead of going through
//! this real process entry point.

// `yadorilink-daemon` takes no arguments at all -- every real
// setting comes from `DaemonConfig::from_env()`, matching this binary's own
// doc comment above. `--version`/`-V` is the one argument handled here
// (not via `clap`, to keep this genuinely thin): a daemon binary that
// silently ignores `--version` and starts the full sync daemon instead is
// a real footgun for a package build/test step (this repo's own
// `juntaki/homebrew-yadorilink` Formula test, `lintian`, a Docker
// healthcheck) that expects the ordinary `binary --version` convention to
// just print a version and exit, not bind sockets and open a database.
fn print_version_and_exit_if_requested() {
    if std::env::args().skip(1).any(|arg| arg == "--version" || arg == "-V") {
        println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    print_version_and_exit_if_requested();
    {
        use tracing_subscriber::filter::FilterExt as _;
        use tracing_subscriber::layer::{Layer as _, SubscriberExt as _};
        use tracing_subscriber::util::SubscriberInitExt as _;
        let env = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
        let throttle = yadorilink_daemon::log_throttle::WarnThrottle::default();
        let filter = env.and(throttle);
        // The macOS LaunchAgent sets YADORILINK_LOG_FILE so logs roll by size
        // instead of growing in launchd's unrotated StandardOutPath files.
        let rolling = std::env::var_os("YADORILINK_LOG_FILE").and_then(|p| {
            yadorilink_daemon::log_roll::RollingLog::open(
                p.into(),
                yadorilink_daemon::log_roll::MAX_BYTES,
            )
            .ok()
        });
        match rolling {
            Some(w) => tracing_subscriber::registry()
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_ansi(false)
                        .with_writer(w)
                        .with_filter(filter),
                )
                .init(),
            None => tracing_subscriber::registry()
                .with(tracing_subscriber::fmt::layer().with_filter(filter))
                .init(),
        }
    }
    yadorilink_daemon::fd_limit::raise_nofile_soft_limit();
    yadorilink_daemon::app::run(yadorilink_daemon::app::DaemonConfig::from_env()).await
}

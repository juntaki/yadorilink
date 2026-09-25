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
    tracing_subscriber::fmt::init();
    yadorilink_daemon::app::run(yadorilink_daemon::app::DaemonConfig::from_env()).await
}

//! Long-running sync daemon entry point.
//!
//! This is deliberately thin: it builds the real (production) multi-threaded
//! tokio runtime and hands off to [`yadorilink_daemon::app::run`], which
//! holds the entire daemon lifecycle. Keeping the lifecycle in the library
//! is what lets a deterministic-simulation node drive an in-process daemon
//! instance by calling `run(..)` directly with a simulated `DaemonConfig`,
//! instead of going through this real process entry point.

// Under the deterministic simulator (`--cfg madsim`) the daemon is driven
// by a simulation node calling `yadorilink_daemon::app::run(..)` inside the
// simulator, not by this real entry point — `#[tokio::main]` expands to the
// real multi-threaded runtime, which is exactly what must NOT run in-sim. A
// trivial stub keeps this bin target compiling under `--cfg madsim` (the
// simulator provides its own `#[madsim::main]`/`#[madsim::test]` entry
// points in the DST test binaries).
#[cfg(madsim)]
fn main() {}

#[cfg(not(madsim))]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    yadorilink_daemon::app::run(yadorilink_daemon::app::DaemonConfig::from_env()).await
}

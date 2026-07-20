//! Test-only synchronization shared across this crate's unit tests.
//!
//! `YADORILINK_CONFIG_DIR` is a process-global env var read by
//! `device_config::config_dir` (and, transitively, by `DaemonState::new`'s
//! `GovernanceConfigStore`/`UpdateManager`/`ReportingStorage` construction).
//! Rust runs a crate's unit tests concurrently, on multiple threads of the
//! same process, by default — so any two tests that each set/restore this
//! env var independently can race and observe each other's temp directory
//! mid-test.
//!
//! `daemon_state.rs`, `device_config.rs`, and `reporting/retry.rs` each
//! used to declare their own *separate* module-local mutex for this
//! (`CONFIG_ENV_MUTEX`/`CONFIG_DIR_ENV_LOCK`/`TEST_MUTEX`), which only
//! serializes tests within the same file — not against each other. That
//! gap was real, not theoretical: adding
//! `daemon_state::tests::daemon_startup_discards_an_unverified_download_left_by_a_crash`
//! reproduced it directly — the
//! test passed reliably when run in isolation but failed once under a
//! full `cargo test --workspace` run, because a concurrently-running test
//! in one of the *other* two modules changed `YADORILINK_CONFIG_DIR`
//! between this test setting it and `DaemonState::new` reading it.
//!
//! This single shared mutex is the actual fix: every test in this crate
//! that touches `YADORILINK_CONFIG_DIR` must hold it for the env var's
//! entire set-to-restore window, regardless of which module it lives in.
//! `tokio::sync::Mutex` (rather than `std::sync::Mutex`) so it can be held
//! across `.await` points in the async tests that need that (e.g.
//! `reporting::retry::tests`'s `test_state.await`); synchronous tests
//! (`device_config.rs`) use `blocking_lock` instead.
#[cfg(test)]
pub(crate) static CONFIG_ENV_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

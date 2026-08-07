//! Capability-typed placeholder providers for on-demand materialization.
//!
//! `chunker::write_placeholder` writes an ordinary sparse file: correct
//! `stat` size/mtime, no real content, but NOT an OS-transparent
//! placeholder. Nothing marks it as one to the OS, so nothing but this
//! process's own size/mtime heuristics (`local_change.rs`) can tell "this
//! is a placeholder awaiting hydration" from "this is a genuine sparse file
//! the user created" or "this file's content was truly replaced by
//! something the same size" — and on at least one platform (Windows) the
//! allocated-vs-actual-data distinction that would disambiguate this is not
//! checked at all, so a real edit that happens to land on the same size and
//! mtime is silently ignored as a self-echo (see `local_change.rs`'s own
//! dirty-detection doc comment).
//!
//! A real OS placeholder provider (Cloud Filter API reparse points on
//! Windows, a `NSFileProviderReplicatedExtension` item on macOS) instead
//! issues its own opaque generation token at creation time, independent of
//! size/mtime, and the OS itself (not this process's own stat heuristics)
//! is the authority on whether the on-disk object has been touched since.
//!
//! This module is the seam a real provider plugs into. `probe` reports
//! whether one is actually available for a given root — today, on every
//! platform, it is not (no provider is wired up yet; see this crate's
//! `chunker::write_placeholder` doc comment), so `finish_link_setup`
//! (`yadorilink-daemon::control_socket`) must keep gating on this rather
//! than on `cfg!(target_os = ...)`, so wiring up a real backend later is a
//! change to what `probe` returns, not a change to every call site that
//! decides whether `OnDemand` is honored.

use std::path::Path;

use yadorilink_root_authority::RootAuthorityError;

/// Whether a real OS-transparent placeholder provider is available for a
/// given sync root. `Unsupported` is not a permanent property of a
/// platform — a future macOS/Windows build wiring up a real provider makes
/// `probe` start returning `Supported` for the same root without any
/// caller needing to change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaceholderCapability {
    /// No OS-transparent placeholder provider is available for this root on
    /// this build. A caller that wants `OnDemand` materialization anyway
    /// has exactly two honest choices: fall back to `Eager` (this crate's
    /// `MaterializationPolicy::Eager`, which never places a placeholder at
    /// all), or refuse the request outright. Silently placing an ordinary
    /// sparse file and calling it `OnDemand` is what this type exists to
    /// stop.
    Unsupported,
    /// A real provider is available and already initialized for this root.
    /// `name` is a short, stable, human-readable identifier (e.g.
    /// `"macos-fileprovider"`) for logging/diagnostics, not for matching
    /// against in caller logic — match on the enum variant, not the string.
    Supported { name: &'static str },
}

impl PlaceholderCapability {
    pub fn supports_on_demand(self) -> bool {
        matches!(self, PlaceholderCapability::Supported { .. })
    }
}

/// Whether this daemon build's `OnDemand` pipeline is actually connected
/// end-to-end, not merely "does some `PlaceholderBackend` impl exist in this
/// codebase." Being `true` requires ALL of:
///
/// 1. A live, per-link `PlaceholderBackend` provider session held for the
///    link's whole lifetime (mirroring how `LinkRuntime` holds the sync-root
///    OS lock today) — not constructed ad hoc per call.
/// 2. That provider's `PlaceholderGeneration` token persisted in the index
///    (surviving a daemon restart), not held only in memory.
/// 3. `local_change.rs`'s dirty detection reading `PlaceholderBackend::
///    inspect`'s `PlaceholderStatus` for a placeholder path instead of its
///    current size/mtime heuristic (see that module's own doc comment on
///    why the heuristic is unreliable — this is the exact gap
///    `PlaceholderStatus::{Untouched,Dirty,Unknown}` exists to close).
/// 4. `materialization.rs`'s placeholder-create/hydrate/evict paths calling
///    through `PlaceholderBackend::{create,hydrate}` instead of
///    `chunker::write_placeholder` (an ordinary sparse file with none of the
///    above properties — see that function's own doc comment).
///
/// None of the four exist yet anywhere in this codebase's runtime path —
/// `write_placeholder` is still what every `OnDemand` materialization call
/// site (`peer_session::materialize`, `materialization::run_eviction_sweep`,
/// `materialization::evict_file`, ...) actually calls. This is therefore
/// unconditionally `false`, regardless of what any single backend's own
/// `PlaceholderBackend::probe` would report for the current OS/filesystem: a
/// theoretically-available OS provider (`WindowsCfApiBackend::probe`
/// returning `Supported` on a real Windows box, say) is a claim about OS
/// capability, not about whether THIS daemon build's materialization code
/// actually routes through it. `yadorilink-daemon`'s `finish_link_setup` and
/// `set_storage_mode` gate every `OnDemand` request on this function rather
/// than on a platform check or a backend's own `probe`, so wiring up the
/// four pieces above is what re-enables `OnDemand` in production — not a
/// second place needing to change.
///
/// Test code that specifically exercises OnDemand-gated behavior (a
/// disk-pressure eviction sweep actually reclaiming a candidate, say) uses
/// [`OverrideForTest`] to force this `true` for its own thread only, rather
/// than this function ever returning anything but `false` in production.
pub fn on_demand_pipeline_is_connected() -> bool {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(overridden) = TEST_OVERRIDE.with(|cell| cell.get()) {
        return overridden;
    }
    false
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static TEST_OVERRIDE: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// RAII override of [`on_demand_pipeline_is_connected`] for the current
/// thread only -- not a process-wide flag, since `cargo test` runs many
/// tests concurrently on separate threads and a global toggle would make
/// one test's override leak into an unrelated one running at the same
/// time. Restores whatever override (or absence of one) was in effect
/// before `enable()` when dropped, so a thread the test harness reuses for
/// a later test never inherits a stale value.
#[cfg(any(test, feature = "test-support"))]
pub struct OverrideForTest {
    previous: Option<bool>,
}

#[cfg(any(test, feature = "test-support"))]
impl OverrideForTest {
    pub fn enable() -> Self {
        let previous = TEST_OVERRIDE.with(|cell| cell.replace(Some(true)));
        Self { previous }
    }
}

#[cfg(any(test, feature = "test-support"))]
impl Drop for OverrideForTest {
    fn drop(&mut self) {
        TEST_OVERRIDE.with(|cell| cell.set(self.previous));
    }
}

/// An opaque, provider-issued token identifying one placeholder's current
/// "generation" — minted at `create` time and compared, not recomputed, at
/// `inspect` time. Never derived from size/mtime: those are exactly the
/// signals a provider exists to stop trusting (see this module's own doc).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PlaceholderGeneration(pub u64);

/// The result of asking a provider whether a placeholder it created has
/// since been touched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaceholderStatus {
    /// The on-disk object is still exactly the placeholder this provider
    /// created — safe to hydrate over or evict back to a placeholder
    /// without losing anything.
    Untouched,
    /// The provider's own signal (not this process's stat heuristics) says
    /// the object has been written to, replaced, or otherwise materialized
    /// since `create` — must be treated as a real local change, never
    /// silently overwritten.
    Dirty,
    /// The provider could not determine which of the above is true (e.g.
    /// the object is gone, or the provider's own state is unavailable).
    /// Fails closed: a caller must treat this exactly like `Dirty`, never
    /// like `Untouched`.
    Unknown,
}

/// A real OS-transparent placeholder provider for one sync root.
///
/// Implementors mint their own generation tokens and are the sole
/// authority on `inspect`'s answer — no implementation may fall back to
/// comparing size/mtime internally, since that is precisely the
/// unreliable signal this trait exists to replace.
pub trait PlaceholderBackend: Send + Sync {
    /// Probes whether this backend is available and usable for `root` on
    /// this build/platform/filesystem. Must be cheap enough to call once
    /// per link setup (`finish_link_setup`) — no network I/O, no lengthy
    /// directory walk.
    fn probe(root: &Path) -> PlaceholderCapability
    where
        Self: Sized;

    /// Creates a placeholder for a file of `size` bytes at `path`,
    /// returning the generation token the provider minted for it.
    fn create(
        &self,
        path: &Path,
        size: u64,
        mtime_unix_nanos: i64,
    ) -> Result<PlaceholderGeneration, RootAuthorityError>;

    /// Asks the provider whether the placeholder at `path` — created with
    /// `expected` — has been touched since.
    fn inspect(
        &self,
        path: &Path,
        expected: PlaceholderGeneration,
    ) -> Result<PlaceholderStatus, RootAuthorityError>;

    /// Populates the placeholder at `path` with `content`, read from
    /// `content` (already assembled by the caller — e.g. a reconstructed
    /// file from `chunker`/`materialization`) rather than the caller
    /// writing to `path` directly first: an ordinary filesystem write into
    /// an unpopulated placeholder byte range requires the OS to attempt a
    /// fetch through this provider first, which times out with no live
    /// fetch callback registered (confirmed empirically against the real
    /// Cloud Filter API — see `placeholder_backend_windows`'s own doc).
    /// The provider must inject the bytes itself through its own
    /// platform-mediated write path instead of relying on a plain
    /// `std::fs` write succeeding.
    fn hydrate(
        &self,
        path: &Path,
        content: &mut dyn std::io::Read,
    ) -> Result<(), RootAuthorityError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_never_reports_on_demand_support() {
        assert!(!PlaceholderCapability::Unsupported.supports_on_demand());
    }

    #[test]
    fn supported_reports_on_demand_support() {
        assert!(PlaceholderCapability::Supported { name: "test" }.supports_on_demand());
    }

    #[test]
    fn on_demand_pipeline_is_not_yet_connected() {
        assert!(
            !on_demand_pipeline_is_connected(),
            "flip this only once a live provider session, persisted generation, \
             PlaceholderStatus-based dirty detection, and a PlaceholderBackend-routed \
             hydrate/evict path are all actually wired -- see this function's own doc comment"
        );
    }

    #[test]
    fn override_for_test_is_scoped_to_its_own_lifetime() {
        assert!(!on_demand_pipeline_is_connected());
        {
            let _override = OverrideForTest::enable();
            assert!(on_demand_pipeline_is_connected());
        }
        assert!(
            !on_demand_pipeline_is_connected(),
            "the override must not outlive the guard that enabled it"
        );
    }
}

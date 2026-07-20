//! On-disk persistence for `yadorilink_reporting::ConsentState`
//! ("shape only, persistence lives in yadorilink-daemon" per that module's
//! doc comment). This is also where "local reporting config storage"
//! lives — `ConsentState` already carries `prompt_to_report_enabled` and
//! `endpoint_override`, so one JSON file covers consent *and* the
//! configurable knobs; there's no separate config file.
//!
//! Two invariants this module exists to uphold:
//! - A fresh install must never eagerly write a non-default consent file,
//!   and must never generate an anonymous reporter ID before the user
//!   opts in. `load` returns `ConsentState::default`
//!   without touching disk when no file exists yet; `save` is only ever
//!   called from an explicit mutation method.
//! - The anonymous reporter ID is a fresh random UUID (`new_reporter_id`),
//!   never derived from this device's `device_id` or any coordination-plane
//!   account identifier — this module has no access to either
//!   of those anyway, by construction (`ConsentStore` only ever sees a
//!   directory path).

use std::path::{Path, PathBuf};

use yadorilink_reporting::consent::ConsentState;

use super::error::ReportingResult;

/// Generates a fresh anonymous reporter ID. A plain random UUIDv4 has no
/// relationship to any yadorilink account ID or device ID — those are
/// assigned by the coordination plane / `device_config::DeviceConfig`,
/// neither of which this function (or this module) ever reads.
pub fn new_reporter_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub struct ConsentStore {
    path: PathBuf,
}

impl ConsentStore {
    pub fn new(reporting_dir: impl AsRef<Path>) -> Self {
        ConsentStore { path: reporting_dir.as_ref().join("consent.json") }
    }

    /// Loads the persisted consent state, or the safe default if no file
    /// has ever been written (fresh install, or reporting has never been
    /// touched) — this branch deliberately does **not** write anything to
    /// disk, so simply calling `load` can never turn a fresh install into
    /// one with a reporting directory/file on disk.
    pub fn load(&self) -> ReportingResult<ConsentState> {
        match std::fs::read_to_string(&self.path) {
            Ok(contents) => Ok(serde_json::from_str(&contents)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ConsentState::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Best-effort read for call sites that must never fail: falls back to
    /// the safe (reporting-disabled) default and logs a warning rather
    /// than propagating. This is what a non-reporting-specific call site
    /// (e.g. "should I even bother collecting a counter") should use.
    pub fn load_or_default(&self) -> ConsentState {
        match self.load() {
            Ok(state) => state,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    path = %self.path.display(),
                    "reporting: failed to load consent state; treating reporting as disabled"
                );
                ConsentState::default()
            }
        }
    }

    /// Writes `state` to disk, creating the reporting directory if needed.
    /// Writes to a temp file and renames over the target so a crash
    /// mid-write can't leave a half-written, unparseable consent file
    /// behind (`load` would otherwise treat that as a hard error).
    pub fn save(&self, state: &ConsentState) -> ReportingResult<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(state)?;
        let tmp_path = self.path.with_extension("json.tmp");
        std::fs::write(&tmp_path, json)?;
        std::fs::rename(&tmp_path, &self.path)?;
        Ok(())
    }

    fn mutate(&self, f: impl FnOnce(&mut ConsentState)) -> ReportingResult<ConsentState> {
        let mut state = self.load()?;
        f(&mut state);
        self.save(&state)?;
        Ok(state)
    }

    pub fn opt_in_usage(&self) -> ReportingResult<ConsentState> {
        self.mutate(|state| state.opt_in_usage(new_reporter_id))
    }

    pub fn opt_in_error_reporting(&self) -> ReportingResult<ConsentState> {
        self.mutate(|state| state.opt_in_error_reporting(new_reporter_id))
    }

    pub fn opt_in_crash_reporting(&self) -> ReportingResult<ConsentState> {
        self.mutate(|state| state.opt_in_crash_reporting(new_reporter_id))
    }

    pub fn disable_all_submission(&self) -> ReportingResult<ConsentState> {
        self.mutate(|state| state.disable_all_submission())
    }

    /// Always mints a brand new ID, severing any
    /// correlation with previously-submitted reports, without touching
    /// the submission-enabled flags.
    pub fn reset_reporter_id(&self) -> ReportingResult<ConsentState> {
        self.mutate(|state| state.reset_reporter_id(new_reporter_id))
    }

    pub fn set_prompt_to_report_enabled(&self, enabled: bool) -> ReportingResult<ConsentState> {
        self.mutate(|state| state.prompt_to_report_enabled = enabled)
    }

    pub fn set_queue_retry_enabled(&self, enabled: bool) -> ReportingResult<ConsentState> {
        self.mutate(|state| state.queue_retry_enabled = enabled)
    }

    pub fn set_endpoint_override(&self, endpoint: Option<String>) -> ReportingResult<ConsentState> {
        self.mutate(|state| state.endpoint_override = endpoint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, ConsentStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = ConsentStore::new(dir.path());
        (dir, store)
    }

    /// default disabled consent, and no file written just by
    /// reading it.
    #[test]
    fn fresh_store_reports_default_disabled_state_without_writing_a_file() {
        let (dir, store) = store();
        let state = store.load().unwrap();
        assert_eq!(state, ConsentState::default());
        assert!(!dir.path().join("consent.json").exists());
        assert!(!dir.path().join("reporting").exists());
    }

    /// opt-in state persistence.
    #[test]
    fn opt_in_usage_persists_across_a_new_store_instance() {
        let (dir, store) = store();
        let state = store.opt_in_usage().unwrap();
        assert!(state.usage_submission_enabled);
        assert!(state.anonymous_reporter_id.is_some());

        let reopened = ConsentStore::new(dir.path());
        let reloaded = reopened.load().unwrap();
        assert_eq!(reloaded, state);
    }

    /// ID reset.
    #[test]
    fn reset_reporter_id_changes_the_id_and_persists_the_change() {
        let (_dir, store) = store();
        let first = store.opt_in_usage().unwrap();
        let first_id = first.anonymous_reporter_id.clone().unwrap();

        let second = store.reset_reporter_id().unwrap();
        let second_id = second.anonymous_reporter_id.clone().unwrap();

        assert_ne!(first_id, second_id);
        assert_eq!(store.load().unwrap().anonymous_reporter_id, Some(second_id));
    }

    /// the generated ID must never look like (or be derived
    /// from) a device ID passed around elsewhere in the daemon — this is
    /// mostly structural (this module never receives one), but assert the
    /// generator produces a real random UUID each time as a sanity check.
    #[test]
    fn new_reporter_id_is_random_and_not_a_fixed_or_device_derived_value() {
        let a = new_reporter_id();
        let b = new_reporter_id();
        assert_ne!(a, b);
        assert!(uuid::Uuid::parse_str(&a).is_ok());
        let fake_device_id = "device-a";
        assert_ne!(a, fake_device_id);
    }

    #[test]
    fn disable_all_submission_keeps_the_reporter_id() {
        let (_dir, store) = store();
        let opted_in = store.opt_in_usage().unwrap();
        let id = opted_in.anonymous_reporter_id.clone().unwrap();
        let disabled = store.disable_all_submission().unwrap();
        assert!(disabled.is_fully_disabled());
        assert_eq!(disabled.anonymous_reporter_id, Some(id));
    }
}

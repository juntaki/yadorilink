//! Consent state shape (design.md D1, D7). This module defines the type
//! only — persistence (reading/writing it under the daemon's config
//! directory) is section 2's job, in `yadorilink-daemon`, which is the
//! only place that should ever construct or mutate one of these outside
//! tests.

use serde::{Deserialize, Serialize};

/// Every field defaults to the least-sharing option. `ConsentState::default()`
/// is the state a fresh install starts in: no network submission, no
/// automatic error submission, no anonymous reporter ID (one is created
/// only by `opt_in_usage`/`opt_in_error_reporting`, never implicitly).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ConsentState {
    pub usage_submission_enabled: bool,
    pub error_submission_enabled: bool,
    pub prompt_to_report_enabled: bool,
    pub queue_retry_enabled: bool,
    pub anonymous_reporter_id: Option<String>,
    pub endpoint_override: Option<String>,
}

impl Default for ConsentState {
    fn default() -> Self {
        ConsentState {
            usage_submission_enabled: false,
            error_submission_enabled: false,
            // Prompting (a purely local, no-network suggestion to run
            // `yadorilink report error --last`) defaults to on: it costs
            // the user nothing and is how they'd discover the feature
            // exists, unlike the two submission toggles above.
            prompt_to_report_enabled: true,
            queue_retry_enabled: false,
            anonymous_reporter_id: None,
            endpoint_override: None,
        }
    }
}

impl ConsentState {
    /// Enables usage-summary submission, creating an anonymous reporter
    /// ID if one doesn't already exist. Does not touch
    /// `error_submission_enabled` — usage and automatic-error submission
    /// are separate toggles per design.md D4.
    pub fn opt_in_usage(&mut self, new_reporter_id: impl FnOnce() -> String) {
        self.usage_submission_enabled = true;
        if self.anonymous_reporter_id.is_none() {
            self.anonymous_reporter_id = Some(new_reporter_id());
        }
    }

    pub fn opt_in_error_reporting(&mut self, new_reporter_id: impl FnOnce() -> String) {
        self.error_submission_enabled = true;
        if self.anonymous_reporter_id.is_none() {
            self.anonymous_reporter_id = Some(new_reporter_id());
        }
    }

    pub fn disable_all_submission(&mut self) {
        self.usage_submission_enabled = false;
        self.error_submission_enabled = false;
        self.queue_retry_enabled = false;
    }

    /// Resets the anonymous reporter ID without touching consent flags —
    /// a user who's opted in can still get a fresh ID (severing any
    /// correlation with reports already submitted under the old one)
    /// without having to opt out and back in.
    pub fn reset_reporter_id(&mut self, new_reporter_id: impl FnOnce() -> String) {
        self.anonymous_reporter_id = Some(new_reporter_id());
    }

    /// Reporting is entirely off in the sense that matters for "is it
    /// safe to skip prompting/queueing work at all": no submission
    /// paths are active. `prompt_to_report_enabled` doesn't factor in
    /// here since prompting alone sends nothing.
    pub fn is_fully_disabled(&self) -> bool {
        !self.usage_submission_enabled && !self.error_submission_enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_state_has_no_network_submission_and_no_reporter_id() {
        let state = ConsentState::default();
        assert!(!state.usage_submission_enabled);
        assert!(!state.error_submission_enabled);
        assert!(state.anonymous_reporter_id.is_none());
        assert!(state.is_fully_disabled());
    }

    #[test]
    fn opt_in_usage_creates_a_reporter_id_only_once() {
        let mut state = ConsentState::default();
        let mut calls = 0;
        state.opt_in_usage(|| {
            calls += 1;
            "id-1".to_string()
        });
        assert_eq!(state.anonymous_reporter_id.as_deref(), Some("id-1"));
        state.opt_in_error_reporting(|| {
            calls += 1;
            "id-2".to_string()
        });
        // Second opt-in reuses the existing ID rather than minting a new
        // one — the generator closure must not be called again.
        assert_eq!(state.anonymous_reporter_id.as_deref(), Some("id-1"));
        assert_eq!(calls, 1);
    }

    #[test]
    fn reset_reporter_id_always_generates_a_fresh_one() {
        let mut state = ConsentState::default();
        state.opt_in_usage(|| "id-1".to_string());
        state.reset_reporter_id(|| "id-2".to_string());
        assert_eq!(state.anonymous_reporter_id.as_deref(), Some("id-2"));
    }

    #[test]
    fn disable_all_submission_clears_flags_but_keeps_reporter_id() {
        let mut state = ConsentState::default();
        state.opt_in_usage(|| "id-1".to_string());
        state.disable_all_submission();
        assert!(state.is_fully_disabled());
        // The ID itself isn't cleared -- only an explicit reset does
        // that (`reset_reporter_id`), so re-enabling later doesn't
        // silently mint a brand new identity the user didn't ask for.
        assert_eq!(state.anonymous_reporter_id.as_deref(), Some("id-1"));
    }

    #[test]
    fn deserializing_an_empty_json_object_yields_the_safe_default() {
        // `#[serde(default)]` on the struct plus a real `Default` impl:
        // an old config file (or one hand-edited to `{}`) must still
        // resolve to "everything off," never to Rust's derived-Default
        // all-false-and-also-prompt-off shape, which is why this isn't
        // `#[derive(Default)]`.
        let state: ConsentState = serde_json::from_str("{}").unwrap();
        assert_eq!(state, ConsentState::default());
        assert!(state.prompt_to_report_enabled);
    }
}

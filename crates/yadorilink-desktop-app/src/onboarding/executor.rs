//! The effect executor. It runs each
//! [`Effect`] the machine emits off the UI thread on a short-lived tokio
//! runtime (the same threading pattern `main.rs`'s `handle_menu_event` uses
//! for its mutating actions), maps the `yadorilink_cli` result to an
//! [`Event`], and posts it back through an [`EventSink`] for the window to
//! feed into the next `step`.
//!
//! The result→event mapping for each effect is a pure function
//! (`*_to_event` / `preflight_to_view` below), unit-tested here without a
//! network or daemon; `spawn` is the thin real-world wrapper that performs the
//! actual call and posts the mapped event. Nothing in the machine or window
//! needs to know how an effect is carried out.

use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::sync::Arc;

use yadorilink_cli::commands::{device, link, share};
use yadorilink_cli::error::CliError;
use yadorilink_sync_core::link_preflight::LinkPreflightReport;

use super::machine::{Effect, Event, GroupOption, PreflightView};

/// A channel back to the UI thread plus a wake hook (the window passes
/// `egui::Context::request_repaint`) so a completed effect repaints promptly
/// instead of waiting for the next poll tick. Generic over the event type so
/// the account window (`crate::account`) can reuse it with its own event
/// enum; defaults to the onboarding [`Event`].
pub struct EventSink<E = Event> {
    tx: Sender<E>,
    wake: Arc<dyn Fn() + Send + Sync>,
}

impl<E> Clone for EventSink<E> {
    fn clone(&self) -> Self {
        EventSink { tx: self.tx.clone(), wake: self.wake.clone() }
    }
}

impl<E> EventSink<E> {
    pub fn new(tx: Sender<E>, wake: Arc<dyn Fn() + Send + Sync>) -> Self {
        EventSink { tx, wake }
    }

    pub fn send(&self, event: E) {
        // A closed receiver means the window is gone; nothing to do.
        let _ = self.tx.send(event);
        (self.wake)();
    }
}

/// Run `effect` on its own thread + current-thread tokio runtime and post the
/// resulting [`Event`] to `sink`. Returns immediately; the UI thread never
/// blocks.
pub fn spawn(effect: Effect, sink: EventSink) {
    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(e) => {
                sink.send(effect_error_event(&effect, format!("could not start runtime: {e}")));
                return;
            }
        };
        let event = runtime.block_on(execute(&effect));
        sink.send(event);
    });
}

/// Perform the effect's underlying `yadorilink_cli` call and map its result to
/// an event. Split from `spawn` so the async body is exercised together with
/// the pure mappers below.
/// spec "Abandoned consent is surfaced": the loopback listener otherwise waits
/// forever for the browser callback, so the sign-in effect is bounded — an
/// unreturned consent lands the sign-in step back in a retryable failure state
/// rather than a permanent spinner.
const SIGN_IN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

async fn execute(effect: &Effect) -> Event {
    match effect {
        Effect::StartLogin => {
            match tokio::time::timeout(SIGN_IN_TIMEOUT, crate::google_login::login()).await {
                Ok(result) => login_to_event(result),
                Err(_) => Event::SignInFailed(
                    "timed out waiting for browser sign-in — try again".to_string(),
                ),
            }
        }
        Effect::RegisterDevice { name } => {
            register_to_event(device::register_device(name.clone()).await)
        }
        // Same-account onboarding surfaces the account's own joinable folder
        // groups so a second device can pick one to link here.
        Effect::ListGroups => list_groups_to_event(share::list_joinable_groups().await),
        Effect::RunPreflight { path } => preflight_to_event(link::run_link_preflight(path).await),
        Effect::JoinAndLink { path, group_id, group_name, acknowledge_risks, on_demand } => {
            link_to_event(
                share::join_resolved(
                    group_id.clone(),
                    group_name.clone(),
                    std::path::PathBuf::from(path),
                    *on_demand,
                    *acknowledge_risks,
                )
                .await,
            )
        }
        // First-run: create the group and link the already-preflighted path
        // atomically. `create_and_link` deletes the group if the link fails, so
        // no phantom full replica is left behind.
        Effect::CreateAndLink { name, path, acknowledge_risks, on_demand } => {
            create_and_link_to_event(
                share::create_and_link(
                    name.clone(),
                    std::path::PathBuf::from(path),
                    *on_demand,
                    *acknowledge_risks,
                )
                .await,
            )
        }
    }
}

/// A fallback failure event routed to the phase the effect belongs to, used
/// when the effect can't even start (e.g. runtime construction failed).
fn effect_error_event(effect: &Effect, msg: String) -> Event {
    match effect {
        Effect::StartLogin => Event::SignInFailed(msg),
        Effect::RegisterDevice { .. } => Event::DeviceRegisterFailed(msg),
        Effect::ListGroups => Event::GroupsListFailed(msg),
        Effect::RunPreflight { .. } => Event::PreflightFailed(msg),
        Effect::JoinAndLink { .. } => Event::LinkFailed(msg),
        Effect::CreateAndLink { .. } => Event::LinkFailed(msg),
    }
}

fn login_to_event(result: Result<(), crate::google_login::LoginError>) -> Event {
    match result {
        // The loopback+PKCE flow stores the session in the keychain but does
        // not surface the account's email to this process, so the window shows
        // a generic signed-in label.
        Ok(()) => Event::SignInSucceeded { account: "Google account".to_string() },
        Err(e) => Event::SignInFailed(e.to_string()),
    }
}

fn register_to_event(result: Result<String, CliError>) -> Event {
    match result {
        Ok(_device_id) => Event::DeviceRegistered,
        Err(e) => Event::DeviceRegisterFailed(e.to_string()),
    }
}

fn create_and_link_to_event(result: Result<String, CliError>) -> Event {
    match result {
        Ok(group_id) => Event::CreateAndLinkSucceeded { group_id },
        // The group is deleted inside `create_and_link` before the error
        // returns, so a failure leaves no phantom — route it as a link failure.
        Err(e) => Event::LinkFailed(e.to_string()),
    }
}

fn list_groups_to_event(result: Result<Vec<share::GroupSummary>, CliError>) -> Event {
    match result {
        Ok(groups) => Event::GroupsListed(
            groups
                .into_iter()
                .map(|g| GroupOption { group_id: g.group_id, name: g.name })
                .collect(),
        ),
        Err(e) => Event::GroupsListFailed(e.to_string()),
    }
}

fn preflight_to_event(result: Result<(PathBuf, LinkPreflightReport), CliError>) -> Event {
    match result {
        Ok((path, report)) => Event::PreflightCompleted(preflight_to_view(path, &report)),
        Err(e) => Event::PreflightFailed(e.to_string()),
    }
}

fn link_to_event(result: Result<(), CliError>) -> Event {
    match result {
        Ok(()) => Event::LinkSucceeded,
        Err(e) => Event::LinkFailed(e.to_string()),
    }
}

/// Convert the shared preflight report into the machine's UI-facing view: the
/// factual summary lines the CLI prints as `preflight:` lines, plus the exact
/// `warnings` the CLI renders and the daemon enforces.
pub fn preflight_to_view(path: PathBuf, report: &LinkPreflightReport) -> PreflightView {
    let mut summary = Vec::new();
    if report.path_exists {
        summary.push(format!(
            "{} — {} entr{}{}{}",
            if report.is_empty_folder() { "empty folder" } else { "non-empty folder" },
            report.entry_count,
            if report.entry_count == 1 { "y" } else { "ies" },
            if report.ignored_entry_count > 0 {
                format!(", {} ignored", report.ignored_entry_count)
            } else {
                String::new()
            },
            if report.scan_truncated { ", scan capped" } else { "" },
        ));
        if let Some(space) = report.free_space {
            summary.push(format!(
                "{} free space on the target volume ({} bytes free)",
                space.classify().as_str(),
                space.available_bytes,
            ));
        }
    }
    PreflightView {
        resolved_path: path.to_string_lossy().to_string(),
        summary,
        warnings: report.warnings(),
        is_risky: report.is_risky(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_ok_maps_to_device_registered() {
        assert_eq!(register_to_event(Ok("dev-1".into())), Event::DeviceRegistered);
    }

    #[test]
    fn register_err_carries_the_message() {
        let ev = register_to_event(Err(CliError::NotLoggedIn));
        match ev {
            Event::DeviceRegisterFailed(msg) => assert!(msg.contains("not logged in")),
            other => panic!("expected DeviceRegisterFailed, got {other:?}"),
        }
    }

    #[test]
    fn create_and_link_ok_carries_group_id() {
        assert_eq!(
            create_and_link_to_event(Ok("g-42".into())),
            Event::CreateAndLinkSucceeded { group_id: "g-42".into() }
        );
    }

    #[test]
    fn list_groups_ok_maps_each_summary() {
        let groups = vec![
            share::GroupSummary { group_id: "g1".into(), name: "Photos".into() },
            share::GroupSummary { group_id: "g2".into(), name: "Docs".into() },
        ];
        assert_eq!(
            list_groups_to_event(Ok(groups)),
            Event::GroupsListed(vec![
                GroupOption { group_id: "g1".into(), name: "Photos".into() },
                GroupOption { group_id: "g2".into(), name: "Docs".into() },
            ])
        );
    }

    #[test]
    fn link_ok_maps_to_link_succeeded() {
        assert_eq!(link_to_event(Ok(())), Event::LinkSucceeded);
    }

    /// The report→view conversion carries every warning through verbatim
    /// (the window's acknowledgement cards are exactly the CLI's warnings)
    /// and reflects the report's own risk verdict.
    #[test]
    fn preflight_view_carries_warnings_and_risk_from_a_real_report() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("existing.txt"), b"x").unwrap();
        // Some(0) disables the free-space headroom check so this test's verdict
        // is driven purely by the non-empty-folder condition, not the host's
        // disk state.
        let report = yadorilink_sync_core::link_preflight::run_preflight(dir.path(), &[], Some(0));
        let view = preflight_to_view(dir.path().to_path_buf(), &report);

        assert!(view.is_risky);
        assert_eq!(view.warnings, report.warnings());
        assert!(view.warnings.iter().any(|w| w.contains("not empty")));
        assert!(view.summary.iter().any(|s| s.contains("non-empty folder")));
        assert_eq!(view.resolved_path, dir.path().to_string_lossy());
    }

    #[test]
    fn preflight_view_of_an_empty_folder_has_no_non_empty_warning() {
        let dir = tempfile::tempdir().unwrap();
        let report = yadorilink_sync_core::link_preflight::run_preflight(dir.path(), &[], Some(0));
        let view = preflight_to_view(dir.path().to_path_buf(), &report);
        assert!(!view.warnings.iter().any(|w| w.contains("not empty")));
        assert!(view.summary.iter().any(|s| s.contains("empty folder")));
    }
}

//! The effect executor. It runs each
//! [`Effect`] the machine emits off the UI thread on a short-lived tokio
//! runtime (the same threading pattern `main.rs`'s `handle_menu_event` uses
//! for its mutating actions), maps the `yadorilink_client_core` result to an
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

use yadorilink_client_core::ops::{auth, devices as device, links as link, shares as share};
use yadorilink_client_core::CoreError;
use yadorilink_local_storage::link_preflight::LinkPreflightReport;

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

/// Perform the effect's underlying client-layer call and map its result to
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
            // Always the loopback (non-device) flow: the desktop app's own
            // browser is co-located with this process by construction, so
            // the cross-machine loopback-reachability problem `--device`
            // exists for cannot occur here.
            //
            // Each step is written to stdout exactly as `yadorilink login`
            // prints it, which is where this window's sign-in has always
            // reported the pages to open.
            let print_progress = |event| {
                for line in yadorilink_client_core::wording::login_event_lines(&event) {
                    println!("{line}");
                }
            };
            match tokio::time::timeout(SIGN_IN_TIMEOUT, auth::login(false, print_progress)).await {
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

fn login_to_event(result: Result<(), CoreError>) -> Event {
    match result {
        // Enrolment stores a credential but does not surface the account's
        // email to this process, so the window shows a generic signed-in label.
        Ok(()) => Event::SignInSucceeded { account: "YadoriLink account".to_string() },
        Err(e) => Event::SignInFailed(e.to_string()),
    }
}

fn register_to_event(result: Result<String, CoreError>) -> Event {
    match result {
        Ok(_device_id) => Event::DeviceRegistered,
        Err(e) => Event::DeviceRegisterFailed(e.to_string()),
    }
}

fn create_and_link_to_event(result: Result<String, CoreError>) -> Event {
    match result {
        Ok(group_id) => Event::CreateAndLinkSucceeded { group_id },
        // The group is deleted inside `create_and_link` before the error
        // returns, so a failure leaves no phantom — route it as a link failure.
        Err(e) => Event::LinkFailed(e.to_string()),
    }
}

fn list_groups_to_event(result: Result<Vec<share::GroupSummary>, CoreError>) -> Event {
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

fn preflight_to_event(result: Result<(PathBuf, LinkPreflightReport), CoreError>) -> Event {
    match result {
        Ok((path, report)) => Event::PreflightCompleted(preflight_to_view(path, &report)),
        Err(e) => Event::PreflightFailed(e.to_string()),
    }
}

fn link_to_event(result: Result<(), CoreError>) -> Event {
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
mod tests;

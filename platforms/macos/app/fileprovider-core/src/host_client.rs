//! The host app's ONE persistent connection to the daemon: it reports the domain state and the
//! materialized set, answers the daemon's evict and signal requests, runs the Eager download query
//! and relays prefetch hints. Everything crosses as JSON (bytes as lowercase hex): commands from
//! Swift become shell IPC messages; every message the daemon pushes or answers becomes one event
//! handed to the callback. The first command that names a root (`domain_state`) makes this the
//! daemon's attached host connection. A closed or failed connection ends with a `closed` event and
//! the host reconnects with a fresh reporter epoch.

use std::ffi::{c_char, c_void, CString};

use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use yadorilink_ipc_proto::framing::{read_message, write_message};
use yadorilink_ipc_proto::shellipc::shell_ipc_message::Payload;
use yadorilink_ipc_proto::shellipc::{
    ActivityKind, DomainEvidence, EvictResult, ListProviderFoldersRequest,
    NextProviderDownloadsRequest, PrefetchResult, ProviderActivity, ProviderDomainState,
    ProviderDownloadRejected, ProviderEvictDone, ProviderMaterializedItem,
    ProviderMaterializedReport, ProviderPrefetchDone, ProviderSignalDone, ShellIpcMessage,
};

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn bytes(v: &Value, key: &str) -> Option<Vec<u8>> {
    match v.get(key) {
        None | Some(Value::Null) => Some(Vec::new()),
        Some(Value::String(s)) => unhex(s),
        _ => None,
    }
}

fn hex_list(v: &Value, key: &str) -> Option<Vec<Vec<u8>>> {
    match v.get(key) {
        None | Some(Value::Null) => Some(Vec::new()),
        Some(Value::Array(items)) => items.iter().map(|i| unhex(i.as_str()?)).collect(),
        _ => None,
    }
}

fn num(v: &Value, key: &str) -> u64 {
    v.get(key).and_then(Value::as_u64).unwrap_or(0)
}

/// One command from Swift as the message to send. `None` for anything malformed.
pub(crate) fn message_of(command: &Value) -> Option<ShellIpcMessage> {
    let payload = match command.get("cmd")?.as_str()? {
        "domain_state" => Payload::ProviderDomainState(ProviderDomainState {
            root_id: bytes(command, "root")?,
            preserved_location: command
                .get("preserved_location")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            evidence: match command.get("evidence").and_then(Value::as_str) {
                Some("registered") => DomainEvidence::Registered,
                Some("orphan") => DomainEvidence::Orphan,
                Some("not_registered") => DomainEvidence::NotRegistered,
                Some("removed") => DomainEvidence::Removed,
                // Anything else, including a missing field, is not evidence of anything.
                _ => DomainEvidence::Unknown,
            } as i32,
            last_acked_namespace_revision: num(command, "last_acked"),
        }),
        "report" => Payload::ProviderMaterializedReport(ProviderMaterializedReport {
            root_id: bytes(command, "root")?,
            reporter_epoch: num(command, "epoch"),
            report_seq: num(command, "seq"),
            full: command.get("full").and_then(Value::as_bool).unwrap_or(false),
            observed_after_seq: num(command, "observed_after"),
            upserts: hex_list(command, "upserts")?
                .into_iter()
                .map(|item_id| ProviderMaterializedItem { item_id })
                .collect(),
            removed: hex_list(command, "removed")?,
            more: command.get("more").and_then(Value::as_bool).unwrap_or(false),
        }),
        "evict_done" => Payload::ProviderEvictDone(ProviderEvictDone {
            root_id: bytes(command, "root")?,
            request_id: bytes(command, "request_id")?,
            result: match command.get("result").and_then(Value::as_str)? {
                "evicted" => EvictResult::Evicted,
                "not_materialized" => EvictResult::NotMaterialized,
                "busy" => EvictResult::Busy,
                _ => EvictResult::Error,
            } as i32,
            error: command.get("error").and_then(Value::as_str).unwrap_or("").to_owned(),
        }),
        "signal_done" => Payload::ProviderSignalDone(ProviderSignalDone {
            root_id: bytes(command, "root")?,
            namespace_revision: num(command, "revision"),
            ok: command.get("ok").and_then(Value::as_bool).unwrap_or(false),
            error: command.get("error").and_then(Value::as_str).unwrap_or("").to_owned(),
            request_id: bytes(command, "request_id").unwrap_or_default(),
        }),
        "download_rejected" => Payload::ProviderDownloadRejected(ProviderDownloadRejected {
            root_id: bytes(command, "root")?,
            item_id: bytes(command, "item")?,
            error: command.get("error").and_then(Value::as_str).unwrap_or("").to_owned(),
        }),
        "prefetch_done" => Payload::ProviderPrefetchDone(ProviderPrefetchDone {
            root_id: bytes(command, "root")?,
            hint_id: num(command, "hint_id"),
            folder_item_id: bytes(command, "folder")?,
            result: match command.get("result").and_then(Value::as_str)? {
                "done" => PrefetchResult::Done,
                "skipped" => PrefetchResult::Skipped,
                _ => PrefetchResult::Failed,
            } as i32,
        }),
        "activity" => Payload::ProviderActivity(ProviderActivity {
            root_id: bytes(command, "root")?,
            item_id: bytes(command, "item")?,
            activity_kind: match command.get("kind").and_then(Value::as_str)? {
                "enumerate" => ActivityKind::Enumerate,
                "fetch" => ActivityKind::Fetch,
                _ => return None,
            } as i32,
        }),
        "next_downloads" => Payload::NextProviderDownloadsRequest(NextProviderDownloadsRequest {
            root_id: bytes(command, "root")?,
            exclude_item_ids: hex_list(command, "exclude")?,
            max: num(command, "max") as u32,
        }),
        "list_folders" => Payload::ListProviderFoldersRequest(ListProviderFoldersRequest {
            app_group_container: command
                .get("app_group_container")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        }),
        _ => return None,
    };
    Some(ShellIpcMessage { payload: Some(payload) })
}

/// One message from the daemon as the event handed to Swift; `None` for a message the host ignores.
pub(crate) fn event_of(payload: Payload) -> Option<Value> {
    Some(match payload {
        Payload::ProviderEvictRequest(r) => json!({
            "event": "evict", "root": hex(&r.root_id), "item": hex(&r.item_id),
            "request_id": hex(&r.request_id), "target": hex(&r.target_version_hash),
        }),
        Payload::ProviderChanged(r) => json!({
            "event": "changed", "root": hex(&r.root_id), "revision": r.namespace_revision,
            "items": r.changed_item_ids.iter().map(|b| hex(b)).collect::<Vec<_>>(),
            "parents": r.changed_parent_ids.iter().map(|b| hex(b)).collect::<Vec<_>>(),
            "working_set": r.signal_working_set,
            "request_id": hex(&r.request_id),
        }),
        Payload::ProviderEvidenceTick(r) => {
            json!({ "event": "evidence_tick", "root": hex(&r.root_id), "seq": r.evidence_seq })
        }
        Payload::ProviderReportAck(r) => json!({
            "event": "report_ack", "root": hex(&r.root_id), "epoch": r.reporter_epoch,
            "accepted_seq": r.accepted_seq, "needs_full": r.needs_full,
        }),
        Payload::ProviderPrefetchHint(r) => json!({
            "event": "prefetch_hint", "root": hex(&r.root_id), "hint_id": r.hint_id,
            "folders": r.folder_item_ids.iter().map(|b| hex(b)).collect::<Vec<_>>(),
        }),
        Payload::ProviderPrefetchControl(r) => {
            json!({ "event": "prefetch_control", "root": hex(&r.root_id), "paused": r.paused })
        }
        Payload::NextProviderDownloadsResponse(r) => json!({
            "event": "downloads",
            "downloads": r.downloads.iter()
                .map(|d| json!({ "item": hex(&d.item_id), "version": hex(&d.version_hash) }))
                .collect::<Vec<_>>(),
            "settled": r.settled_item_ids.iter().map(|b| hex(b)).collect::<Vec<_>>(),
            "state": r.state,
        }),
        Payload::ListProviderFoldersResponse(r) => json!({
            "event": "folders", "snapshot_available": r.snapshot_available,
            "folders": r.folders.iter().map(|f| json!({
                "root": hex(&f.root_id), "display_name": f.display_name,
                "hydration_policy": f.hydration_policy, "ready": f.registration_ready,
                "latest_evidence_seq": f.latest_evidence_seq,
            })).collect::<Vec<_>>(),
            "removals": r.removals.iter().map(|d| json!({
                "root": hex(&d.root_id), "display_name": d.display_name,
            })).collect::<Vec<_>>(),
        }),
        _ => return None,
    })
}

/// Runs the connection over `stream` until it ends: commands from `commands` go out in order,
/// events go to `on_event`; a final `closed` event ends it.
pub(crate) async fn run_over<S>(
    stream: S,
    mut commands: mpsc::UnboundedReceiver<Value>,
    on_event: impl Fn(Value),
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    // Two independent loops (a read is never cancelled half-way): the connection ends when either
    // ends, a closed command channel or a failed write on one side, EOF or an error on the other.
    let writing = async {
        while let Some(command) = commands.recv().await {
            let Some(message) = message_of(&command) else { continue };
            if write_message(&mut writer, &message).await.is_err() {
                break;
            }
        }
    };
    let reading = async {
        loop {
            match read_message::<ShellIpcMessage>(&mut reader).await {
                Ok(Some(ShellIpcMessage { payload: Some(payload) })) => {
                    if let Some(event) = event_of(payload) {
                        on_event(event);
                    }
                }
                Ok(Some(_)) => {}
                _ => break,
            }
        }
    };
    tokio::select! {
        () = writing => {}
        () = reading => {}
    }
    on_event(json!({ "event": "closed" }));
}

/// A handle Swift holds: commands go in, events come out through the callback.
pub struct Host {
    commands: mpsc::UnboundedSender<Value>,
}

/// The callback's context pointer is the caller's: it is only passed back, never dereferenced.
struct Context(*mut c_void);
// SAFETY: the pointer is opaque to this crate and handed back verbatim on the host's own thread;
// the caller guarantees it is usable from any thread (a retained Swift object reference).
unsafe impl Send for Context {}

pub type EventCallback = extern "C" fn(*const c_char, *mut c_void);

impl Host {
    /// Connects and starts the connection's thread. `None` when the daemon cannot be reached.
    pub fn open(callback: EventCallback, context: *mut c_void) -> Option<Host> {
        let (commands, receiver) = mpsc::unbounded_channel();
        let context = Context(context);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("yadorilink-provider-host".into())
            .spawn(move || {
                let Ok(runtime) =
                    tokio::runtime::Builder::new_current_thread().enable_all().build()
                else {
                    let _ = ready_tx.send(false);
                    return;
                };
                runtime.block_on(async move {
                    let Ok(stream) = crate::ipc_client::connect().await else {
                        let _ = ready_tx.send(false);
                        return;
                    };
                    let _ = ready_tx.send(true);
                    let context = context;
                    run_over(stream, receiver, |event| {
                        if let Ok(text) = CString::new(event.to_string()) {
                            callback(text.as_ptr(), context.0);
                        }
                    })
                    .await;
                });
            })
            .ok()?;
        ready_rx.recv().ok()?.then_some(Host { commands })
    }

    /// Queues one command; `false` when the connection already ended or the command is malformed.
    pub fn send(&self, command_json: &str) -> bool {
        let Ok(command) = serde_json::from_str::<Value>(command_json) else { return false };
        if message_of(&command).is_none() {
            return false;
        }
        self.commands.send(command).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    async fn fake_daemon(
        mut server: tokio::io::DuplexStream,
        replies: Vec<Payload>,
    ) -> Vec<ShellIpcMessage> {
        let mut seen = Vec::new();
        for reply in replies {
            let message: ShellIpcMessage = read_message(&mut server).await.unwrap().unwrap();
            seen.push(message);
            write_message(&mut server, &ShellIpcMessage { payload: Some(reply) }).await.unwrap();
        }
        seen
    }

    /// Commands reach the daemon as the messages the protocol defines, and the daemon's answers and
    /// pushes come back as events with their hex ids; a closed stream ends with `closed`.
    #[tokio::test]
    async fn commands_become_messages_and_messages_become_events() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let (tx, rx) = mpsc::unbounded_channel();
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = events.clone();
        let daemon = tokio::spawn(fake_daemon(
            server,
            vec![
                Payload::ProviderReportAck(yadorilink_ipc_proto::shellipc::ProviderReportAck {
                    root_id: vec![9; 16],
                    reporter_epoch: 4,
                    accepted_seq: 1,
                    needs_full: false,
                }),
                Payload::NextProviderDownloadsResponse(
                    yadorilink_ipc_proto::shellipc::NextProviderDownloadsResponse {
                        downloads: vec![yadorilink_ipc_proto::shellipc::ProviderDownload {
                            item_id: vec![5; 16],
                            version_hash: vec![6; 32],
                        }],
                        settled_item_ids: vec![vec![7; 16]],
                        state: 1,
                    },
                ),
            ],
        ));
        let host =
            tokio::spawn(run_over(client, rx, move |event| sink.lock().unwrap().push(event)));
        tx.send(json!({"cmd":"report","root":hex(&[9;16]),"epoch":4,"seq":1,"full":true,
                       "observed_after":3,"upserts":[hex(&[1;16])],"more":false}))
            .unwrap();
        tx.send(
            json!({"cmd":"next_downloads","root":hex(&[9;16]),"exclude":[hex(&[7;16])],"max":2}),
        )
        .unwrap();
        let seen = daemon.await.unwrap();
        let Some(Payload::ProviderMaterializedReport(report)) = &seen[0].payload else { panic!() };
        assert!(report.full && report.report_seq == 1 && report.upserts[0].item_id == vec![1; 16]);
        let Some(Payload::NextProviderDownloadsRequest(next)) = &seen[1].payload else { panic!() };
        assert_eq!((next.max, next.exclude_item_ids.clone()), (2, vec![vec![7; 16]]));
        host.await.unwrap();
        let events = events.lock().unwrap();
        assert_eq!(events[0]["event"], "report_ack");
        assert_eq!(events[1]["downloads"][0]["item"], hex(&[5; 16]));
        assert_eq!(events[1]["settled"][0], hex(&[7; 16]));
        assert_eq!(events.last().unwrap()["event"], "closed");
    }

    /// A malformed command is refused before it is queued, never sent half-formed.
    #[test]
    fn malformed_commands_are_not_messages() {
        assert!(message_of(&json!({"cmd":"report","root":"zz"})).is_none());
        assert!(message_of(&json!({"cmd":"nope"})).is_none());
        assert!(message_of(&json!({"cmd":"activity","root":"00","item":"","kind":"x"})).is_none());
        assert!(message_of(
            &json!({"cmd":"evict_done","root":"01","request_id":"02","result":"busy"})
        )
        .is_some());
    }

    /// Daemon pushes the host acts on become events.
    #[test]
    fn pushes_become_events() {
        use yadorilink_ipc_proto::shellipc::{ProviderChanged, ProviderEvictRequest};
        let evict = event_of(Payload::ProviderEvictRequest(ProviderEvictRequest {
            root_id: vec![1],
            item_id: vec![2],
            request_id: vec![3],
            target_version_hash: vec![4],
        }))
        .unwrap();
        assert_eq!(evict["event"], "evict");
        assert_eq!(evict["request_id"], "03");
        let changed = event_of(Payload::ProviderChanged(ProviderChanged {
            root_id: vec![1],
            namespace_revision: 8,
            changed_item_ids: vec![vec![2]],
            changed_parent_ids: vec![vec![]],
            signal_working_set: true,
            request_id: vec![9],
        }))
        .unwrap();
        assert_eq!(
            (changed["revision"].as_u64(), changed["working_set"].as_bool()),
            (Some(8), Some(true))
        );
        // The correlation id crosses to Swift and back unchanged.
        assert_eq!(changed["request_id"], "09");
        let done = message_of(&json!({"cmd":"signal_done","root":"01","revision":8,"ok":true,"request_id":"09"})).unwrap();
        let Some(Payload::ProviderSignalDone(done)) = done.payload else { panic!() };
        assert_eq!(done.request_id, vec![9]);
    }
}

//! The provider-root protocol for the File Provider extension: one JSON request in, one JSON
//! response out, over one short-lived connection (handshake first, then the request).
//!
//! The daemon's version identifiers are 40-byte tokens (32-byte content hash, then the item
//! generation, big endian). This module never builds, splits or combines them: a token received in
//! an item or a materialize response is passed to Swift as an opaque hex string, and a base token
//! handed back by Swift is sent verbatim as `base_version_hash`. The Swift side stores a token
//! atomically with the bytes and view it names.
//!
//! Every byte string crosses as lowercase hex. A transport failure (unreachable daemon, timeout, a
//! malformed or unexpected reply) is `None`, never an empty success.

use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncWrite};
use yadorilink_ipc_proto::framing::{read_message, write_message};
use yadorilink_ipc_proto::shellipc::shell_ipc_message::Payload;
use yadorilink_ipc_proto::shellipc::{
    ActivityKind, ChangeScope, EntryKind, EnumerateChangesRequest, EnumerateChildrenRequest,
    EnumerateWorkingSetRequest, ExtensionHandshake, MaterializeToTempRequest, ProviderActivity,
    ProviderApplyChangeRequest, ProviderChangeKind, ProviderContentSource, ProviderItem,
    ProviderItemMetadata, ProviderItemRequest, ShellIpcMessage,
};

use crate::ipc_client::{connect, runtime};

const ENUMERATE_TIMEOUT: Duration = Duration::from_secs(10);
const APPLY_TIMEOUT: Duration = Duration::from_secs(60);
const MATERIALIZE_TIMEOUT: Duration = Duration::from_secs(40);
const EXTENSION_BUILD: &str = "1";

/// Runs one request. `None` on any transport failure.
pub fn call(request_json: &str) -> Option<String> {
    let request: Value = serde_json::from_str(request_json).ok()?;
    let timeout = match request.get("op")?.as_str()? {
        "apply" => APPLY_TIMEOUT,
        "materialize" => MATERIALIZE_TIMEOUT,
        _ => ENUMERATE_TIMEOUT,
    };
    let response = runtime().block_on(async {
        tokio::time::timeout(timeout, async {
            let mut stream = connect().await.ok()?;
            call_over(&mut stream, &request).await
        })
        .await
        .ok()?
    })?;
    serde_json::to_string(&response).ok()
}

pub(crate) async fn call_over<S>(stream: &mut S, request: &Value) -> Option<Value>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let root = bytes(request, "root")?;
    write_message(
        stream,
        &ShellIpcMessage {
            payload: Some(Payload::ExtensionHandshake(ExtensionHandshake {
                root_id: root.clone(),
                extension_build: EXTENSION_BUILD.into(),
            })),
        },
    )
    .await
    .ok()?;
    let payload = build(request, root)?;
    write_message(stream, &ShellIpcMessage { payload: Some(payload) }).await.ok()?;
    // Activity is a notification: the daemon answers nothing.
    if request.get("op").and_then(Value::as_str) == Some("activity") {
        return Some(json!({ "ok": true }));
    }
    match read_message::<ShellIpcMessage>(stream).await {
        Ok(Some(ShellIpcMessage { payload: Some(reply) })) => render(reply),
        _ => None,
    }
}

fn bytes(v: &Value, key: &str) -> Option<Vec<u8>> {
    match v.get(key) {
        None | Some(Value::Null) => Some(Vec::new()),
        Some(Value::String(s)) => unhex(s),
        _ => None,
    }
}

fn opt_bytes(v: &Value, key: &str) -> Option<Option<Vec<u8>>> {
    match v.get(key) {
        None | Some(Value::Null) => Some(None),
        Some(Value::String(s)) => Some(Some(unhex(s)?)),
        _ => None,
    }
}

fn num(v: &Value, key: &str) -> Option<u64> {
    v.get(key).and_then(Value::as_u64)
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn build(r: &Value, root: Vec<u8>) -> Option<Payload> {
    Some(match r.get("op")?.as_str()? {
        "children" => Payload::EnumerateChildrenRequest(EnumerateChildrenRequest {
            root_id: root,
            parent_item_id: bytes(r, "parent")?,
            page_token: bytes(r, "page_token")?,
            limit: num(r, "limit").unwrap_or(0) as u32,
        }),
        "item" => Payload::ProviderItemRequest(ProviderItemRequest {
            root_id: root,
            item_id: bytes(r, "item")?,
        }),
        "changes" => Payload::EnumerateChangesRequest(EnumerateChangesRequest {
            root_id: root,
            scope: match r.get("scope")?.as_str()? {
                "working_set" => ChangeScope::WorkingSet,
                "container" => ChangeScope::Container,
                _ => return None,
            } as i32,
            parent_item_id: bytes(r, "parent")?,
            since_anchor: num(r, "since")?,
            limit: num(r, "limit").unwrap_or(0) as u32,
        }),
        "working_set" => Payload::EnumerateWorkingSetRequest(EnumerateWorkingSetRequest {
            root_id: root,
            page_token: bytes(r, "page_token")?,
            limit: num(r, "limit").unwrap_or(0) as u32,
        }),
        "materialize" => Payload::MaterializeToTempRequest(MaterializeToTempRequest {
            request_id: bytes(r, "request_id")?,
            root_id: root,
            item_id: bytes(r, "item")?,
            requested_version_hash: bytes(r, "requested_hash")?,
        }),
        "apply" => Payload::ProviderApplyChangeRequest(build_apply(r, root)?),
        "activity" => Payload::ProviderActivity(ProviderActivity {
            root_id: root,
            item_id: bytes(r, "item")?,
            activity_kind: match r.get("kind")?.as_str()? {
                "enumerate" => ActivityKind::Enumerate,
                "fetch" => ActivityKind::Fetch,
                _ => return None,
            } as i32,
        }),
        _ => return None,
    })
}

fn build_apply(r: &Value, root: Vec<u8>) -> Option<ProviderApplyChangeRequest> {
    let kind = match r.get("kind")?.as_str()? {
        "create" => ProviderChangeKind::Create,
        "modify" => ProviderChangeKind::Modify,
        "delete" => ProviderChangeKind::Delete,
        _ => return None,
    };
    let entry_kind = match r.get("entry_kind").and_then(Value::as_str).unwrap_or("file") {
        "file" => EntryKind::File,
        "directory" => EntryKind::Directory,
        "symlink" => EntryKind::Symlink,
        _ => return None,
    };
    let content = match r.get("content") {
        Some(c) if !c.is_null() => Some(ProviderContentSource {
            ingest_name: c.get("ingest_name")?.as_str()?.to_owned(),
            size: num(c, "size")?,
            sha256: bytes(c, "sha256")?,
        }),
        _ => None,
    };
    let metadata = r.get("metadata").filter(|m| !m.is_null()).map(|m| ProviderItemMetadata {
        unix_mode: num(m, "unix_mode").map(|x| x as u32),
        mtime_unix_nanos: m.get("mtime_unix_nanos").and_then(Value::as_i64),
        replace_xattrs: false,
        xattrs: Vec::new(),
    });
    Some(ProviderApplyChangeRequest {
        request_id: bytes(r, "request_id")?,
        session_id: bytes(r, "session")?,
        operation_seq: num(r, "seq")?,
        root_id: root,
        kind: kind as i32,
        item_id: bytes(r, "item")?,
        parent_item_id: opt_bytes(r, "parent")?,
        name: r.get("name").and_then(Value::as_str).map(str::to_owned),
        entry_kind: entry_kind as i32,
        // The base token, verbatim as the daemon issued it (or empty: none).
        base_version_hash: bytes(r, "base")?,
        content,
        symlink_target: bytes(r, "symlink_target")?,
        metadata,
        recursive: r.get("recursive").and_then(Value::as_bool).unwrap_or(false),
        base_generation: None,
        parent_generation: num(r, "parent_generation"),
        observed_revision: num(r, "observed_revision"),
    })
}

fn item_json(i: &ProviderItem) -> Value {
    json!({
        "item_id": hex(&i.item_id),
        "parent_item_id": hex(&i.parent_item_id),
        "name": i.name,
        "entry_kind": entry_kind_str(i.entry_kind),
        "size": i.size,
        "mtime_unix_nanos": i.mtime_unix_nanos,
        "unix_mode": i.unix_mode,
        "content_version": hex(&i.content_version),
        "metadata_version": hex(&i.metadata_version),
        "content_pending": i.content_pending,
        "symlink_target": hex(&i.symlink_target),
        "parent_generation": i.parent_generation,
        "read_only": i.read_only,
    })
}

fn entry_kind_str(kind: i32) -> &'static str {
    match EntryKind::try_from(kind) {
        Ok(EntryKind::File) => "file",
        Ok(EntryKind::Directory) => "directory",
        Ok(EntryKind::Symlink) => "symlink",
        _ => "unspecified",
    }
}

fn render(reply: Payload) -> Option<Value> {
    Some(match reply {
        Payload::EnumerateChildrenResponse(r) => json!({
            "ok": r.ok, "failure": r.failure, "error": r.error,
            "items": r.items.iter().map(item_json).collect::<Vec<_>>(),
            "next_page_token": hex(&r.next_page_token), "anchor": r.anchor,
        }),
        Payload::ProviderItemResponse(r) => json!({
            "ok": r.ok, "failure": r.failure, "error": r.error,
            "item": r.item.as_ref().map(item_json), "anchor": r.anchor,
        }),
        Payload::EnumerateChangesResponse(r) => json!({
            "ok": r.ok, "failure": r.failure, "error": r.error,
            "upserts": r.upserts.iter().map(item_json).collect::<Vec<_>>(),
            "removed_item_ids": r.removed_item_ids.iter().map(|b| hex(b)).collect::<Vec<_>>(),
            "next_anchor": r.next_anchor, "more": r.more,
        }),
        Payload::EnumerateWorkingSetResponse(r) => json!({
            "ok": r.ok, "failure": r.failure, "error": r.error,
            "items": r.items.iter().map(item_json).collect::<Vec<_>>(),
            "next_page_token": hex(&r.next_page_token), "anchor": r.anchor,
        }),
        Payload::MaterializeToTempResponse(r) => json!({
            "ok": r.ok, "failure": r.failure, "error": r.error,
            "handoff_name": r.handoff_name, "size": r.size,
            // The token these bytes are paired with.
            "content_version": hex(&r.content_version),
        }),
        Payload::ProviderApplyChangeResponse(r) => json!({
            "ok": r.ok, "failure": r.failure, "error": r.error, "outcome": r.outcome,
            "replayed": r.replayed,
            "request_id": hex(&r.request_id), "suggested_name": r.suggested_name,
            "item": r.item.as_ref().map(|i| json!({
                "item_id": hex(&i.item_id), "parent_item_id": hex(&i.parent_item_id),
                "name": i.name, "entry_kind": entry_kind_str(i.entry_kind), "size": i.size,
                "mtime_unix_nanos": i.mtime_unix_nanos, "unix_mode": i.unix_mode,
                "content_version": hex(&i.content_version),
                "metadata_version": hex(&i.metadata_version),
                "current": i.current, "namespace_revision": i.namespace_revision,
                "parent_generation": i.parent_generation,
            })),
        }),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use yadorilink_ipc_proto::shellipc::{ProviderAppliedItem, ProviderApplyChangeResponse};

    /// Runs `request` against a fake daemon that checks the handshake and returns `reply`.
    async fn run(request: Value, reply: Payload) -> (Option<Value>, ShellIpcMessage) {
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        let daemon = tokio::spawn(async move {
            let hello: ShellIpcMessage = read_message(&mut server).await.unwrap().unwrap();
            assert!(matches!(hello.payload, Some(Payload::ExtensionHandshake(_))));
            let seen: ShellIpcMessage = read_message(&mut server).await.unwrap().unwrap();
            write_message(&mut server, &ShellIpcMessage { payload: Some(reply) }).await.unwrap();
            seen
        });
        let out = call_over(&mut client, &request).await;
        (out, daemon.await.unwrap())
    }

    fn token(byte: u8, generation: u64) -> Vec<u8> {
        let mut t = vec![byte; 32];
        t.extend_from_slice(&generation.to_be_bytes());
        t
    }

    /// The base token reaches the daemon exactly as Swift gave it, and the applied item's new
    /// token reaches Swift exactly as the daemon issued it.
    #[tokio::test]
    async fn a_modify_sends_the_base_token_verbatim_and_returns_the_next_token() {
        let base = token(7, 3);
        let next = token(8, 4);
        let reply = Payload::ProviderApplyChangeResponse(ProviderApplyChangeResponse {
            ok: true,
            item: Some(ProviderAppliedItem {
                item_id: vec![1; 16],
                content_version: next.clone(),
                ..Default::default()
            }),
            ..Default::default()
        });
        let (out, seen) = run(
            json!({"op":"apply","root":hex(&[9;16]),"kind":"modify","item":hex(&[1;16]),
                   "base":hex(&base),"session":hex(&[2;16]),"seq":5,"request_id":hex(&[3;4]),
                   "content":{"ingest_name":"c1","size":4,"sha256":hex(&[4;32])}}),
            reply,
        )
        .await;
        let Some(Payload::ProviderApplyChangeRequest(sent)) = seen.payload else { panic!() };
        assert_eq!(sent.base_version_hash, base);
        assert_eq!(sent.base_generation, None, "the generation lives inside the token only");
        assert_eq!(sent.kind, ProviderChangeKind::Modify as i32);
        let out = out.unwrap();
        assert_eq!(out["item"]["content_version"], hex(&next));
    }

    /// A delete carries the base token and no bytes; an absent base stays absent.
    #[tokio::test]
    async fn a_delete_without_a_base_sends_none() {
        let reply = Payload::ProviderApplyChangeResponse(ProviderApplyChangeResponse {
            ok: true,
            ..Default::default()
        });
        let (_, seen) = run(
            json!({"op":"apply","root":hex(&[9;16]),"kind":"delete","item":hex(&[1;16]),
                   "session":hex(&[2;16]),"seq":6,"request_id":hex(&[3;4])}),
            reply,
        )
        .await;
        let Some(Payload::ProviderApplyChangeRequest(sent)) = seen.payload else { panic!() };
        assert!(sent.base_version_hash.is_empty());
        assert!(sent.content.is_none());
    }

    /// A reply of another type, a malformed request and bad hex are transport failures, not
    /// empty successes.
    #[tokio::test]
    async fn malformed_input_and_foreign_replies_are_failures() {
        let wrong = Payload::ProviderApplyChangeResponse(ProviderApplyChangeResponse::default());
        let (out, _) = run(json!({"op":"children","root":hex(&[9;16])}), wrong).await;
        assert!(out.is_some(), "a children reply of the apply type is rendered, not trusted");
        assert!(unhex("abc").is_none());
        assert!(unhex("zz").is_none());
        assert!(build(&json!({"op":"nope"}), vec![]).is_none());
    }

    /// An activity notification is written and nothing is read back.
    #[tokio::test]
    async fn an_activity_notification_is_sent_and_not_awaited() {
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        let daemon = tokio::spawn(async move {
            let _hello: ShellIpcMessage = read_message(&mut server).await.unwrap().unwrap();
            let seen: ShellIpcMessage = read_message(&mut server).await.unwrap().unwrap();
            seen
        });
        let out = call_over(
            &mut client,
            &json!({"op":"activity","root":hex(&[9;16]),"item":hex(&[1;16]),"kind":"fetch"}),
        )
        .await;
        assert_eq!(out.unwrap()["ok"], true);
        let Some(Payload::ProviderActivity(a)) = daemon.await.unwrap().payload else { panic!() };
        assert_eq!((a.item_id, a.activity_kind), (vec![1; 16], ActivityKind::Fetch as i32));
    }
}

//! Typed requests of the provider-root protocol, each over one short-lived connection: the
//! extension handshake for the root first, then the request, then the matching response (other
//! messages the daemon may push on the connection, such as status updates, are skipped).
//!
//! A transport failure (unreachable daemon, timeout, a closed connection) is `None`, never an
//! empty success: a caller that reconciles the local namespace against an answer must not read
//! "could not ask" as "nothing there".

use std::sync::OnceLock;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::runtime::Runtime;
use yadorilink_ipc_proto::framing::{read_message, write_message};
use yadorilink_ipc_proto::shellipc::shell_ipc_message::Payload;
use yadorilink_ipc_proto::shellipc::{
    ActivityKind, EnumerateChildrenRequest, ExtensionHandshake, MaterializeToTempRequest,
    MaterializeToTempResponse, ProviderActivity, ProviderApplyChangeRequest,
    ProviderApplyChangeResponse, ProviderItem, ShellIpcMessage,
};

const ENUMERATE_TIMEOUT: Duration = Duration::from_secs(10);
const MATERIALIZE_TIMEOUT: Duration = Duration::from_secs(40);
const APPLY_TIMEOUT: Duration = Duration::from_secs(60);
const EXTENSION_BUILD: &str = "1";
/// Children per enumeration page.
const PAGE_LIMIT: u32 = 500;
/// A folder never has more pages than this; a daemon that keeps returning page tokens is broken.
const MAX_PAGES: usize = 100_000;

/// The runtime blocking callers (the host's loop and the Cloud Files callbacks, which run on
/// operating-system threads at the same time) drive their requests on.
pub(crate) fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("failed to start the provider client runtime")
    })
}

/// Sends the handshake for `root` and `request`, then reads until `pick` accepts a message.
pub(crate) async fn exchange<S, T>(
    stream: &mut S,
    root: &[u8],
    request: Payload,
    pick: impl Fn(Payload) -> Option<T>,
) -> Option<T>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let handshake = Payload::ExtensionHandshake(ExtensionHandshake {
        root_id: root.to_vec(),
        extension_build: EXTENSION_BUILD.into(),
    });
    write_message(stream, &ShellIpcMessage { payload: Some(handshake) }).await.ok()?;
    write_message(stream, &ShellIpcMessage { payload: Some(request) }).await.ok()?;
    loop {
        match read_message::<ShellIpcMessage>(stream).await {
            Ok(Some(ShellIpcMessage { payload: Some(payload) })) => {
                if let Some(answer) = pick(payload) {
                    return Some(answer);
                }
            }
            Ok(Some(_)) => {}
            _ => return None,
        }
    }
}

fn call<T>(
    timeout: Duration,
    root: &[u8],
    request: Payload,
    pick: impl Fn(Payload) -> Option<T>,
) -> Option<T> {
    runtime().block_on(async {
        tokio::time::timeout(timeout, async {
            let mut stream = crate::ipc_client::connect().await.ok()?;
            exchange(&mut stream, root, request, pick).await
        })
        .await
        .ok()?
    })
}

/// Every child of folder `parent` (empty: the root container), all pages. `None` when any page
/// could not be confirmed.
pub fn enumerate_children(root: &[u8], parent: &[u8]) -> Option<Vec<ProviderItem>> {
    let mut items = Vec::new();
    let mut page_token = Vec::new();
    for _ in 0..MAX_PAGES {
        let response = call(
            ENUMERATE_TIMEOUT,
            root,
            Payload::EnumerateChildrenRequest(EnumerateChildrenRequest {
                root_id: root.to_vec(),
                parent_item_id: parent.to_vec(),
                page_token: page_token.clone(),
                limit: PAGE_LIMIT,
            }),
            |payload| match payload {
                Payload::EnumerateChildrenResponse(r) => Some(r),
                _ => None,
            },
        )?;
        if !response.ok {
            eprintln!(
                "yadorilink-cfapi-host: enumeration refused (failure {}): {}",
                response.failure, response.error
            );
            return None;
        }
        items.extend(response.items);
        if response.next_page_token.is_empty() {
            return Some(items);
        }
        page_token = response.next_page_token;
    }
    None
}

/// Asks the daemon for the current bytes of `item`, as a verified file in its handoff directory.
pub fn materialize(
    root: &[u8],
    item: &[u8],
    request_id: &[u8],
) -> Option<MaterializeToTempResponse> {
    call(
        MATERIALIZE_TIMEOUT,
        root,
        Payload::MaterializeToTempRequest(MaterializeToTempRequest {
            request_id: request_id.to_vec(),
            root_id: root.to_vec(),
            item_id: item.to_vec(),
            requested_version_hash: Vec::new(),
        }),
        move |payload| match payload {
            Payload::MaterializeToTempResponse(r) if r.request_id == request_id => Some(r),
            _ => None,
        },
    )
}

/// Sends one change the user made to the daemon and returns its answer; `None` when the daemon
/// could not be asked or did not answer (the change may or may not have been applied: send the
/// same request again).
pub fn apply(
    root: &[u8],
    request: ProviderApplyChangeRequest,
) -> Option<ProviderApplyChangeResponse> {
    let request_id = request.request_id.clone();
    call(APPLY_TIMEOUT, root, Payload::ProviderApplyChangeRequest(request), move |payload| {
        match payload {
            Payload::ProviderApplyChangeResponse(r) if r.request_id == request_id => Some(r),
            _ => None,
        }
    })
}

/// Tells the daemon that the user is reading `item` (it pauses background prefetch). The daemon
/// answers nothing; failures are ignored.
pub fn note_fetch_activity(root: &[u8], item: &[u8]) {
    runtime().block_on(async {
        let _ = tokio::time::timeout(Duration::from_secs(2), async {
            let mut stream = crate::ipc_client::connect().await.ok()?;
            let message = |payload| ShellIpcMessage { payload: Some(payload) };
            write_message(
                &mut stream,
                &message(Payload::ExtensionHandshake(ExtensionHandshake {
                    root_id: root.to_vec(),
                    extension_build: EXTENSION_BUILD.into(),
                })),
            )
            .await
            .ok()?;
            write_message(
                &mut stream,
                &message(Payload::ProviderActivity(ProviderActivity {
                    root_id: root.to_vec(),
                    item_id: item.to_vec(),
                    activity_kind: ActivityKind::Fetch as i32,
                })),
            )
            .await
            .ok()
        })
        .await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use yadorilink_ipc_proto::shellipc::{EnumerateChildrenResponse, StatusPush};

    /// The handshake precedes the request, pushes in between are skipped, and the matching
    /// response is returned.
    #[tokio::test]
    async fn the_handshake_comes_first_and_unrelated_pushes_are_skipped() {
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        let daemon = tokio::spawn(async move {
            let first: ShellIpcMessage = read_message(&mut server).await.unwrap().unwrap();
            assert!(matches!(first.payload, Some(Payload::ExtensionHandshake(_))));
            let second: ShellIpcMessage = read_message(&mut server).await.unwrap().unwrap();
            assert!(matches!(second.payload, Some(Payload::EnumerateChildrenRequest(_))));
            write_message(
                &mut server,
                &ShellIpcMessage { payload: Some(Payload::StatusPush(StatusPush::default())) },
            )
            .await
            .unwrap();
            write_message(
                &mut server,
                &ShellIpcMessage {
                    payload: Some(Payload::EnumerateChildrenResponse(EnumerateChildrenResponse {
                        ok: true,
                        items: vec![ProviderItem { name: "a".into(), ..Default::default() }],
                        ..Default::default()
                    })),
                },
            )
            .await
            .unwrap();
        });
        let answer = exchange(
            &mut client,
            &[7; 16],
            Payload::EnumerateChildrenRequest(EnumerateChildrenRequest::default()),
            |payload| match payload {
                Payload::EnumerateChildrenResponse(r) => Some(r),
                _ => None,
            },
        )
        .await
        .expect("an answer");
        assert_eq!(answer.items[0].name, "a");
        daemon.await.unwrap();
    }

    /// A connection that closes before the answer is a failure, not an empty success.
    #[tokio::test]
    async fn a_closed_connection_is_no_answer() {
        let (mut client, server) = tokio::io::duplex(1024);
        drop(server);
        let answer = exchange(
            &mut client,
            &[7; 16],
            Payload::EnumerateChildrenRequest(EnumerateChildrenRequest::default()),
            |payload| match payload {
                Payload::EnumerateChildrenResponse(r) => Some(r),
                _ => None,
            },
        )
        .await;
        assert!(answer.is_none());
    }
}

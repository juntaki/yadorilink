#![cfg(windows)]

//! M2-3b: the daemon-process side of `dehydrate_server`'s pipe --
//! `materialization_eviction.rs`'s ONLY way to get a confirmed answer
//! that a Windows placeholder's local content was actually dehydrated
//! before it commits the row to `Placeholder` and reclaims blocks. See
//! `shell-ext/windows/src/dehydrate_server.rs`'s own module doc for why
//! this is a real cross-process RPC (daemon dials cfapi-host), unlike
//! `placeholder_inspect_windows.rs`'s direct-call bet for the read-only
//! dirty-detection query.
//!
//! Mirrors `shell_ipc::client::query_status`'s Windows client exactly
//! (bounded retry on `ERROR_PIPE_BUSY`, no server-identity verification --
//! that check exists in `shell-ext/windows/src/ipc_client.rs` because
//! THAT client runs inside every Explorer.exe process, a much more
//! exposed context than this daemon-to-daemon-owned-process call; this
//! module follows the daemon's own existing convention for dialing
//! another local process's pipe, not the Explorer-DLL one).

use std::sync::OnceLock;
use std::time::Duration;

use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use tokio::runtime::Runtime;
use yadorilink_ipc_proto::framing::{read_message, write_message};
use yadorilink_ipc_proto::shellipc::shell_ipc_message::Payload;
use yadorilink_ipc_proto::shellipc::{DehydrateRequest, DehydrateResponse, ShellIpcMessage};

const ERROR_PIPE_BUSY: i32 = 231;
const MAX_ATTEMPTS: u32 = 5;
const RETRY_DELAY: Duration = Duration::from_millis(50);

/// `MaterializationExecutionPort::dehydrate_windows_placeholder` (the port
/// method `materialization_eviction::evict_to_placeholder` calls) is a
/// plain synchronous trait method -- matching every other method on that
/// port, and callable from `evict_file`'s own synchronous call sites
/// (the eviction sweep, the CLI's manual evict command) without requiring
/// them to become async -- but this module's own client call is
/// inherently async (named-pipe I/O). Bridges the two with a dedicated,
/// lazily-started, single-threaded runtime blocked on per call, the exact
/// same pattern `shell-ext/windows/src/ipc_client.rs`'s own doc comment
/// documents for the identical problem on the shell-extension side
/// ("COM shell-extension callbacks are inherently synchronous, so this
/// module owns one... runtime and blocks on it per call"). A dedicated
/// runtime rather than `tokio::runtime::Handle::current().block_on(...)`:
/// the latter panics if `evict_file` is ever called from within an
/// existing async task on a current-thread runtime (nesting a runtime
/// inside itself) -- an independent runtime has no such restriction, at
/// the cost of blocking whatever OS thread calls in for up to
/// `DEHYDRATE_TIMEOUT`.
fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to start the dehydrate pipe client's background Tokio runtime")
    })
}

/// Synchronous wrapper around [`dehydrate_via_cfapi_host`] -- see
/// [`runtime`]'s doc comment for why a blocking wrapper is needed here.
/// This is what `ReplicaCoordinator`'s `MaterializationExecutionPort`
/// implementation actually calls.
pub fn dehydrate_via_cfapi_host_blocking(
    absolute_path: &str,
    expected_generation: Option<u64>,
) -> Result<(), DehydrateError> {
    runtime().block_on(dehydrate_via_cfapi_host(absolute_path, expected_generation))
}

/// Bounded well above any expected `CfDehydratePlaceholder` call (a local,
/// synchronous driver operation with no network I/O, unlike hydration's
/// `HYDRATE_TIMEOUT`) but still finite: if `cfapi-host.exe` is wedged or
/// its dehydrate pipe is saturated, `evict_file`'s caller must eventually
/// get an error back and roll the row back to `Hydrated` rather than hang
/// the eviction sweep indefinitely.
const DEHYDRATE_TIMEOUT: Duration = Duration::from_secs(15);

/// Every failure mode this returns must be treated as "dehydration did
/// NOT happen" by the caller -- there is no variant here that means
/// "unknown, might have succeeded". A `CfDehydratePlaceholder` call that
/// itself partially completes before erroring is a real residual risk
/// this module cannot close (see `dehydrate_placeholder`'s own doc
/// comment in `cfapi.rs`), but every error THIS module can distinguish
/// (connection refused, timeout, malformed response, an explicit `ok:
/// false`) fails closed the same way: the caller must not commit the
/// `Placeholder` transition or reclaim any block.
#[derive(Debug)]
pub enum DehydrateError {
    Io(std::io::Error),
    Timeout,
    /// cfapi-host itself reported failure (`DehydrateResponse{ ok: false,
    /// error }`), or the response was malformed/missing entirely -- the
    /// `String` is a human-readable reason for logging, not something a
    /// caller should pattern-match on.
    Rejected(String),
}

impl std::fmt::Display for DehydrateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DehydrateError::Io(e) => write!(f, "dehydrate pipe I/O error: {e}"),
            DehydrateError::Timeout => {
                write!(f, "dehydrate pipe call timed out after {DEHYDRATE_TIMEOUT:?}")
            }
            DehydrateError::Rejected(reason) => write!(f, "dehydrate rejected: {reason}"),
        }
    }
}

impl std::error::Error for DehydrateError {}

/// `\\.\pipe\yadorilink-cfapi-host-<user>` -- must match `shell-ext/windows/
/// src/dehydrate_server.rs::pipe_name` exactly.
fn pipe_name() -> String {
    #[cfg(debug_assertions)]
    {
        if let Ok(name) = std::env::var("YADORILINK_DEHYDRATE_PIPE") {
            return name;
        }
    }
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "default".into());
    format!(r"\\.\pipe\yadorilink-cfapi-host-{user}")
}

/// Asks `cfapi-host.exe` to natively dehydrate the placeholder at
/// `absolute_path`, blocking until it confirms success or failure (or
/// this call times out). `expected_generation`: the generation this
/// process's index has recorded for the file (see
/// `MaterializationExecutionPort::get_recorded_placeholder_identity`),
/// passed through unchanged as `DehydrateRequest`'s own defense-in-depth
/// identity guard -- `None` if this row never had one recorded (a
/// pre-M2-3a row, or a mismatched provider_kind), in which case
/// cfapi-host dehydrates unconditionally.
pub async fn dehydrate_via_cfapi_host(
    absolute_path: &str,
    expected_generation: Option<u64>,
) -> Result<(), DehydrateError> {
    tokio::time::timeout(DEHYDRATE_TIMEOUT, dehydrate_inner(absolute_path, expected_generation))
        .await
        .map_err(|_| DehydrateError::Timeout)?
}

async fn dehydrate_inner(
    absolute_path: &str,
    expected_generation: Option<u64>,
) -> Result<(), DehydrateError> {
    let mut stream = connect().await.map_err(DehydrateError::Io)?;
    write_message(
        &mut stream,
        &ShellIpcMessage {
            payload: Some(Payload::DehydrateRequest(DehydrateRequest {
                path: absolute_path.to_string(),
                expected_generation,
            })),
        },
    )
    .await
    .map_err(DehydrateError::Io)?;
    let response =
        read_message::<ShellIpcMessage>(&mut stream).await.map_err(DehydrateError::Io)?;
    match response.and_then(|m| m.payload) {
        Some(Payload::DehydrateResponse(DehydrateResponse { ok: true, .. })) => Ok(()),
        Some(Payload::DehydrateResponse(DehydrateResponse { ok: false, error })) => {
            Err(DehydrateError::Rejected(error))
        }
        _ => Err(DehydrateError::Rejected(
            "cfapi-host's dehydrate pipe returned a malformed or missing response".to_string(),
        )),
    }
}

async fn connect() -> std::io::Result<NamedPipeClient> {
    let name = pipe_name();
    let mut attempt = 0;
    loop {
        match ClientOptions::new().open(&name) {
            Ok(client) => return Ok(client),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && attempt < MAX_ATTEMPTS => {
                attempt += 1;
                tokio::time::sleep(RETRY_DELAY).await;
            }
            Err(e) => return Err(e),
        }
    }
}

//! Golden tests for what the `yadorilink` binary writes to stdout and stderr,
//! and the exit code it returns.
//!
//! Each case runs the real binary as a child process, with every environment
//! variable it reads pointed at a per-test temporary directory, and compares
//! the complete stdout, the complete stderr and the exit code against fixed
//! expectations. The library-level tests elsewhere check what a command does;
//! these check what a person at a terminal (or a script parsing its output)
//! actually sees, so a refactor that moves command logic around cannot change
//! a byte of it unnoticed.
//!
//! Cases that need a daemon run one in-process on a per-test control socket,
//! the same harness `tests/limits.rs` and `tests/link_library_surface.rs` use.
//! Cases that need the coordination plane only exercise the paths that fail
//! before any request is made (not signed in, invalid arguments), because no
//! in-repo coordination server exists to answer the rest.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::SegmentBlockStore;

/// What one run of the binary produced.
#[derive(Debug, PartialEq, Eq)]
struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Run {
    fn new(code: i32, stdout: &str, stderr: &str) -> Self {
        Run { code, stdout: stdout.to_owned(), stderr: stderr.to_owned() }
    }
}

/// An isolated environment for one run: its own config directory, credential
/// file, home directory and control socket path.
struct Env {
    dir: tempfile::TempDir,
    socket: PathBuf,
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("daemon.sock");
        Env { dir, socket }
    }

    fn root(&self) -> &Path {
        self.dir.path()
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_yadorilink"));
        command
            .args(args)
            .env_clear()
            .env("HOME", self.root())
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("YADORILINK_CONFIG_DIR", self.root().join("config"))
            .env("YADORILINK_CONTROL_SOCKET", &self.socket)
            .env("YADORILINK_CREDENTIAL_STORE", "file")
            .env("YADORILINK_CREDENTIAL_FILE", self.root().join("credentials.json"))
            // A coordination address nothing listens on: every case here must
            // fail (or finish) before it would contact the coordination plane.
            .env("YADORILINK_COORDINATION_HTTP_ADDR", "http://127.0.0.1:9");
        command
    }

    /// Runs the binary and replaces this environment's temporary directory
    /// (canonical and as given) with `<TMP>` in both streams.
    fn run_blocking(&self, args: &[&str]) -> Run {
        let output = self.command(args).output().expect("run the yadorilink binary");
        let canonical = self.root().canonicalize().unwrap();
        let normalize = |bytes: &[u8]| {
            String::from_utf8(bytes.to_vec())
                .expect("utf-8 output")
                .replace(&canonical.to_string_lossy().to_string(), "<TMP>")
                .replace(&self.root().to_string_lossy().to_string(), "<TMP>")
        };
        Run {
            code: output.status.code().expect("exit code"),
            stdout: normalize(&output.stdout),
            stderr: normalize(&output.stderr),
        }
    }

    async fn run(self: &Arc<Self>, args: &[&str]) -> Run {
        let env = Arc::clone(self);
        let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
        tokio::task::spawn_blocking(move || {
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            env.run_blocking(&args)
        })
        .await
        .unwrap()
    }
}

/// Starts an in-process daemon serving `env`'s control socket.
async fn start_daemon(env: &Env) -> Arc<DaemonState> {
    // The daemon's own config (governance limits) lives under the same
    // config directory the child process is pointed at.
    std::env::set_var("YADORILINK_CONFIG_DIR", env.root().join("config"));
    std::fs::create_dir_all(env.root().join("config")).unwrap();
    let store = Arc::new(SegmentBlockStore::new(env.root().join("blocks")).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open(env.root().join("sync.sqlite3")).unwrap());
    let state = DaemonState::new("device-under-test".into(), sync_state, store);
    state.set_device_signing_key(yadorilink_transport::DeviceSigningKeyPair::generate().signing);

    let serve_path = env.socket.clone();
    let serve_context =
        Arc::new(yadorilink_daemon::control_context::ControlContext::from_state(state.clone()));
    tokio::spawn(async move {
        let _ =
            yadorilink_daemon::control_socket::unix_transport::serve(&serve_path, serve_context)
                .await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    state
}

/// Links `folder` to `group_id` directly over the control socket, bypassing
/// the CLI (and so the coordination plane, which the plain `Link` request
/// does not need).
async fn link_directly(env: &Env, folder: &Path, group_id: &str) {
    use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
    use yadorilink_ipc_proto::daemonctl::{
        DaemonControlRequest, DaemonControlResponse, LinkRequest, PendingEnrollmentKind,
    };
    use yadorilink_ipc_proto::framing::{read_message, write_message};

    let mut stream = tokio::net::UnixStream::connect(&env.socket).await.unwrap();
    let request = DaemonControlRequest {
        payload: Some(ReqPayload::Link(LinkRequest {
            local_path: folder.canonicalize().unwrap().to_string_lossy().to_string(),
            group_id: group_id.to_owned(),
            on_demand: false,
            max_local_size_bytes: None,
            acknowledge_risks: true,
            pending_enrollment_operation_id: String::new(),
            pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
            pending_enrollment_device_id: String::new(),
        })),
        protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
    };
    write_message(&mut stream, &request).await.unwrap();
    let response = read_message::<DaemonControlResponse>(&mut stream).await.unwrap().unwrap();
    assert!(
        !matches!(
            response.payload,
            Some(yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload::Error(_))
        ),
        "linking the fixture folder failed: {response:?}"
    );
}

/// The in-process daemon reads `YADORILINK_CONFIG_DIR` from this process's
/// environment, so daemon-backed cases must not overlap.
static DAEMON_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const NOT_LOGGED_IN: &str = "error: not logged in — run `yadorilink login`\n";
const DAEMON_NOT_RUNNING: &str =
    "error: yadorilink daemon is not running — run `yadorilink daemon start`\n";

// ---- no daemon, not signed in --------------------------------------------

#[test]
fn coordination_commands_report_not_logged_in_with_exit_code_2() {
    let env = Env::new();
    for args in [
        &["share", "members", "photos"][..],
        &["share", "list"],
        &["share", "joinable"],
        &["share", "invites"],
        &["share", "pending"],
        &["share", "approve", "photos", "device-1"],
        &["share", "deny", "photos", "device-1"],
        &["share", "revoke", "photos", "device-1"],
        &["share", "invite", "photos"],
        &["share", "cancel-invite", "invite-1"],
        &["share", "change-role", "photos", "device-1", "--role", "viewer"],
        &["share", "set-storage-mode", "photos", "--mode", "eager"],
        &["share", "grant", "photos", "device-1"],
        &["share", "delete", "photos"],
        &["device", "list"],
        &["device", "register", "--name", "laptop"],
        &["account", "delete", "status"],
        &["account", "delete", "request"],
        &["account", "delete", "cancel"],
        &["account", "delete", "confirm", "token"],
        &["account", "export"],
        &["logout"],
        &["forget-local-credentials"],
    ] {
        assert_eq!(env.run_blocking(args), Run::new(2, "", NOT_LOGGED_IN), "yadorilink {args:?}");
    }
}

#[test]
fn daemon_commands_report_daemon_not_running_with_exit_code_4() {
    let env = Env::new();
    for args in [
        &["links"][..],
        &["unlink", "/nowhere"],
        &["daemon", "stop"],
        &["daemon", "pause"],
        &["daemon", "resume"],
        &["limits", "show"],
        &["limits", "set", "--up", "1", "--down", "2"],
        &["gc", "--dry-run"],
        &["inbox"],
        &["send", "/nowhere", "device-1"],
        &["receive", "transfer-1"],
        &["trash", "list"],
        &["conflicts", "list"],
        &["versions", "/nowhere"],
        &["pin", "/nowhere"],
        &["unpin", "/nowhere"],
        &["evict", "/nowhere"],
        &["materialization-status", "/nowhere"],
        &["update", "status"],
        &["update", "check"],
        &["device", "remove", "device-1"],
        &["share", "revoke", "edge-1"],
    ] {
        assert_eq!(
            env.run_blocking(args),
            Run::new(4, "", DAEMON_NOT_RUNNING),
            "yadorilink {args:?}"
        );
    }
}

#[test]
fn a_role_owner_is_refused_before_any_request() {
    let env = Env::new();
    let run = env.run_blocking(&["share", "change-role", "photos", "device-1", "--role", "owner"]);
    assert_eq!(run.code, 1);
    assert_eq!(run.stdout, "");
    assert!(
        run.stderr.starts_with(
            "error: invalid --role \"owner\" (expected viewer or editor); owner is not available \
             via this command yet\n"
        ),
        "{run:?}"
    );
}

#[test]
fn an_invalid_storage_mode_is_refused_before_any_request() {
    let env = Env::new();
    for args in [
        &["share", "join", "photos", "--path", "/nowhere", "--storage-mode", "bogus"][..],
        &["share", "accept", "code", "--path", "/nowhere", "--storage-mode", "bogus"],
        &["share", "set-storage-mode", "photos", "--mode", "bogus"],
    ] {
        let run = env.run_blocking(args);
        assert_eq!(run.code, 1, "yadorilink {args:?}: {run:?}");
        assert_eq!(run.stdout, "", "yadorilink {args:?}");
        assert!(
            run.stderr.starts_with(
                "error: invalid --storage-mode \"bogus\" (expected eager or on-demand)\n"
            ),
            "yadorilink {args:?}: {run:?}"
        );
    }
}

#[test]
fn linking_a_missing_directory_names_it() {
    let env = Env::new();
    let run = env.run_blocking(&["link", "/definitely/not/here", "photos", "--dry-run"]);
    assert_eq!(run.code, 1, "{run:?}");
    assert_eq!(run.stdout, "");
    assert!(run.stderr.starts_with("error: no such directory: /definitely/not/here\n"), "{run:?}");
}

// ---- with a daemon --------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_backed_commands_print_their_results() {
    let _guard = DAEMON_MUTEX.lock().await;
    let env = Arc::new(Env::new());
    let _state = start_daemon(&env).await;

    assert_eq!(env.run(&["links"]).await, Run::new(0, "No linked folders.\n", ""));
    assert_eq!(env.run(&["daemon", "pause"]).await, Run::new(0, "Sync paused.\n", ""));
    assert_eq!(env.run(&["daemon", "resume"]).await, Run::new(0, "Sync resumed.\n", ""));
    assert_eq!(
        env.run(&["limits", "show"]).await,
        Run::new(0, "up=unlimited  down=unlimited\n", "")
    );
    assert_eq!(
        env.run(&["limits", "set", "--up", "1024", "--down", "0"]).await,
        Run::new(0, "Limits updated: up=1024 bytes/sec  down=unlimited\n", "")
    );
    assert_eq!(
        env.run(&["limits", "show"]).await,
        Run::new(0, "up=1024 bytes/sec  down=unlimited\n", "")
    );
    // Without coordination-plane connectivity the daemon refuses the inbox
    // listing; that refusal is an ordinary reportable command failure.
    assert_eq!(
        env.run(&["inbox"]).await,
        Run::new(
            1,
            "",
            "error: Track Send is not ready yet (this device has no coordination-plane \
             connectivity established)\nhint: run `yadorilink report error --last --preview` to \
             see what would be reported (nothing is sent automatically)\n"
        )
    );
    assert_eq!(env.run(&["trash", "list"]).await, Run::new(0, "Trash is empty.\n", ""));
    assert_eq!(env.run(&["conflicts", "list"]).await, Run::new(0, "No conflicted files.\n", ""));
    assert_eq!(
        env.run(&["gc", "--dry-run"]).await,
        Run::new(0, "Dry run: would delete 0 block(s), reclaiming 0 bytes\n", "")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn links_then_unlink_print_the_folder() {
    let _guard = DAEMON_MUTEX.lock().await;
    let env = Arc::new(Env::new());
    let _state = start_daemon(&env).await;
    let folder = env.root().join("photos");
    std::fs::create_dir_all(&folder).unwrap();
    link_directly(&env, &folder, "group-1").await;

    assert_eq!(
        env.run(&["links"]).await,
        Run::new(0, "<TMP>/photos  group=group-1  syncing\n", "")
    );
    assert_eq!(
        env.run(&["daemon", "pause"]).await,
        Run::new(0, "Sync paused.\n", ""),
        "pausing with one link"
    );
    assert_eq!(env.run(&["links"]).await, Run::new(0, "<TMP>/photos  group=group-1  paused\n", ""));

    let canonical = folder.canonicalize().unwrap().to_string_lossy().to_string();
    assert_eq!(
        env.run(&["unlink", &canonical, "--force"]).await,
        Run::new(
            0,
            "Unlinked <TMP>/photos\n",
            "warning: --force set -- if this device is the sole full replica for this folder's \
             group with no other confirmed-ready replica, unlinking anyway may permanently lose \
             the only copy of that data\n"
        )
    );
    assert_eq!(env.run(&["links"]).await, Run::new(0, "No linked folders.\n", ""));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn link_dry_run_prints_the_preflight_report() {
    let _guard = DAEMON_MUTEX.lock().await;
    let env = Arc::new(Env::new());
    let _state = start_daemon(&env).await;
    let folder = env.root().join("notes");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join("a.txt"), b"a").unwrap();

    let run = env.run(&["link", &folder.to_string_lossy(), "photos", "--dry-run"]).await;
    assert_eq!(run.code, 0, "{run:?}");
    assert_eq!(run.stderr, "");
    let lines: Vec<&str> = run.stdout.lines().collect();
    assert_eq!(lines[0], "preflight: non-empty folder (1 entry)");
    // The free-space line carries this machine's real numbers; pin its shape.
    assert!(lines[1].starts_with("preflight: "), "{lines:?}");
    assert!(lines[1].contains(" free space on target volume ("), "{lines:?}");
    assert!(lines[1].contains(" bytes free, headroom "), "{lines:?}");
    assert!(
        lines.iter().any(|l| l.starts_with("warning: ") && l.contains("not empty")),
        "{lines:?}"
    );
    assert_eq!(*lines.last().unwrap(), "dry run: no link registered (risky conditions found)");
}

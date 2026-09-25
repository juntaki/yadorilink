//! Starting and stopping the local daemon.

use std::path::PathBuf;
use std::time::Duration;

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::{ShutdownRequest, StatusRequest};

use crate::daemon::control;
use crate::dto::DaemonLaunch;
use crate::error::CoreError;

/// What [`start_daemon`] found or did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DaemonStartOutcome {
    /// The daemon already answered on the control socket; nothing was
    /// launched.
    AlreadyRunning,
    /// The daemon was launched and then answered.
    Started,
}

/// Launches the daemon if nothing answers the control socket: spawns
/// `yadorilink-daemon` from next to the current executable, else from PATH,
/// then polls every 250 ms, for up to [`START_BUDGET`], until it answers.
pub async fn start_daemon() -> Result<DaemonStartOutcome, CoreError> {
    start_daemon_with(&DaemonLaunch::SpawnBinary { path: None }).await
}

/// [`start_daemon`] with a chosen launch strategy (see [`DaemonLaunch`]).
///
/// # Errors
/// [`CoreError::DaemonUnresponsive`] when a daemon is already running but
/// does not answer: nothing is launched, since another copy cannot help.
/// [`CoreError::DaemonNotRunning`] is never returned for a launch failure;
/// every way the daemon could not be brought up is [`CoreError::Other`],
/// naming what was tried.
pub async fn start_daemon_with(launch: &DaemonLaunch) -> Result<DaemonStartOutcome, CoreError> {
    match control::send(ReqPayload::Status(StatusRequest {})).await {
        Ok(_) => return Ok(DaemonStartOutcome::AlreadyRunning),
        Err(CoreError::DaemonUnresponsive) => return Err(CoreError::DaemonUnresponsive),
        Err(_) => {}
    }

    let mut failures = Vec::new();
    let mut launched = false;
    for step in launch_steps(launch, current_uid()) {
        match run_step(&step) {
            Ok(()) => {
                launched = true;
                break;
            }
            Err(e) => failures.push(format!("{}: {e}", step.program.display())),
        }
    }
    if !launched {
        // One attempt reads as it always has: "failed to launch <path>: <error>".
        return Err(CoreError::Other(format!("failed to launch {}", failures.join("; then "))));
    }

    // Bounded by elapsed time, not by attempts: a probe that connects and
    // then waits on its reply deadline would otherwise stretch each attempt.
    let answered = tokio::time::timeout(START_BUDGET, async {
        loop {
            tokio::time::sleep(Duration::from_millis(250)).await;
            if daemon_answers().await {
                return;
            }
        }
    })
    .await;
    match answered {
        Ok(()) => Ok(DaemonStartOutcome::Started),
        Err(_) => Err(CoreError::Other("daemon did not become reachable after starting".into())),
    }
}

/// How long a freshly launched daemon has to start answering.
pub const START_BUDGET: Duration = Duration::from_secs(5);

/// One way of bringing the daemon up, tried in order until one launches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LaunchStep {
    pub(crate) program: PathBuf,
    pub(crate) args: Vec<String>,
    /// Wait for the program and require success (`launchctl`), rather than
    /// spawning it and leaving it running (the daemon itself).
    pub(crate) wait: bool,
}

/// The launch attempts for `launch`. A LaunchAgent is started through
/// `/bin/launchctl`; its fallback binary is used only when it is an absolute
/// path, so this strategy never searches PATH for anything.
pub(crate) fn launch_steps(launch: &DaemonLaunch, uid: u32) -> Vec<LaunchStep> {
    match launch {
        DaemonLaunch::SpawnBinary { path } => vec![LaunchStep {
            program: path.as_ref().map_or_else(daemon_binary_path, PathBuf::from),
            args: Vec::new(),
            wait: false,
        }],
        DaemonLaunch::LaunchAgent { label, fallback_binary } => {
            let mut steps = vec![LaunchStep {
                program: PathBuf::from("/bin/launchctl"),
                args: vec!["kickstart".into(), format!("gui/{uid}/{label}")],
                wait: true,
            }];
            steps.extend(
                fallback_binary
                    .as_deref()
                    .map(PathBuf::from)
                    .filter(|p| p.is_absolute())
                    .map(|program| LaunchStep { program, args: Vec::new(), wait: false }),
            );
            steps
        }
    }
}

fn run_step(step: &LaunchStep) -> std::io::Result<()> {
    let mut command = std::process::Command::new(&step.program);
    command.args(&step.args);
    if !step.wait {
        return spawn_detached(command);
    }
    let output = command.stdin(std::process::Stdio::null()).output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "{} ({})",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

/// Starts a program that outlives this call, such as the daemon itself.
/// It gets no stdin and, on Unix, its own process group, so a terminal's
/// Ctrl-C aimed at the starter does not reach it. A thread waits for it, so
/// when it exits it is reaped instead of staying a zombie of a long-lived
/// starter such as the app. Its stdout and stderr stay the starter's, where
/// a daemon started from a terminal logs.
fn spawn_detached(mut command: std::process::Command) -> std::io::Result<()> {
    command.stdin(std::process::Stdio::null());
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut command, 0);
    let mut child = command.spawn()?;
    std::thread::Builder::new().name("yadorilink-daemon-reaper".into()).spawn(move || {
        let _ = child.wait();
    })?;
    Ok(())
}

#[cfg(unix)]
fn current_uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

#[cfg(not(unix))]
fn current_uid() -> u32 {
    0
}

async fn daemon_answers() -> bool {
    control::send(ReqPayload::Status(StatusRequest {})).await.is_ok()
}

/// Asks the daemon to shut down cleanly. Under a supervisor that restarts it
/// (the macOS LaunchAgent's `KeepAlive`, the Windows logon task), this is a
/// restart.
pub async fn stop_daemon() -> Result<(), CoreError> {
    control::send(ReqPayload::Shutdown(ShutdownRequest {})).await?;
    Ok(())
}

/// `yadorilink-daemon[.exe]` next to the current executable when it exists
/// there, else the bare name for a PATH lookup.
fn daemon_binary_path() -> PathBuf {
    let name = if cfg!(windows) { "yadorilink-daemon.exe" } else { "yadorilink-daemon" };
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join(name)))
        .filter(|p| p.exists())
        .unwrap_or_else(|| PathBuf::from(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_daemon_launch_agent_never_uses_path() {
        let with_fallback = DaemonLaunch::LaunchAgent {
            label: "com.yadorilink.daemon".into(),
            fallback_binary: Some("/usr/local/bin/yadorilink-daemon".into()),
        };
        assert_eq!(
            launch_steps(&with_fallback, 501),
            vec![
                LaunchStep {
                    program: "/bin/launchctl".into(),
                    args: vec!["kickstart".into(), "gui/501/com.yadorilink.daemon".into()],
                    wait: true,
                },
                LaunchStep {
                    program: "/usr/local/bin/yadorilink-daemon".into(),
                    args: vec![],
                    wait: false,
                },
            ]
        );
        // A bare name would be a PATH lookup: it is dropped, not tried.
        let bare = DaemonLaunch::LaunchAgent {
            label: "l".into(),
            fallback_binary: Some("yadorilink-daemon".into()),
        };
        let steps = launch_steps(&bare, 1);
        assert_eq!(steps.len(), 1);
        assert!(steps.iter().all(|s| s.program.is_absolute()));
        let none = DaemonLaunch::LaunchAgent { label: "l".into(), fallback_binary: None };
        assert_eq!(launch_steps(&none, 1).len(), 1);
    }

    #[test]
    fn spawn_binary_uses_the_given_path_else_the_default_lookup() {
        let given = DaemonLaunch::SpawnBinary { path: Some("/opt/y/yadorilink-daemon".into()) };
        assert_eq!(launch_steps(&given, 0)[0].program, PathBuf::from("/opt/y/yadorilink-daemon"));
        let default = DaemonLaunch::SpawnBinary { path: None };
        assert_eq!(launch_steps(&default, 0)[0].program, daemon_binary_path());
    }

    /// The name it looks for is a pure, display-free fact worth pinning; the
    /// "sibling of the current executable, else PATH" resolution needs a real
    /// filesystem layout to test end to end.
    #[test]
    fn daemon_binary_path_uses_the_platform_correct_name() {
        let path = daemon_binary_path();
        let name = path.file_name().unwrap().to_string_lossy();
        if cfg!(windows) {
            assert_eq!(name, "yadorilink-daemon.exe");
        } else {
            assert_eq!(name, "yadorilink-daemon");
        }
    }

    /// A daemon started directly, rather than by a supervisor, is the
    /// starting process's child. When it exits it must be reaped, or a
    /// long-lived app keeps a zombie for the rest of its life.
    #[cfg(unix)]
    #[test]
    fn a_directly_started_daemon_is_reaped_when_it_exits() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("pid");
        let step = LaunchStep {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), format!("echo $$ > '{}'", pid_file.display())],
            wait: false,
        };
        run_step(&step).unwrap();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let pid = loop {
            if let Some(pid) = std::fs::read_to_string(&pid_file)
                .ok()
                .and_then(|text| text.trim().parse::<libc::pid_t>().ok())
            {
                break pid;
            }
            assert!(std::time::Instant::now() < deadline, "the started process never ran");
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        // A zombie still accepts signal 0; only a reaped process is gone.
        // SAFETY: signal 0 only checks that the process exists.
        while unsafe { libc::kill(pid, 0) } == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the exited daemon process {pid} was never reaped"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

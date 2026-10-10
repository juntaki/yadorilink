# Cloud Files end-to-end run

`run-e2e.ps1` exercises the Windows Cloud Files integration with the real binaries and no GUI automation:
two daemons on one Windows machine, device A with a Cloud Files provider folder served by
`yadorilink-cfapi-host`, device B with an ordinary folder, both in one share. Every check looks at bytes
(SHA-256), names, sizes and placeholder attributes.

| # | Scenario |
|---|----------|
| 1 | placeholders are created for what device B has (reparse point, recall-on-access, right size) |
| 2 | an ordinary read hydrates a placeholder |
| 3 | the bytes equal the remote bytes (multi-block files, ranged read, full hash) |
| 4 | edit, ranged edit and an editor-style save-by-replace on Windows reach device B; bytes written over a never-read placeholder are kept as a conflicted copy on both devices (nothing proves where they come from) and never replace the remote version |
| 5 | rename of a hydrated file, a placeholder and a directory |
| 6 | delete of a hydrated file, a placeholder and a directory tree |
| 7 | remote edits (hydrated, unread, multi-block) and remote creates show up on Windows |
| 8 | `yadorilink evict` drops the local copy only after a full replica confirmed the version; a local edit that was not shared yet is never dropped |
| 9 | opening an evicted file hydrates it again with the right bytes |
| 10 | the cfapi-host, then the daemon, is restarted while a large read is in flight: no hang, no wrong bytes, a fresh read is correct |
| 11 | cfapi-host restart: same placeholder tree, reads and changes in both directions still work |
| 12 | daemon restart: same, after the peer session is back |
| 13 | Windows reboot (see below) |
| 15 | a local edit made while a large file is being hydrated is kept (bytes before and after untouched) and reaches device B |
| 16 | the other device changes the file while it is being hydrated: the read returns a whole version (old or new, never a mix) and Windows settles on the new one |
| 14 | the remote delete of the iteration directory reaches Windows (clean-up, also checked) |

## Running

```powershell
.\run-e2e.ps1 -BinDir <dir with yadorilink.exe and yadorilink-daemon.exe> `
    -HostExe <yadorilink-cfapi-host.exe> -CoordinationAddr http://127.0.0.1:8788 `
    -AuthDriver <sign-in helper> -Iterations 10 -Fresh
```

* The host must be a debug build: only a debug build accepts the pipe-name overrides that keep the two daemons
  apart.
* `-CoordinationAddr` must be a coordination service the CLI accepts (HTTPS, or plain HTTP on a loopback
  address), reachable from this machine.
* `-AuthDriver` is a Python 3 script that completes the CLI's `login --device` flow without a browser:
  `login --addr <address> --subject <subject> -- <cli command>`. A fresh run signs both devices in as a new
  account, because an account only takes so many devices.
* `-Scenarios 1,8,9` runs a subset; scenario 1 always has to be part of it, it creates the files the others use.
* Without `-Fresh` a run continues from `<WorkDir>\state.json` (the next iteration, results so far).
* `-HoldMB` sets the size of the two files read in scenario 10 (default 96), `-RaceMB` of those in 15 and 16 (default 64).
* Waits have fixed budgets (`-SyncTimeoutSec`, default 90 s); a slow run fails instead of waiting longer.
  After a daemon start the script waits until `yadorilink status` shows the peer connected and no "cannot fetch now"
  (about 90 s on the machines tried) before it relies on sync, and prints how long that took.

Results are printed per iteration and summarised per scenario at the end (passes / runs). Logs of every started
process are in `<WorkDir>\logs`; a failed scenario also leaves the last log lines, both statuses and both trees in
`<WorkDir>\failures`.

## Reboot

Scenario 13 restarts the operating system, which ends the script. It stores its state, runs `shutdown /r` and
exits with code 75. Run the same command again once the machine is back; it verifies the state after the reboot
and continues. `drive-remote.sh` does this over ssh:

```sh
E2E_SSH='ssh user@winhost' E2E_REMOTE_SCRIPT='C:\src\platforms\windows\e2e\run-e2e.ps1' \
  ./drive-remote.sh -BinDir ... -HostExe ... -CoordinationAddr ... -AuthDriver ... -Iterations 10 -Fresh
```

`E2E_AFTER_REBOOT` may name a command to run once ssh answers again (for example to re-establish a port forward
the reboot dropped). `-SkipReboot` leaves scenario 13 out.

Exit codes: 0 all green, 1 a check failed, 2 setup failed, 75 reboot requested.

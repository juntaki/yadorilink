#!/usr/bin/env bash
# Runs run-e2e.ps1 on a remote Windows machine over ssh and carries it across the reboot of scenario 13.
#
# run-e2e.ps1 exits with code 75 after it has asked Windows to restart; when the restart comes first, the ssh
# connection drops instead (exit code 255). In both cases this script waits until the machine answers over ssh
# again and starts run-e2e.ps1 once more with the same arguments (without -Fresh), which continues from the state
# the previous run stored.
#
#   E2E_SSH            command that runs one remote command line, e.g. "ssh -o BatchMode=yes user@host" (required)
#   E2E_REMOTE_SCRIPT  path of run-e2e.ps1 on the Windows machine (required)
#   E2E_AFTER_REBOOT   optional shell command run on this machine once ssh is back, before the run continues,
#                      e.g. to re-establish a port forward that the reboot dropped
#   E2E_REBOOT_WAIT    seconds to wait for the machine to come back (default 900)
#
# Usage: E2E_SSH=... E2E_REMOTE_SCRIPT='C:\src\platforms\windows\e2e\run-e2e.ps1' ./drive-remote.sh <run-e2e.ps1 arguments>
set -u
: "${E2E_SSH:?set E2E_SSH}"
: "${E2E_REMOTE_SCRIPT:?set E2E_REMOTE_SCRIPT}"
wait_secs="${E2E_REBOOT_WAIT:-900}"

# The remote command line is parsed by Windows: wrap every argument in double quotes.
quote_arg() {
  local a=${1//\"/\\\"}
  printf '"%s"' "$a"
}

run_remote() {
  local quoted=() a
  for a in "$@"; do quoted+=("$(quote_arg "$a")"); done
  # shellcheck disable=SC2086
  $E2E_SSH powershell -NoProfile -ExecutionPolicy Bypass -File "$(quote_arg "$E2E_REMOTE_SCRIPT")" "${quoted[@]}"
}

# True while a run-e2e.ps1 is still alive on the remote machine (a dropped connection does not stop it).
remote_run_alive() {
  local ps enc out
  ps="if (@(Get-CimInstance Win32_Process | Where-Object { \$_.CommandLine -like '*run-e2e.ps1*' -and \$_.ProcessId -ne \$PID }).Count -gt 0) { 'alive' } else { 'idle' }"
  enc=$(printf '%s' "$ps" | iconv -f UTF-8 -t UTF-16LE | base64 | tr -d '\n')
  # shellcheck disable=SC2086
  out=$($E2E_SSH powershell -NoProfile -EncodedCommand "$enc" 2>/dev/null | tr -d '\r')
  case "$out" in *alive*) return 0 ;; *) return 1 ;; esac
}

args=("$@")
resumes=0
while true; do
  run_remote "${args[@]}"
  code=$?
  if [ "$code" -ne 75 ] && [ "$code" -ne 255 ]; then
    exit "$code"
  fi
  resumes=$((resumes + 1))
  if [ "$resumes" -gt "${E2E_MAX_RESUMES:-100}" ]; then
    echo "giving up after $((resumes - 1)) resumes" >&2
    exit 4
  fi
  echo "== the run was interrupted (exit $code); waiting for ssh"
  sleep 30
  waited=30
  until $E2E_SSH hostname >/dev/null 2>&1; do
    if [ "$waited" -ge "$wait_secs" ]; then
      echo "the machine did not come back within ${wait_secs}s" >&2
      exit 3
    fi
    sleep 10
    waited=$((waited + 10))
  done
  echo "== the machine is back after about ${waited}s"
  # After a plain connection drop the run may still be going: never start a second one next to it.
  while remote_run_alive; do
    if [ "$waited" -ge "$wait_secs" ]; then
      echo "a run is still active on the machine after ${wait_secs}s" >&2
      exit 5
    fi
    echo "== the previous run is still active; waiting"
    sleep 10
    waited=$((waited + 10))
  done
  if [ -n "${E2E_AFTER_REBOOT:-}" ]; then
    eval "$E2E_AFTER_REBOOT"
  fi
  # Continue the stored run: -Fresh would start over.
  resumed=()
  for a in "${args[@]}"; do [ "$a" = "-Fresh" ] || resumed+=("$a"); done
  args=("${resumed[@]}")
done

# M6-0: competitive benchmark harness — design

Goal of M6: beat Resilio Sync on transfer speed. Goal of M6-0 (this crate):
give every later optimization commit a real, measured baseline instead of
vibes. This document is the architecture decision record for that harness,
not a spec for the whole milestone.

## Where it lives

A new standalone crate, `crates/yadorilink-bench` (workspace member), with
both a library (`src/lib.rs`) and a CLI binary (`src/main.rs`):
`cargo run -p yadorilink-bench -- L1 [--size-mb <n>]`, or `cargo bench-l1`
(alias in `.cargo/config.toml`, mirroring the `dst-*` alias convention).

**Not** an `xtask` subcommand. `xtask`'s own doc comment scopes it
explicitly to "DST replay and the tiered test lanes" — every subcommand
there shells out to `cargo test` under `RUSTFLAGS="--cfg madsim"` against a
seeded deterministic-simulation runtime. This harness is the opposite shape:
real wall-clock time, real OS threads, real (loopback, for now) UDP, driven
directly as a library, not through `cargo test`. Bolting it onto `xtask`
would mean either forking that tool's whole "shell out to `cargo test`"
model or leaving a `madsim`-flavored tool with one command that secretly
does something unrelated. A separate crate keeps both tools' documented
scope true.

## Driving YadoriLink: real `DaemonState`, not a mock

`crates/yadorilink-daemon/tests/support/mod.rs` already has the closest
existing thing to "two real YadoriLink nodes talking to each other":
`connect_two_daemons_with_channels` pairs two in-process `DaemonState`s
directly over loopback UDP with a real `PeerSyncSession` each way — the
exact wiring `peer_orchestrator.rs` uses in production, minus the
coordination-plane discovery step (direct dial instead of a netmap lookup).

That module is not reusable as a library dependency: it lives under
`tests/`, which Cargo only compiles into that crate's own integration-test
binaries (`mod support;` inside a `tests/*.rs` file). An external crate
cannot `use` it. Two options: (a) extract a shared, `#[cfg(test)]`-free
library crate both the tests and this harness depend on, or (b) duplicate
the minimal subset this harness actually needs.

**Decision: duplicate (b) for now.** `crates/yadorilink-bench/src/harness.rs`
is a ~250-line port of exactly the direct-pairing path (`new_device`,
`start_link_watch`, `pair_devices`, and their private helpers) — not the
other ~600 lines of matrix/chaos-test scaffolding (`DelayedGetBlockStore`,
`corrupt_stored_block`, the coordination-free account/device/group shims,
etc.) that this harness has no use for. Extracting a shared crate is real,
warranted work if the two copies drift, or once a second consumer (say, a
future `yadorilink-daemon-testkit` used by *both* the tests and more bench
scenarios) makes the duplication cost outweigh the extraction cost — not
before. `harness.rs`'s module doc carries the same "if production's
peer-pairing wiring changes, mirror the change here too" warning the
original carries, so this is a known, documented liability, not a silent one.

Two in-process `DaemonState`s in one OS process is a real limitation for
process-level metrics (CPU-seconds, peak RSS below) — see "What isn't
captured yet."

### Loopback today, real link characteristics later

L1's task description says "1GbE"; this first slice runs both `DaemonState`s
in one process over `127.0.0.1`, which has no real 1GbE ceiling to hit
(loopback throughput is typically far higher, and its latency/loss profile
is nothing like a real NIC). That's an intentional, honest scope cut for
this slice: the wire-bytes and timing instrumentation is what needed
building and proving out; a real 1GbE cap can be added as a `tc`-style rate
limit on the loopback interface (Linux `tc qdisc` on `lo`, or a local
`pfctl`/`dnctl` shim on macOS) as a bounded follow-up, orthogonal to
everything else here. **W1/W2 need something stronger anyway** — real
netem-shaped RTT/loss/bandwidth — which structurally requires the two
daemons to run as separate OS processes (or separate network namespaces) so
`tc netem` can be applied to a real interface between them, not a
same-process loopback socket. That's also the shape a genuine head-to-head
against a separately-installed Resilio Sync binary needs (it is a wholly
separate process outside this codebase, full stop). So the two-process
harness variant is real, necessary follow-up work for W1/W2/M1's separate
peers and for the Resilio comparison — not implemented in this slice, which
only needed the in-process pairing to prove out L1's instrumentation.

## Resilio Sync comparison

Checked at development time: `which resilio-sync rslsync` — **neither is
installed on this machine.** `src/resilio.rs` is accordingly a documented
stub: `ResilioAvailability::detect()` checks both binary names and reports
honestly either way; the actual comparison runner (drive Resilio as a real
separate OS process pointed at its own sync folder, over the same file set,
timed the same way) is a `TODO` in that module, not implemented. A machine
that does have Resilio installed gets an explicit "not implemented yet"
message, never a silently-skipped comparison.

## Metrics: what's captured now, and how

### Timestamps (real, all four implemented for L1)

- **T_detect**: `Instant::now()` right after the write-side `File` handle is
  flushed and dropped (real file close), through polling the **source**
  device's `file_index_repository()` for a live record at the expected path
  and size — the real watcher → debounce → scan → index pipeline (the real
  OS filesystem watcher via `LinkRuntimeController::start`, not the
  simulated harness source `dst_daemon_smoke.rs` uses).
- **T_index**: the same poll against the **receiver** device's
  `file_index_repository()` — "metadata available remotely" is exactly this:
  the DAG-imported record appearing in the receiver's index, which (verified
  by reading `dag_import.rs`) happens independently of and before the
  receiver has fetched/materialized the file's actual block content.
- **T_firstbyte**: polling the receiver's `TransportHub::wire_bytes_received`
  for the first increase past a pre-write baseline. This is a **proxy**, not
  a content-specific signal: it fires on the first UDP payload byte the
  receiver's socket sees after the baseline, which could in principle
  include protocol/control traffic unrelated to this file's first content
  byte. Documented here as the known imprecision; a tighter signal (hooking
  the block-serve response path specifically) is realistic follow-up work.
- **T_complete**: polling the receiver's on-disk file for
  `metadata().len() == expected_size` (true the instant the real
  materialization path's atomic temp-then-rename completes), followed by a
  **real, streaming SHA-256 comparison** of both files (not loaded into
  memory at once — 10GB) to assert byte-exact convergence for real. A digest
  mismatch fails the run loudly rather than reporting a fabricated
  convergence metric.

### Wire bytes / packets (real, newly instrumented)

Grepped `yadorilink-transport`/`daemon_state.rs` for existing counters —
**none existed.** Added minimal `AtomicU64` counters directly to
`TransportHub` (`crates/yadorilink-transport/src/transport_hub.rs`):
`wire_bytes_sent`/`wire_bytes_received`/`wire_packets_sent`/
`wire_packets_received`, incremented at the hub's own `send_batch`/`send_to`
(outbound) and `recv_loop` (inbound) — the single choke point every
datagram this hub sends or receives passes through, regardless of which
channel, STUN probe, or handshake it belongs to. Nothing in production reads
these; they exist for this harness. `packets/sec` is derived from the
packet counters over the measured `T_complete` duration.

### CPU-seconds / peak RSS (real, process-wide caveat)

`getrusage(2)` via `libc` (already a workspace dependency elsewhere —
`yadorilink-filesystem-sync`, `yadorilink-root-authority`,
`yadorilink-desktop-app`). **Caveat, load-bearing:** since both `DaemonState`
instances run in one OS process (see above), these numbers are the **sum**
of source + receiver + harness overhead, not either device alone. Real
per-device numbers need the two-process harness variant noted above.

### Disk read/write bytes — NOT YET IMPLEMENTED

No per-process disk-IO counter exists in this codebase today. Linux has
`/proc/self/io`; macOS has no equivalent `/proc`, but does expose
`proc_pid_rusage(pid, RUSAGE_INFO_V4, ...)` (`libproc`,
`ri_diskio_bytesread`/`ri_diskio_byteswritten`) via a raw syscall — real,
buildable follow-up work, not done in this slice. The alternative the task
description raises — instrumenting `FsBlockStore`'s write path directly to
self-report — is also viable and arguably more portable; either is a
bounded follow-up. The harness prints an explicit
`NOT YET IMPLEMENTED -- ...` line for both metrics rather than a fake `0`.

### fsync count — NOT YET IMPLEMENTED

Same treatment: needs instrumenting `yadorilink-local-storage`'s
`FsBlockStore` (and/or the materialization rename path) to count its own
`fsync`/`fdatasync` calls. Not done in this slice; printed as
`NOT YET IMPLEMENTED`.

### iperf3 / fio ceiling — checked, neither installed

`which iperf3 fio` on this machine: **neither found.** `src/ceiling.rs`
detects both at runtime and reports honestly either way — a machine that has
them gets a "found, but not wired into this scenario yet" message (the
actual ceiling run — a loopback `iperf3 -s`/`-c` pair, a representative
`fio` job against the block-store disk — is real follow-up work), not a
silent skip.

## A real bug this harness's own development surfaced

Building L1 caught a genuine, reproducible convergence bug -- exactly what
M6-0 exists to make visible. The first working version of `write_large_file`
wrote its random content directly to the watched path in 8MB chunks. On
macOS (FSEvents), the real filesystem watcher sometimes observed and
captured an intermediate, still-being-written revision of the file mid-write.
That revision indexes and content-defined-chunks differently from the final
one; the receiver then requested blocks by a stale revision's hashes, which
the source's now-current `FileRecord` no longer referenced. The source
answered `DontHave` (correctly, by its own logic — see
`handle_block_request`'s "not referenced by the requested file record"
check), the requester's bounded `NOT_FOUND_RETRY_ATTEMPTS` retry exhausted
against the same stale hash (nothing ever re-announced it), and the transfer
stalled **permanently** — confirmed by instrumenting a run and watching it
sit idle for 8+ minutes past its last retry with no further activity, not
merely slow convergence. `crates/yadorilink-bench/src/scenarios/l1.rs`'s
`write_large_file` now writes to a sibling temp path and renames atomically
into place, which resolved it (a real 8MB run converges in ~3 seconds — see
the sample output in the crate's own module docs / this repo's PR
description). Whether large **real-world** writes that legitimately grow a
watched file in place over several seconds (a browser download, an archive
extractor) can hit the same permanent stall in production is now an open
question this harness's own development turned up, not something this
slice attempts to fix in `yadorilink-peer-session`/`yadorilink-filesystem-sync`
-- flagging it here as the concrete, actionable finding for whoever picks up
transport-layer M6 optimization work next.

## Extension points for the remaining 9 scenarios

- `scenario::Scenario` (async trait: `id()`, `run(&RunOptions) -> Result<ScenarioReport>`)
  is the one thing every scenario implements. `scenario::ALL_SCENARIO_IDS`
  is the fixed roster (`L1..O2`) `main.rs`'s `list`/dispatch walks; adding a
  scenario is "implement `Scenario`, add a match arm in `main.rs`", not a
  redesign.
- `metrics::ScenarioReport`/`Metric` (`Duration`/`Bytes`/`Count`/`Rate`/
  `NotImplemented`) is scenario-agnostic; every scenario constructs one.
- `metrics::WireSnapshot` and `rusage::snapshot()` are reusable as-is by
  every scenario that needs wire/CPU/RSS deltas.
- `harness::{new_device, start_link_watch, pair_devices}` covers L1/D1/O1/O2
  (two peers) as-is; **M1** (3 sources → 1 receiver) needs a `pair_devices`
  generalization to N peers — a bounded extension, not a rewrite, since
  `spawn_paired_session` is already per-pairing. **S1/S2** (many small
  files) need `RunOptions` to grow a file-count/size-distribution field
  instead of (or alongside) `file_size_bytes`, and each scenario's own
  per-file bookkeeping instead of the single-path polling this slice uses.
  **W1/W2** need the two-OS-process harness variant discussed above, plus
  actually invoking `tc netem` (or equivalent) — out of scope here twice
  over (new process model AND new scenario).

## What this slice deliberately does not do

- Only L1 has a runner. `list`/`main.rs` name all 10 ids; the other 9 return
  an explicit "on the roster but not implemented yet" error, never a silent
  fake result.
- No xtask wiring beyond the one `bench-l1` cargo alias.
- No Resilio comparison run (not installed here) and no iperf3/fio ceiling
  run (neither installed here) — both are detected and reported honestly,
  neither is invoked.
- No disk-IO or fsync instrumentation.
- No real 1GbE-shaped link (loopback only) and no multi-process harness
  variant (needed for W1/W2/M1/Resilio, not for L1's single loopback pair).

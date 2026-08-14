//! M3 Pass 1: deterministic reproducer + measurement for the known
//! "N initiators -> 1 receiving `TransportHub`" handshake fan-in problem
//! (see `yadorilink-daemon/tests/reconnect_handshake_stress.rs`'s own doc
//! comment, which discovered this gap and explicitly deferred a dedicated
//! `TransportHub`-level reproducer to a follow-up -- this file is that
//! follow-up).
//!
//! This file's job is measurement, not a fix -- it makes no PRODUCTION
//! BEHAVIOR change (the one `transport_hub.rs` edit this pass made is a
//! log-only `tracing::debug!` on an already-silent `try_send` drop path,
//! never touched otherwise) and does not hard-assert that fan-in degrades
//! gracefully. It isolates the receiving side's `TransportHub`/
//! `DemuxRegistry` from everything else in the stack (`peer_orchestrator`,
//! netmap churn, reconnect supervisors, DAG/sync) that the existing
//! daemon-level test already covers, so any signal here is provably about
//! the transport layer's own fan-in behavior, not confounded by
//! higher-level retry logic.
//!
//! # Architecture under test (read `transport_hub.rs`'s own module doc
//! first for the full demux contract)
//!
//! A WireGuard handshake INITIATION carries only a sender index -- the
//! hub cannot route it to one channel by receiver index the way it routes
//! everything else, so `DemuxRegistry::offer_initiation` broadcasts every
//! MAC1-verified initiation to EVERY locally registered channel (source-IP
//! matches ordered first), and each channel's own `Tunn::decapsulate`
//! attempt is what actually determines whether it was the real recipient
//! (`tunn_wrapper.rs::handle_incoming`'s own doc comment: "an initiation is
//! offered to every channel and only the one holding the right static key
//! decapsulates it, so the others land [in `TunnResult::Err`]"). This is a
//! real, deliberate design -- there IS no other way to route an
//! initiation, since it carries no receiver index yet -- but it means
//! every incoming initiation costs one asymmetric-crypto decapsulate
//! attempt PER REGISTERED CHANNEL, not one. With N peers all reconnecting
//! toward one device near-simultaneously, that is up to N wasted
//! decapsulate attempts per initiation, for N initiations arriving close
//! together -- an O(N^2) crypto cost hypothesis this file exists to
//! confirm or refute with real measurement, not just read the code and
//! guess.
//!
//! # What this measures
//!
//! For each fan-in size N in `FAN_IN_SIZES`: one receiving device
//! registers N channels (one per initiator) on a single shared
//! `TransportHub`; N independent initiator devices, each with its own
//! socket/hub, start their handshake toward the receiver at (as close to)
//! the same instant as a `std::sync::Barrier` can make them. Recorded per
//! N:
//! - wall-clock time from the barrier release to each receiver-side
//!   channel reaching `PeerReachability::Connected` (or "did not connect
//!   within the per-N budget"), observed change-driven via
//!   `PeerChannel::reachability_watch` (not polled -- see the "review
//!   history" section below for why an earlier version's 20ms polling
//!   both quantized small-N timing and, worse, measured receiver channels
//!   SEQUENTIALLY, inflating whichever channel happened to be checked
//!   last)
//! - count of `"wireguard decapsulate error"` tracing events (wasted
//!   attempts) and the new-this-pass `"channel demux queue full"` drop
//!   events -- both are EXISTING/minimal production log lines, not new
//!   hot-path work; see "review history" for why this can't be made
//!   perfectly zero-cost and why that's fine for this reproducer's actual
//!   claims
//!
//! Printed as a table at the end (`--nocapture` to see it) for a human
//! (or a Codex review) to read the actual scaling, not just this file's
//! own interpretation of it.
//!
//! This file makes exactly one hard assertion: N=1 (no fan-in at all)
//! must connect within a short, generous bound -- a sanity check that the
//! reproducer harness itself works, not a claim about fan-in behavior.
//! Every larger N is measured and reported, never asserted on, since
//! Pass 1's own charter is "explain the cause", not "fix it" -- asserting
//! a tight bound here would either be red before Pass 2 lands a fix (the
//! wrong signal for an explicitly measurement-only pass) or force loosening
//! it later in a way that could mask a regression.
//!
//! # Review history (a Codex review of this file's first version)
//!
//! - **Runtime flavor**: `#[tokio::test]`'s default `current_thread`
//!   flavor puts the test fn, every initiator task, every receiver-side
//!   `PeerChannel`/`TransportHub` actor task, and this file's own
//!   tracing-capture callbacks on ONE OS thread -- genuinely concurrent
//!   (interleaved) but never truly PARALLEL, which cannot exercise the
//!   same cross-core crypto contention a real multi-core daemon would see
//!   under fan-in. Fixed: `#[tokio::test(flavor = "multi_thread",
//!   worker_threads = 8)]` below.
//! - **Thread-local capture breaks under multi-thread**: the first
//!   version's `tracing::subscriber::set_default` is thread-local, so
//!   switching to a real multi-thread runtime would silently stop
//!   counting events happening on other worker threads with no failure
//!   signal at all. Fixed: a single `tracing::subscriber::set_global_
//!   default` installed once for the whole test binary (composing the
//!   counting layer with an `fmt` layer, replacing the separate `fmt`
//!   `try_init()` call the first version had), which is genuinely
//!   process-wide.
//! - **Sequential receiver-side polling inflated later channels'
//!   measured latency**: the first version checked each receiver channel
//!   ONE AT A TIME in a loop, so a channel checked late could already have
//!   connected well before the loop reached it, but was recorded as
//!   connecting only when the loop got there. Fixed: every channel (both
//!   initiator- and receiver-side) is now watched CONCURRENTLY via
//!   `reachability_watch()` + `tokio::time::timeout`, each in its own
//!   `tokio::spawn`ed task, removing both the sequential-measurement
//!   distortion and the 20ms polling quantization together.
//! - **Loopback source-IP fidelity (NOT fixed, documented instead)**:
//!   every initiator binds to `127.0.0.1` with only the port differing,
//!   so `offer_initiation`'s source-IP-match ordering (`transport_hub.rs`'s
//!   own doc comment) never actually gets a chance to prefer the right
//!   channel by source IP here -- every registered channel matches every
//!   initiator's source IP identically, so the offering order this
//!   reproducer exercises is effectively unordered (map-iteration-order),
//!   not "correct peer first". A first attempt at fixing this by binding
//!   each initiator to a distinct `127.0.0.{2..}` address failed outright
//!   on macOS (`AddrNotAvailable` -- unlike Linux, macOS does not treat
//!   the whole `127.0.0.0/8` range as bound-able loopback without an
//!   explicit `ifconfig lo0 alias` first, and this repo's CI runs macOS
//!   too), so this reproducer accepts the gap rather than add
//!   platform-conditional test setup for it: what this file measures is
//!   still the real fan-out-to-every-channel cost regardless of ordering
//!   (every channel still gets offered every initiation, whichever order
//!   they're offered in), just not specifically the "does source-IP
//!   ordering help" question -- a distinct, narrower follow-up if that
//!   ever needs its own answer.
//! - **Measurement overhead is not fully isolated from what's measured**:
//!   the counting layer's own work (a `String` format + substring match +
//!   atomic increment per captured event) executes on the same runtime as
//!   the crypto work it's counting, so the reported wall-clock numbers
//!   include some measurement cost layered on top of real cost. This
//!   file does NOT attempt to run a separate uninstrumented control pass
//!   to fully isolate the two: the observed effect (single-digit
//!   milliseconds at N=1 vs. multi-SECOND, sometimes 16+ second stalls at
//!   N=10/20) is many orders of magnitude larger than what a handful of
//!   microseconds-scale string-formatting calls per event could plausibly
//!   contribute, even at the thousands-of-events counts observed -- the
//!   qualitative scaling signal this file exists to demonstrate does not
//!   depend on sub-millisecond measurement precision.
//! - **Cannot distinguish crypto contention from queue-overflow drops**:
//!   the first version could only count wasted decapsulate attempts, not
//!   whether `DEMUX_QUEUE_DEPTH`'s bounded per-channel queues (256 slots)
//!   were ALSO overflowing and silently dropping datagrams -- a real gap,
//!   since "purely CPU-bound crypto contention" was an unsupported
//!   conclusion without that data. Fixed: `transport_hub.rs`'s two
//!   `try_send` call sites (previously silently discarding a full-queue
//!   drop with no signal at all -- a genuine pre-existing observability
//!   gap, not something this reproducer introduced) now each log a
//!   `tracing::debug!` on drop; this file counts those too and reports
//!   them separately from wasted-but-delivered decapsulate attempts.
//!
//! # M3 Pass 2 update: this is no longer measurement-only
//!
//! A correction from the user, made while scoping Pass 2, changed this
//! file's own job: bounding CONCURRENCY (a queue + worker pool) alone
//! would only spread the SAME O(N^2) crypto cost across workers, not
//! eliminate it -- WireGuard's Noise IK handshake message-1 encrypts the
//! initiator's static public key using a key the RESPONDER can derive
//! from ONLY its own static private key plus the message's own (already
//! plaintext) ephemeral public key, so identifying the real sender is
//! possible in O(1) crypto work per initiation, REGARDLESS of how many
//! peers are registered -- no need to trial-decrypt against every
//! registered channel's own key. `boringtun` already exposes exactly
//! this seam (`noise::handshake::parse_handshake_anon`), and its own
//! `device` module uses precisely this pattern for its reference
//! multi-peer demux. `transport_hub.rs`'s `identify_and_route_
//! initiation` (M3 Pass 2) now uses it: resolve the sender once, one
//! hash-map lookup, dispatch to exactly the one matching channel.
//!
//! This file now runs the SAME scaling sweep in two modes and reports
//! them side by side as the before/after KPI this correction asked for:
//! - `IdentityMode::Fallback`: the receiver never calls
//!   `TransportHub::set_device_identity` -- the ORIGINAL, pre-Pass-2
//!   broadcast-to-every-channel behavior this file's first version
//!   measured, kept as the "before" baseline (also still real production
//!   behavior for the rare caller that never provides a device identity).
//! - `IdentityMode::Resolved`: the receiver DOES call `set_device_
//!   identity` -- the fixed path. Hard-asserted here (unlike Fallback,
//!   and unlike this file's original Pass-1-only measurement stance):
//!   wasted decapsulate attempts must not scale with N, and N=20 must
//!   not reproduce the multi-second crypto collapse Pass 1 measured.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::sync::watch;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::Layer;
use yadorilink_transport::{PeerChannel, PeerReachability, TransportHub};

/// Deliberately small and mid and larger, matching the user's own named
/// scenarios (`1→1, 2→1, 5→1, 10→1, 20→1`).
const FAN_IN_SIZES: &[usize] = &[1, 2, 5, 10, 20];

/// How long to wait for a single connection with no fan-in (N=1) --
/// generous for a loopback UDP handshake, tight enough that a genuine
/// hang still fails the sanity check.
const N1_SANITY_BUDGET: Duration = Duration::from_secs(5);

/// How long to wait for EACH channel to connect at larger N before giving
/// up on it and recording "did not connect" -- generous, since observing
/// a slow/failing case is the point, not racing it.
const PER_N_BUDGET: Duration = Duration::from_secs(30);

fn gen_keypair() -> (StaticSecret, PublicKey) {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    let secret = StaticSecret::from(bytes);
    let public = PublicKey::from(&secret);
    (secret, public)
}

/// Counts two EXISTING (this pass's own log-only additions notwithstanding)
/// tracing events by substring match on their message: wasted decapsulate
/// attempts (`tunn_wrapper.rs`) and demux queue-full drops
/// (`transport_hub.rs`, added this pass, log-only). No new hot-path
/// computation was added anywhere these events originate from -- this
/// layer only observes what production code already logs.
#[derive(Default)]
struct EventCounters {
    decapsulate_errors: AtomicUsize,
    queue_full_drops: AtomicUsize,
}

struct CountingLayer(Arc<EventCounters>);

#[derive(Default)]
struct MessageVisitor {
    message: String,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        }
    }
}

impl<S: Subscriber> Layer<S> for CountingLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        if visitor.message.contains("wireguard decapsulate error") {
            self.0.decapsulate_errors.fetch_add(1, Ordering::Relaxed);
        } else if visitor.message.contains("demux queue full") {
            self.0.queue_full_drops.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn on_new_span(&self, _attrs: &Attributes<'_>, _id: &Id, _ctx: Context<'_, S>) {}
    fn on_record(&self, _id: &Id, _values: &Record<'_>, _ctx: Context<'_, S>) {}
}

/// Per-channel outcome for one fan-in run.
#[derive(Debug, Clone)]
enum ConnectOutcome {
    Connected(Duration),
    TimedOut,
}

/// M3 Pass 2: which handshake-identification path the receiver in one
/// `run_fan_in` call exercises -- see this file's own top-level "M3 Pass
/// 2 update" section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdentityMode {
    /// The original broadcast-to-every-channel path (no device identity
    /// provided to the receiver's hub).
    Fallback,
    /// The O(1) identify-then-dispatch path.
    Resolved,
}

/// Awaits `rx` reaching `Connected`, relative to `start`, bounded by
/// `deadline` -- change-driven via `watch::Receiver::wait_for`, not
/// polled, so this has no fixed granularity to quantize small timings and
/// no ordering dependency on when a caller happens to check it (unlike
/// this file's first version's sequential polling loop -- see the
/// top-level "review history" section).
async fn wait_connected(
    mut rx: watch::Receiver<PeerReachability>,
    start: Instant,
    deadline: Instant,
) -> ConnectOutcome {
    let remaining = deadline.saturating_duration_since(Instant::now());
    let result = tokio::time::timeout(
        remaining,
        rx.wait_for(|r| matches!(r, PeerReachability::Connected { .. })),
    )
    .await;
    match result {
        Ok(Ok(_)) => ConnectOutcome::Connected(Instant::now() - start),
        _ => ConnectOutcome::TimedOut,
    }
}

/// Runs one fan-in size: N initiators against 1 receiver, sharing a
/// single receiving `TransportHub` registered with N channels ahead of
/// time (matching how a real device's netmap-driven channel set is
/// already registered before any of N peers happens to reconnect at
/// once -- this reproducer does not model the ALSO-real cold-registration
/// race, deliberately, to isolate fan-in from that separate concern).
async fn run_fan_in(
    n: usize,
    budget: Duration,
    counters: &Arc<EventCounters>,
    mode: IdentityMode,
) -> Vec<ConnectOutcome> {
    let receiver_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (receiver_secret, receiver_public) = gen_keypair();
    let receiver_hub = TransportHub::from_socket(receiver_socket, Some(receiver_public));
    if mode == IdentityMode::Resolved {
        receiver_hub.set_device_identity(receiver_secret.clone());
    }

    // Bind every initiator's socket FIRST so the receiver can register
    // each channel with that initiator's real candidate address. All on
    // `127.0.0.1` (only the port differs) -- see this file's own top-level
    // "review history" section for why per-initiator source-IP diversity
    // was attempted and reverted (macOS does not support binding
    // `127.0.0.{2..}` without host configuration this test cannot assume).
    let mut initiator_secrets = Vec::with_capacity(n);
    let mut initiator_sockets = Vec::with_capacity(n);
    let mut initiator_addrs = Vec::with_capacity(n);
    for _ in 0..n {
        let (secret, public) = gen_keypair();
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        initiator_secrets.push((secret, public));
        initiator_sockets.push(socket);
        initiator_addrs.push(addr);
    }

    let mut receiver_channels = Vec::with_capacity(n);
    let mut receiver_watches = Vec::with_capacity(n);
    for (i, (_, initiator_public)) in initiator_secrets.iter().enumerate() {
        let channel = PeerChannel::connect(
            receiver_secret.clone(),
            *initiator_public,
            i as u32,
            vec![initiator_addrs[i]],
            receiver_hub.clone(),
        )
        .await
        .unwrap();
        receiver_watches.push(channel.reachability_watch());
        // Kept alive in this Vec for the whole function (dropping tears
        // down the session) -- dropped naturally at the end, unlike the
        // first version's `std::mem::forget` (a real leak: the channel's
        // background actor task and socket registration would never be
        // cleaned up for the rest of this test process's lifetime).
        receiver_channels.push(channel);
    }
    let receiver_addr = receiver_hub.local_addr();

    // `Barrier::wait` releases every initiator task at (as close to) the
    // same instant as the runtime's scheduler allows -- tighter
    // simultaneity than the first version's "spawn in a loop, don't await
    // any of them yet" approach, and independent of how many OS threads
    // the runtime actually has.
    let barrier = Arc::new(tokio::sync::Barrier::new(n + 1));
    let mut initiator_handles = Vec::with_capacity(n);
    for (i, (secret, _)) in initiator_secrets.into_iter().enumerate() {
        let socket = initiator_sockets.remove(0);
        let barrier = barrier.clone();
        initiator_handles.push(tokio::spawn(async move {
            let hub = TransportHub::from_socket(socket, None);
            barrier.wait().await;
            let channel = PeerChannel::connect(
                secret,
                receiver_public,
                (1000 + i) as u32,
                vec![receiver_addr],
                hub,
            )
            .await
            .unwrap();
            let mut rx = channel.reachability_watch();
            let deadline = Instant::now() + PER_N_BUDGET;
            let _ = tokio::time::timeout(
                deadline.saturating_duration_since(Instant::now()),
                rx.wait_for(|r| matches!(r, PeerReachability::Connected { .. })),
            )
            .await;
            // Keep the initiator's own channel alive for the duration of
            // this run -- dropping it would tear down its session and
            // could itself look like a "connection lost" event on the
            // receiver side, confounding the measurement.
            channel
        }));
    }

    // Captured BEFORE this task's own `barrier.wait()` call, not after --
    // a Codex-review finding on an earlier version: capturing `start`
    // AFTER the wait returns races the N initiator tasks, which run on
    // OTHER worker threads under this file's multi-thread runtime and can
    // resume (and for a very fast local handshake, even finish) before
    // THIS task's own await point resumes -- biasing every reported
    // duration downward by an unmeasured amount. The main task is always
    // the LAST arrival at this barrier (every initiator only does cheap
    // socket-bind/hub-construction setup before its own `barrier.wait()`,
    // all of which already happened above), so capturing here instead
    // measures very slightly EARLY (this task's own brief wait for the
    // last initiator to arrive) rather than late -- the safe direction:
    // it can only overstate latency by a small, bounded amount, never
    // understate it by an unbounded one.
    let start = Instant::now();
    barrier.wait().await;
    let deadline = start + budget;

    let outcome_handles: Vec<_> = receiver_watches
        .into_iter()
        .map(|rx| tokio::spawn(wait_connected(rx, start, deadline)))
        .collect();
    let mut outcomes = Vec::with_capacity(n);
    for handle in outcome_handles {
        outcomes.push(handle.await.unwrap());
    }

    for (i, handle) in initiator_handles.into_iter().enumerate() {
        if let Err(e) = handle.await {
            // A Codex-review finding: silently discarding this let an
            // initiator's own panic (a real bug, not just "didn't
            // connect in time") manifest ONLY as a receiver-side timeout
            // -- indistinguishable from genuine fan-in degradation.
            panic!("initiator {i} task failed: {e}");
        }
    }
    let _ = counters; // counted via the process-wide subscriber, not passed data
    outcomes
}

fn summarize(outcomes: &[ConnectOutcome]) -> String {
    let connected: Vec<Duration> = outcomes
        .iter()
        .filter_map(|o| match o {
            ConnectOutcome::Connected(d) => Some(*d),
            ConnectOutcome::TimedOut => None,
        })
        .collect();
    let timed_out = outcomes.len() - connected.len();
    if connected.is_empty() {
        return format!("0/{} connected, {timed_out} timed out", outcomes.len());
    }
    let min = connected.iter().min().unwrap();
    let max = connected.iter().max().unwrap();
    let mean_ms: u128 =
        connected.iter().map(|d| d.as_millis()).sum::<u128>() / connected.len() as u128;
    format!(
        "{}/{} connected (min {min:?}, mean {mean_ms}ms, max {max:?}), {timed_out} timed out",
        connected.len(),
        outcomes.len()
    )
}

type Report = BTreeMap<usize, (Vec<ConnectOutcome>, usize, usize)>;

/// Between iterations, gives the PREVIOUS iteration's `TransportHub`
/// instances time to actually finish tearing down before the next
/// iteration resets the shared event counters -- a real bug this file's
/// own flakiness surfaced (not a production bug): `TransportHub::drop`
/// calls `task.abort()` on its receive-loop and handshake-worker tasks,
/// but `abort()` only takes effect at that task's NEXT `.await` point,
/// not synchronously. A task that's mid-decapsulate (CPU-bound, no
/// `.await` inside that single call) when aborted still finishes that
/// one unit of work -- including logging a "wireguard decapsulate
/// error" event -- before actually stopping. Without this delay, a
/// still-finishing task from run N's teardown could log an event that
/// lands AFTER run N+1's `counters.store(0)` reset, spuriously inflating
/// N+1's count with N's leftover activity (observed empirically: an
/// otherwise-clean N=1 run occasionally showed 100+ "wasted" attempts
/// that were really N=20's prior teardown bleeding through).
const ITERATION_SETTLE_DELAY: Duration = Duration::from_millis(200);

async fn run_sweep(mode: IdentityMode, counters: &Arc<EventCounters>) -> Report {
    let mut report = Report::new();
    for &n in FAN_IN_SIZES {
        let budget = if n == 1 { N1_SANITY_BUDGET } else { PER_N_BUDGET };
        tokio::time::sleep(ITERATION_SETTLE_DELAY).await;
        counters.decapsulate_errors.store(0, Ordering::Relaxed);
        counters.queue_full_drops.store(0, Ordering::Relaxed);
        let outcomes = run_fan_in(n, budget, counters, mode).await;
        let decap_errors = counters.decapsulate_errors.load(Ordering::Relaxed);
        let queue_drops = counters.queue_full_drops.load(Ordering::Relaxed);
        report.insert(n, (outcomes, decap_errors, queue_drops));
    }
    report
}

fn print_report(label: &str, report: &Report) {
    println!("\n=== handshake fan-in scaling report: {label} ===");
    println!(
        "{:>4}  {:>50}  {:>12}  {:>12}",
        "N", "connect outcomes", "decap errors", "queue drops"
    );
    for (&n, (outcomes, decap_errors, queue_drops)) in report {
        println!("{n:>4}  {:>50}  {decap_errors:>12}  {queue_drops:>12}", summarize(outcomes));
    }
    println!("========================================\n");
}

/// The reproducer: runs the same fan-in scaling sweep in both
/// [`IdentityMode`]s and prints them side by side as a before/after
/// comparison (see this file's own top-level "M3 Pass 2 update" section).
/// `Fallback` is measured and reported only (matching Pass 1's original
/// "explain, don't assert" stance -- it's still real, if now-uncommon,
/// production behavior). `Resolved` is hard-asserted: the whole point of
/// Pass 2 is that this mode must not reproduce Pass 1's O(N^2) collapse.
///
/// `multi_thread`/`worker_threads = 8`: a real multi-core execution
/// model, not the single-OS-thread cooperative scheduling
/// `#[tokio::test]`'s default `current_thread` flavor would give every
/// task here -- see this file's own "review history" section.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn handshake_fan_in_scaling_report() {
    // A single, PROCESS-WIDE subscriber (not thread-local `set_default`,
    // which would silently miss events on other worker threads under the
    // multi-thread runtime above) composing the counting layer with an
    // `fmt` layer, so `RUST_LOG`-gated output still works exactly like
    // every other test in this repo's convention.
    let counters = Arc::new(EventCounters::default());
    let subscriber = tracing_subscriber::registry().with(CountingLayer(counters.clone())).with(
        tracing_subscriber::fmt::layer()
            .with_filter(tracing_subscriber::EnvFilter::from_default_env()),
    );
    // A Codex-review finding: discarding this `Result` let a failed
    // install (this process already has a global subscriber -- e.g. two
    // `#[tokio::test]` fns in the same binary racing to install one) fail
    // SILENTLY, producing a misleadingly clean report (zero counted
    // events looks identical to "no problem" and to "the counter never
    // actually saw anything"). This file has exactly one test fn, so this
    // should never actually fail in practice -- failing loudly rather
    // than silently is strictly safer.
    tracing::subscriber::set_global_default(subscriber)
        .expect("no other global tracing subscriber must already be installed in this process");

    let fallback_report = run_sweep(IdentityMode::Fallback, &counters).await;
    let resolved_report = run_sweep(IdentityMode::Resolved, &counters).await;

    print_report("Fallback (pre-Pass-2 broadcast, before)", &fallback_report);
    print_report("Resolved (Pass 2 O(1) identification, after)", &resolved_report);

    let (n1_outcomes, ..) = &resolved_report[&1];
    assert!(
        matches!(n1_outcomes[0], ConnectOutcome::Connected(_)),
        "sanity check failed: N=1 (no fan-in at all) did not connect within {N1_SANITY_BUDGET:?} \
         in Resolved mode -- the reproducer harness itself is broken, not merely observing fan-in \
         degradation"
    );

    // The core M3 Pass 2 exit criterion: wasted decapsulate attempts must
    // not SCALE WITH N -- a flat ceiling, deliberately not multiplied by
    // `n` (a per-N-scaled bound like `n * 2` would itself imply some
    // scaling is expected, which is exactly what this pass exists to
    // rule out). In Resolved mode there is no trial-decryption against
    // the wrong channel at all, so observed counts stay in the low tens
    // regardless of N in practice; this ceiling is generous headroom
    // above that. The "wireguard decapsulate error" event this counts
    // (see `tunn_wrapper.rs::handle_incoming`) is not exclusively a
    // fan-in signal -- WireGuard's own handshake retransmission (an
    // initiator resending its own init packet before it sees a response,
    // then that duplicate hitting an already-established session) also
    // lands here, and happens occasionally regardless of N, including at
    // N=1 -- observed empirically across repeated runs, not merely
    // theorized, which is why this is a generous flat ceiling rather
    // than a tight one.
    const MAX_WASTED_DECAPSULATE_ATTEMPTS_RESOLVED: usize = 60;
    for (&n, (outcomes, decap_errors, _queue_drops)) in &resolved_report {
        assert!(
            *decap_errors <= MAX_WASTED_DECAPSULATE_ATTEMPTS_RESOLVED,
            "N={n}: {decap_errors} wasted decapsulate attempts in Resolved mode -- expected \
             O(1)-per-initiation identification to keep this flat and bounded independent of N, \
             not scaling like the pre-Pass-2 O(N^2) broadcast path"
        );
        // A second, RELATIVE check at the two N values where Pass 1
        // measured the real O(N^2) collapse (hundreds of wasted attempts
        // under Fallback) -- Resolved must be dramatically smaller at the
        // SAME N, not merely under the flat ceiling above (which alone
        // couldn't distinguish "the fix genuinely worked" from "this run
        // just happened to land under an arbitrary constant").
        if n >= 10 {
            let fallback_decap_errors = fallback_report[&n].1;
            assert!(
                *decap_errors * 4 < fallback_decap_errors,
                "N={n}: Resolved mode's {decap_errors} wasted decapsulate attempts is not \
                 dramatically smaller than Fallback mode's {fallback_decap_errors} at the same \
                 N -- the O(1) identification path may not actually be taking effect"
            );
        }

        for outcome in outcomes {
            if let ConnectOutcome::Connected(d) = outcome {
                assert!(
                    *d < Duration::from_secs(2),
                    "N={n}: a channel took {d:?} to connect in Resolved mode -- Pass 1 measured \
                     multi-second (up to ~16s) stalls at this scale under the OLD broadcast path; \
                     Resolved mode must not reproduce that collapse"
                );
            }
        }
    }
}

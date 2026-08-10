# Storage / Connectivity / Availability Vocabulary (M0)

Fixes the four concepts the "one full copy on an always-on device, on-demand
everywhere else, that device relays when needed" product story depends on,
before any of M1-M5 touch code. No behavior changes in this document.

Symbol names, not line numbers, are the stable source of truth here — same
convention as [`data-durability-model.md`](./data-durability-model.md),
since this repo refactors line numbers away regularly. That file already
owns concept 2's safety invariants (DL-1..DL-7) in full depth; this document
places concept 2 in the four-concept frame instead of restating them, and
focuses on the three concepts that file doesn't cover.

## The contract

```text
Durability  ≠  Connectivity
```

A full replica can be perfectly durable and completely offline at the same
moment (a NAS powered down overnight). Nothing about "is my data safe" may
ever be computed from, or reported alongside, "is that device reachable
right now." These are two different questions with two different answers,
and the UI (M4) must show them as two separate rows, never one merged
status.

## 1. StorageRole — is this device Eager or OnDemand?

**Maps to:** `MaterializationPolicy` (`Eager` / `OnDemand`, per link) in
`yadorilink-replica-domain`'s `session_state` module. Set via
`DaemonState::set_storage_mode`, read back through `control_socket` and
`recovery_snapshot` (persisted as `"eager"`/`"on_demand"`).

**Status:** fully modeled — needs no new concept, only user-facing
vocabulary (`"完全コピー"` / `"容量を節約"`) and, per M1, an actual working
OnDemand runtime path (see concept 4's gap).

## 2. DurabilityStatus — is there a confirmed full copy somewhere?

**Maps to:** `GroupDurabilityStatus` (`Healthy` / `Syncing` /
`DurabilityUnknown` / `KnownMissing`) in `yadorilink-daemon`'s
`durability_service` module, computed by `DaemonState::group_durability_
status` via the pure `classify` function. The underlying safety
*mechanisms* it draws on — `data-durability-model.md`'s DL-1..DL-7 — are
strong and already shipped.

**Status: the safety mechanisms are strong; the product-facing status type
is not yet a full expression of them.** `classify`'s actual precedence is:
four "cannot currently confirm" facts (latch-load failure, unknown-scope
force, blocked recovery, a latched-unknown group) each short-circuit to
`DurabilityUnknown`; only once none apply does it fall through to `Ok(
MaterializationHealth::FullyLocal) → Healthy`. Critically, `classify`'s own
input struct carries **no `StorageRole` and no peer `HandoffReady`
confirmation at all** — `Healthy` today means "every current file is
`Hydrated` on THIS device," nothing more.

This is a real gap once M1 ships OnDemand: a `StorageRole::OnDemand`
MacBook that happens to have every file locally hydrated right now (still
mid-session, nothing evicted yet) would report `GroupDurabilityStatus::
Healthy` — but that MacBook is not a durability anchor. Every file on it
can be evicted at any time; nothing has confirmed a *durable* full copy
exists anywhere, only that THIS device's local cache is momentarily
complete. `GroupDurabilityStatus::Healthy` is not the same claim as "a full
copy exists somewhere" — conflating the two is exactly the kind of status
overstatement `classify`'s own doc comment says it must never do, and today
it can, for an OnDemand device.

**What the eventual product-level `DurabilityStatus` needs to derive from**
(strengthening `classify`, or a new view model built on top of it — either
is fine, decide in M1-M4, not M0):

```text
Protected     -- a StorageRole::Eager device (this one or a confirmed
                 peer) durably holds the current head, OR a peer's
                 HandoffReady confirmation is fresh and valid
Protecting    -- configured Eager, still catching up to head
Unknown       -- cannot currently confirm (today's DurabilityUnknown facts)
AtRisk        -- positively confirmed no durable holder exists anywhere
```

The key addition versus today's `classify`: gate `Healthy`/`Protected` on
`StorageRole::Eager` (local or peer), not on "every file happens to be
`Hydrated` right now" alone. This is flagged for M1-M4 to strengthen —
M0's job is only to name the gap precisely so it isn't rediscovered later
as a surprise.

## 3. ConnectivityAnchorStatus — is a full-replica device reachable right now to relay?

**Maps to:** nothing today. This is the one genuinely missing concept.

The closest existing type is `PeerReachability` (`Connecting` / `Connected`
/ `ProtocolIncompatible` / `Unreachable(UnreachableCategory)`) in
`yadorilink-daemon`'s `peer_registry` module, but it answers a different
question — "is THIS device's direct channel to ONE specific peer up" — not
"is there a full-replica device reachable that other peers could relay
through." There is no relay concept in the codebase at all today:
`nat_traversal`'s own module doc comment states devices connect "without an
operator-run relay," by design, as of this writing.

**ConnectivityAnchorStatus has no existing mapping. Exact state ownership
and granularity are deliberately deferred to M3-B** — a single per-device
"is this NAS online" boolean is very likely insufficient once relay routing
exists (device online ≠ every laptop can route through it; a laptop's own
NAT class, and which peers it needs to reach, both matter). M3-B should
expect to need something closer to three separable facts — a device's own
capability to act as a relay, one endpoint's reachability to that device,
and whether a specific A→anchor→B route actually completes — rather than
collapsing them into one status prematurely. That's M3-B's design problem
to solve with full context on the relay protocol; M0 intentionally does not
pre-decide it.

## 4. LocalMaterializationStatus — is this specific file present, placeholder, or hydrating on THIS device?

Named `LocalMaterializationStatus`, not `FileAvailabilityStatus` — the
latter invites scope creep toward "placeholder, but the NAS is online so
it's available right now," which is a DIFFERENT (connectivity-dependent)
question this concept must not answer. This concept is local-disk state
only.

**Maps to:** `MaterializationState` (`Hydrated` / `Placeholder` /
`Hydrating` / `Evicting`) in `yadorilink-replica-domain`'s `session_state`
module, per file. A separate boolean pin flag exists alongside it (not a
`MaterializationState` variant) — pinning forces and holds `Hydrated`,
unaffected by eviction sweeps.

**Status:** fully modeled at the domain-type level, but M1's own audit
already found the production runtime doesn't route through it for OnDemand
today: `on_demand_pipeline_is_connected()` in `yadorilink-filesystem-sync`'s
`placeholder_backend` module is unconditionally `false` in every non-test
build. Its own doc comment is explicit about why and what's missing — the
four pieces M1 lists (live provider session, placeholder generation
persistence, OS-provider dirty detection, hydrate/evict wired through
`PlaceholderBackend`) are confirmed as "none exist yet anywhere in this
codebase's runtime path." This is exactly M1's starting point, not a new
finding — M0 just confirms the type this vocabulary maps to is already
right; the gap is wiring, not modeling.

## Summary table

| Product concept | Current implementation |
|---|---|
| StorageRole | `MaterializationPolicy` ✅ |
| DurabilityStatus | safety mechanisms (DL-1..DL-7) are strong; product-facing status type is only a partial expression of them ⚠️ |
| ConnectivityAnchorStatus | missing ❌ |
| LocalMaterializationStatus | `MaterializationState` ✅ |

## What M0 does NOT close

Whether any existing status-assembly code (CLI `yadorilink status`, IPC
status responses) already mixes durability and connectivity into one field
or one screen was not exhaustively audited here. Auditing every UI/IPC call
site is M4's job, once `ConnectivityAnchorStatus` actually exists to check
against — and once `DurabilityStatus` itself is strengthened per concept 2
above, since auditing a status surface against a not-yet-accurate product
concept would just document the wrong target.

# Storage / Connectivity / Availability Vocabulary (M0)

Fixes the four concepts the "one full copy on an always-on device, on-demand
everywhere else, that device relays when needed" product story depends on,
before any of M1-M5 touch code. No behavior changes in this document — it
maps the four concepts onto what already exists, and calls out the one real
gap (concept 3) and the one real risk (keeping 2 and 3 apart going forward).

Companion to [`data-durability-model.md`](./data-durability-model.md), which
already owns concept 2 in full depth (the DL-1..DL-7 invariants). This
document does not restate that file — it places concept 2 in the four-concept
frame and focuses on the three concepts that file doesn't cover.

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

**Maps to:** `MaterializationPolicy` (`crates/yadorilink-replica-domain/src/session_state.rs:51-54`)
— `Eager` / `OnDemand`, per link. Set via `DaemonState::set_storage_mode`
(`crates/yadorilink-daemon/src/coordination_client.rs:1554` calls into it)
and read back by `control_socket.rs`/`recovery_snapshot.rs` (string form
`"eager"`/`"on_demand"`, `recovery_snapshot.rs:358`).

**Status:** fully modeled, this is what already exists and needs no new
concept — only user-facing vocabulary (`"完全コピー"` / `"容量を節約"`, per M0's
own translation table) and, per M1, an actual working OnDemand runtime path
(see gap note under concept 4).

## 2. DurabilityStatus — is there a confirmed full copy somewhere?

**Maps to:** `GroupDurabilityStatus` (`crates/yadorilink-daemon/src/durability_service.rs:37-53`)
— `Healthy` / `Syncing` / `DurabilityUnknown` / `KnownMissing`, computed by
`DaemonState::group_durability_status` (`daemon_state.rs:1319`) and the pure
`classify` function `durability_service.rs` documents as its own single
source of truth. Full depth in `data-durability-model.md`'s DL-1..DL-7.

**Status:** this is the strongest of the four concepts already. Its own doc
comment (`durability_service.rs:24-31`) already states the exact contract
this document is trying to generalize: "how safe is my data right now, from
what this daemon can currently confirm... must never overstate safety."
Notably, `classify`'s own inputs (materialization health, handoff-readiness
facts, the `DurabilityUnknown` latch) contain **no peer-reachability input at
all** — durability and connectivity are already architecturally separate at
this layer. The M0 risk is not in this type; it's in whatever assembles a
user-facing status screen from multiple sources (open question below).

## 3. ConnectivityAnchorStatus — is a full-replica device reachable right now to relay?

**Maps to:** nothing today. This is the one genuinely missing concept.

The closest existing type is `PeerReachability`
(`crates/yadorilink-daemon/src/peer_registry.rs:51-61`: `Connecting` /
`Connected` / `ProtocolIncompatible` / `Unreachable(UnreachableCategory)`),
but it answers a different question — "is THIS device's direct channel to
ONE specific peer up" — not "is there a full-replica device reachable that
other peers could relay through." There is no relay concept in the codebase
at all today: `nat_traversal.rs:3`'s own doc comment states devices connect
"without an operator-run relay," by design, as of this writing. M3-B is
where this gets built; M0 only needs the type to exist conceptually so
nothing downstream conflates "my direct connection to peer X" with "is
there *any* full-replica anchor reachable for this group."

**Open question for M3-B, not M0:** once a relay concept exists, does
`ConnectivityAnchorStatus` live per-group (an anchor for group's peer set)
or per-device (a full-replica device's own current reachability, which
consumers cross-reference against which groups it's eager for)? Recommend
the latter — it composes with `StorageRole` cleanly and avoids a second
per-group cache to keep in sync with `GroupDurabilityStatus`.

## 4. FileAvailabilityStatus — is this specific file present, placeholder, or hydrating on THIS device?

**Maps to:** `MaterializationState` (`crates/yadorilink-replica-domain/src/session_state.rs:22-27`)
— `Hydrated` / `Placeholder` / `Hydrating` / `Evicting`, per file. A separate
boolean pin flag exists alongside it (not a `MaterializationState` variant;
see the `pin_hydrates_via_multiple_peers_and_sets_the_pin_flag` test in
`multi_peer_hydration.rs` for the existing contract: pinning forces and
holds `Hydrated`, unaffected by eviction sweeps).

**Status:** fully modeled at the domain-type level, but M1's own audit
already found the production runtime doesn't route through it for OnDemand
today: `on_demand_pipeline_is_connected()`
(`crates/yadorilink-filesystem-sync/src/placeholder_backend.rs:100-106`) is
unconditionally `false` in every non-test build. Its own doc comment
(`placeholder_backend.rs:80-94`) is explicit about why and what's
missing — the four pieces M1 lists (live provider session, placeholder
generation persistence, OS-provider dirty detection, hydrate/evict wired
through `PlaceholderBackend`) are confirmed as "none exist yet anywhere in
this codebase's runtime path." This is exactly M1's starting point, not a
new finding — M0 just confirms the type this vocabulary maps to is already
right; the gap is wiring, not modeling.

## Summary table

| Concept | Type | Location | Status |
|---|---|---|---|
| StorageRole | `MaterializationPolicy` | `yadorilink-replica-domain/src/session_state.rs:51` | Modeled, needs UX vocabulary only |
| DurabilityStatus | `GroupDurabilityStatus` | `yadorilink-daemon/src/durability_service.rs:37` | Modeled in full depth (DL-1..DL-7); already separate from connectivity |
| ConnectivityAnchorStatus | *(none)* | — | Missing; build in M3-B |
| FileAvailabilityStatus | `MaterializationState` | `yadorilink-replica-domain/src/session_state.rs:22` | Modeled; production wiring missing (M1's own gap, confirmed) |

## What M0 does NOT close

Whether any existing status-assembly code (CLI `yadorilink status`, IPC
status responses) already mixes durability and connectivity into one field
or one screen was not exhaustively audited here — the daemon's own internal
*model* keeps them separate (see concept 2 above), which is the load-bearing
fact for M1-M3. Auditing every UI/IPC call site is M4's job, once
`ConnectivityAnchorStatus` actually exists to check against.

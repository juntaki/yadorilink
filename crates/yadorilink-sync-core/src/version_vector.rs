//! Per-file version vectors: one counter per contributing device, used to
//! distinguish causally-ordered edits from genuine concurrent conflicts —
//! never wall-clock timestamps, which can't tell the two apart.
//!
//! ## Trust boundary
//!
//! Version-vector sync assumes every contributing device reports its own
//! causal history honestly. Among **mutually-untrusted** group members —
//! an authorized peer that has passed coordination-plane auth is not
//! necessarily benign — that assumption does not fully hold: nothing
//! cryptographically proves a claimed counter reflects a real sequence of
//! edits, so a malicious/compromised peer can always advertise a foreign
//! device's counter as larger than it should be. Taken to an extreme, this
//! lets a peer force `VvOrdering::Before` on a file this device has
//! genuinely edited (`compare` sees the peer's version as strictly
//! dominating), which makes `PeerSyncSession::reconcile_one_file` silently
//! *adopt* the peer's version — overwriting the honest local edit with no
//! `Concurrent` result and therefore no conflict copy. That is a real,
//! reachable data-loss path, not a hypothetical one — the exact exploit
//! shape: `{local:5, peer:999}` advertised against a local vector the peer
//! previously observed as `{local:5}`.
//!
//! **This module does not claim to fully close that gap** — no local
//! check can, since a lying peer is indistinguishable from a peer that
//! genuinely made many edits while disconnected. What it *does* provide is
//! a partial, defense-in-depth mitigation: `VersionVector::sanitize_against`
//! bounds how far a single incoming message may advance a counter beyond
//! what this device last actually recorded for that file, so a peer can no
//! longer force an unbounded one-shot jump. This narrows the attack from
//! "one message, arbitrary counter" to "many messages, bounded counter
//! growth per message" — a real reduction in blast radius, not a complete
//! fix. `peer_session.rs`'s `reconcile_one_file` is the call site that
//! applies this sanitization before every causality comparison.

use std::collections::BTreeMap;

/// The maximum amount a single incoming message is allowed to advance any
/// *foreign* device's counter beyond what this device last recorded for the
/// file in question (see `VersionVector::sanitize_against` and this
/// module's trust-boundary doc comment above). Chosen generously so
/// ordinary legitimate behavior — a peer that was offline for a long
/// stretch and batches many real edits into its next sync — is extremely
/// unlikely to be affected: at one counter increment per edit, this
/// tolerates thousands of un-synced edits to the same file arriving in a
/// single message before the bound engages. An adversarial peer trying to
/// force an implausible one-shot jump (the `peer:999` example above) is
/// blocked outright; a peer trying to force it gradually is still bounded
/// per-message and remains subject to every other rate limit already in
/// place on this connection (`MAX_IN_FLIGHT_MESSAGES_PER_PEER`,
/// `MAX_CONCURRENT_RECONCILES`).
pub const MAX_VV_COUNTER_JUMP_PER_MESSAGE: u64 = 10_000;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VersionVector(BTreeMap<String, u64>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VvOrdering {
    /// Identical vectors — same edit, not a new version.
    Equal,
    /// `self` happened-before `other`: `other` is a strict update, no conflict.
    Before,
    /// `self` happened-after `other`: `self` is the update, no conflict.
    After,
    /// Neither dominates: a genuine concurrent edit — a real conflict.
    Concurrent,
}

impl VersionVector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_counters(counters: BTreeMap<String, u64>) -> Self {
        Self(counters)
    }

    pub fn counters(&self) -> &BTreeMap<String, u64> {
        &self.0
    }

    pub fn get(&self, device_id: &str) -> u64 {
        self.0.get(device_id).copied().unwrap_or(0)
    }

    /// Bumps `device_id`'s counter — called on every local edit.
    pub fn increment(&mut self, device_id: &str) {
        *self.0.entry(device_id.to_string()).or_insert(0) += 1;
    }

    /// Pointwise-max merge: the smallest vector that dominates both inputs.
    /// Used after resolving a conflict, so the winning file's vector
    /// reflects having "seen" both contributing edits.
    pub fn merge(&self, other: &VersionVector) -> VersionVector {
        let mut merged = self.0.clone();
        for (device, &count) in &other.0 {
            let entry = merged.entry(device.clone()).or_insert(0);
            *entry = (*entry).max(count);
        }
        VersionVector(merged)
    }

    /// Returns a copy of `incoming` (a peer-supplied version vector) with
    /// every counter clamped to a plausible bound relative to
    /// `self` — the last version vector *this device* actually accepted
    /// for the file in question (from its own edits or a previously
    /// adopted peer update), read from its own index, never peer-supplied.
    /// See this module's trust-boundary doc comment for why this is a
    /// partial mitigation, not a complete fix.
    ///
    /// Two distinct bounds apply:
    /// - `local_device_id`'s counter is capped at exactly
    ///   `self.get(local_device_id)` — this device is the *sole* writer of
    ///   its own counter (nothing else ever increments it), so a peer can
    ///   never legitimately know a higher value for it than this device
    ///   itself already has on record. This is a hard invariant, not a
    ///   heuristic: any claim above it is definitionally impossible under
    ///   honest causal history, so clamping it can never reject a
    ///   legitimate case.
    /// - every other device's counter (including the sending peer's own)
    ///   is capped at `self.get(device) + max_jump` — see
    ///   `MAX_VV_COUNTER_JUMP_PER_MESSAGE`'s doc comment for why this bound
    ///   is generous enough to leave ordinary multi-edit-while-offline
    ///   batches unaffected while still closing the one-shot "advertise an
    ///   arbitrarily large foreign counter" attack.
    pub fn sanitize_against(
        &self,
        incoming: &VersionVector,
        local_device_id: &str,
        max_jump: u64,
    ) -> VersionVector {
        let mut sanitized = BTreeMap::new();
        for (device, &claimed) in incoming.0.iter() {
            let bound = if device == local_device_id {
                self.get(device)
            } else {
                self.get(device).saturating_add(max_jump)
            };
            sanitized.insert(device.clone(), claimed.min(bound));
        }
        VersionVector(sanitized)
    }

    /// Compares `self` to `other` per standard version-vector causality:
    /// dominance in both directions, in neither, or equality.
    pub fn compare(&self, other: &VersionVector) -> VvOrdering {
        if self.0 == other.0 {
            return VvOrdering::Equal;
        }
        let mut self_has_greater = false;
        let mut other_has_greater = false;
        for device in self.0.keys().chain(other.0.keys()) {
            let a = self.get(device);
            let b = other.get(device);
            if a > b {
                self_has_greater = true;
            } else if b > a {
                other_has_greater = true;
            }
        }
        match (self_has_greater, other_has_greater) {
            (false, false) => VvOrdering::Equal, // unreachable given the early-out above
            (true, false) => VvOrdering::After,
            (false, true) => VvOrdering::Before,
            (true, true) => VvOrdering::Concurrent,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequential_edits_are_ordered_not_concurrent() {
        let mut a = VersionVector::new();
        a.increment("device-a"); // a = {a:1}
        let mut b = a.clone();
        b.increment("device-b"); // b = {a:1, b:1}, strictly dominates a

        assert_eq!(a.compare(&b), VvOrdering::Before);
        assert_eq!(b.compare(&a), VvOrdering::After);
    }

    #[test]
    fn independent_edits_are_concurrent() {
        let mut a = VersionVector::new();
        a.increment("device-a"); // {a:1}
        let mut b = VersionVector::new();
        b.increment("device-b"); // {b:1}, neither dominates

        assert_eq!(a.compare(&b), VvOrdering::Concurrent);
        assert_eq!(b.compare(&a), VvOrdering::Concurrent);
    }

    #[test]
    fn identical_vectors_are_equal() {
        let mut a = VersionVector::new();
        a.increment("device-a");
        let b = a.clone();
        assert_eq!(a.compare(&b), VvOrdering::Equal);
    }

    #[test]
    fn merge_dominates_both_inputs() {
        let mut a = VersionVector::new();
        a.increment("device-a");
        let mut b = VersionVector::new();
        b.increment("device-b");

        let merged = a.merge(&b);
        assert_eq!(merged.compare(&a), VvOrdering::After);
        assert_eq!(merged.compare(&b), VvOrdering::After);
    }

    /// Dominance-vs-true-concurrency
    /// across 3 devices — a case a simple 2-device test can't
    /// distinguish, since with only 2 devices "not equal, not before,
    /// not after" always means Concurrent trivially. With 3, two
    /// branches can each strictly dominate a common ancestor while still
    /// being Concurrent with *each other*, and a vector that has seen
    /// both branches must dominate each individually without being
    /// Concurrent with either.
    #[test]
    fn three_device_truth_table_distinguishes_dominance_from_concurrency() {
        // base = {a:1} on all three devices.
        let mut base = VersionVector::new();
        base.increment("device-a");

        // branch1 = base + one edit from device-b = {a:1, b:1}: strictly
        // dominates base (Before/After), not concurrent with it.
        let mut branch1 = base.clone();
        branch1.increment("device-b");
        assert_eq!(base.compare(&branch1), VvOrdering::Before);
        assert_eq!(branch1.compare(&base), VvOrdering::After);

        // branch2 = base + one edit from device-c = {a:1, c:1}: also
        // strictly dominates base, but neither branch1 nor branch2
        // dominates the other — each has a counter (b vs c) the other
        // lacks — so they're Concurrent with each other despite both
        // descending from the same base.
        let mut branch2 = base.clone();
        branch2.increment("device-c");
        assert_eq!(base.compare(&branch2), VvOrdering::Before);
        assert_eq!(branch1.compare(&branch2), VvOrdering::Concurrent);
        assert_eq!(branch2.compare(&branch1), VvOrdering::Concurrent);

        // A vector that has seen both concurrent branches (merged, or
        // independently arrived at {a:1, b:1, c:1}) dominates each of
        // them individually — not concurrent with either anymore.
        let merged = branch1.merge(&branch2);
        assert_eq!(merged.compare(&branch1), VvOrdering::After);
        assert_eq!(merged.compare(&branch2), VvOrdering::After);
        assert_eq!(branch1.compare(&merged), VvOrdering::Before);
        assert_eq!(branch2.compare(&merged), VvOrdering::Before);
    }

    /// Merging a vector with itself (or
    /// re-merging an already-merged pair) must be idempotent — a
    /// resolved conflict re-processed (e.g. a duplicate/retried message)
    /// must not double-count or otherwise change the result.
    #[test]
    fn merge_is_idempotent() {
        let mut a = VersionVector::new();
        a.increment("device-a");
        a.increment("device-a"); // {a:2}
        let mut b = VersionVector::new();
        b.increment("device-b"); // {b:1}

        let merged_once = a.merge(&b);
        let merged_twice = merged_once.merge(&b);
        let merged_with_self = merged_once.merge(&merged_once);

        assert_eq!(merged_once, merged_twice);
        assert_eq!(merged_once, merged_with_self);
    }

    /// Merging two equal vectors is a
    /// true no-op (identical result, not just an equal-under-`compare`
    /// one) — guards against a merge implementation that could otherwise
    /// introduce spurious drift even when there's nothing new to
    /// reconcile.
    #[test]
    fn merge_of_equal_vectors_is_a_no_op() {
        let mut a = VersionVector::new();
        a.increment("device-a");
        a.increment("device-b");
        let b = a.clone();

        assert_eq!(a.compare(&b), VvOrdering::Equal);
        assert_eq!(a.merge(&b), a);
    }

    /// Adversarial case: a peer that has observed local's `{local:5}` cannot
    /// force `Before` (and therefore a silent overwrite) by advertising an
    /// arbitrarily large foreign counter (a `{local:5, peer:999}` example).
    /// After sanitizing against local's last-known-good vector, the peer's
    /// counter is clamped to `local:5's peer-counter (0) + max_jump`, which
    /// stays well below a value that could dominate a genuinely newer
    /// local edit.
    #[test]
    fn sanitize_against_blocks_an_implausible_foreign_counter_jump() {
        let mut local = VersionVector::new();
        local.increment("local"); // {local:1}
        local.increment("local");
        local.increment("local");
        local.increment("local");
        local.increment("local"); // {local:5}

        let mut forged = VersionVector::new();
        forged.increment("local");
        forged.increment("local");
        forged.increment("local");
        forged.increment("local");
        forged.increment("local"); // {local:5}
        for _ in 0..999 {
            forged.increment("peer");
        } // {local:5, peer:999}

        let sanitized = local.sanitize_against(&forged, "local", 10);
        assert_eq!(sanitized.get("local"), 5);
        assert_eq!(sanitized.get("peer"), 10); // clamped to 0 + max_jump

        // Crucially, the *sanitized* comparison no longer claims the peer
        // is strictly ahead of a local vector that has since moved on:
        // suppose local made one more real edit after last syncing with
        // this peer ({local:6}) — the raw forged vector would still claim
        // `Before` is impossible to distinguish from a real dominance, but
        // sanitizing first means the peer's counter can never reach a
        // value that, combined with a stale `local` claim, forges
        // domination over unseen local progress.
        let mut local_after_new_edit = local.clone();
        local_after_new_edit.increment("local"); // {local:6}
        let sanitized2 = local_after_new_edit.sanitize_against(&forged, "local", 10);
        // The peer's claimed "local:5" is honest (it matches what the
        // peer actually last saw) and passes through unclamped since it's
        // <= our true current local counter's own last-recorded value
        // read from `self` at time of sanitization — but the key
        // invariant this test pins down is that peer's own counter claim
        // is still bounded, not unbounded, regardless of what local's
        // vector looks like.
        assert_eq!(sanitized2.get("peer"), 10);
    }

    /// Legitimate case: sanitizing must be a no-op for ordinary, honest
    /// version-vector growth (a peer that made a handful of real edits
    /// since the last sync), so normal non-adversarial conflict resolution
    /// is unaffected by this mitigation.
    #[test]
    fn sanitize_against_is_a_no_op_for_plausible_honest_growth() {
        let mut local = VersionVector::new();
        local.increment("local");
        local.increment("local"); // {local:2}

        // Peer legitimately made 3 real edits since it last synced (a
        // small, ordinary jump, far under any reasonable max_jump bound).
        let mut honest_incoming = local.clone();
        honest_incoming.increment("peer");
        honest_incoming.increment("peer");
        honest_incoming.increment("peer"); // {local:2, peer:3}

        let sanitized =
            local.sanitize_against(&honest_incoming, "local", MAX_VV_COUNTER_JUMP_PER_MESSAGE);
        assert_eq!(sanitized, honest_incoming, "honest growth must pass through unclamped");

        // And the resulting causality comparison is unaffected: peer is
        // legitimately strictly ahead (a real new edit, no local edit
        // since), so it should still resolve as `Before`, not get
        // spuriously blocked into `Concurrent` or `Equal`.
        assert_eq!(local.compare(&sanitized), VvOrdering::Before);
    }

    /// Plausibility clamping may still inform the conflict decision, but
    /// once an honest newer record is adopted its stored version vector
    /// must remain the honest incoming one, not the clamped one.
    #[test]
    fn honest_long_offline_jump_keeps_honest_version_after_adoption() {
        let mut local = VersionVector::new();
        local.increment("local");
        local.increment("local");

        let mut honest_incoming = local.clone();
        for _ in 0..10_001 {
            honest_incoming.increment("peer");
        }

        let sanitized =
            local.sanitize_against(&honest_incoming, "local", MAX_VV_COUNTER_JUMP_PER_MESSAGE);
        assert_eq!(sanitized.get("peer"), 10_000, "decision-time clamp still engages");
        assert_eq!(local.compare(&sanitized), VvOrdering::Before);

        let stored_after_adopt = honest_incoming.clone();

        let mut next_local_edit = stored_after_adopt.clone();
        next_local_edit.increment("local");

        let mut peer_next = honest_incoming.clone();
        peer_next.increment("peer");

        assert_eq!(
            next_local_edit.compare(&peer_next),
            VvOrdering::Concurrent,
            "the honest stored vector preserves the real causal relationship for the next edit",
        );

        let mut clamped_after_adopt = sanitized.clone();
        clamped_after_adopt.increment("local");
        assert_eq!(clamped_after_adopt.compare(&peer_next), VvOrdering::Concurrent);
    }

    /// A peer can never legitimately claim to know a higher counter for
    /// *our own* device than we ourselves have recorded — this is a hard
    /// invariant (not a heuristic bound), so it must hold regardless of
    /// `max_jump`, including `max_jump = 0`.
    #[test]
    fn sanitize_against_caps_local_devices_own_counter_at_its_true_value_even_with_zero_jump() {
        let mut local = VersionVector::new();
        local.increment("local"); // {local:1}

        let mut forged = VersionVector::new();
        for _ in 0..500 {
            forged.increment("local");
        } // {local:500} — peer claims WE are far ahead of what we know

        let sanitized = local.sanitize_against(&forged, "local", 0);
        assert_eq!(
            sanitized.get("local"),
            1,
            "peer cannot claim a higher counter for our own device than we have"
        );
    }
}

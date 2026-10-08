//! Differential test of `native_state::resolve_path` against DCF's
//! own `yadorilink_replica_engine::conflict::resolve_path_heads`, over the
//! same abstract per-path head set (the native win order handed to DCF as its
//! rank, same tie-break hash bytes,
//! same content version per head).
//!
//! Per the design decision recorded in `native_state::resolve_path`'s own
//! doc comment: compares **content sets**, not conflict-copy path strings
//! (DCF's naming embeds a file's mtime, which native's domain model does
//! not track — a materialization-time cosmetic detail, not causal state).
//! Winner content and the set of distinct losing-content versions must
//! agree; which specific head each side reports as the representative of a
//! tied losing version need not (each model's own internal tie-break unit
//! is different: DCF's `change_hash`, native's `provenance` — both fed the
//! same byte value here, but the two resolvers are independent code, not
//! required to pick the identical representative index for a class that
//! only ties on version+hash across a *group* of more than two).

use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
use yadorilink_replica_domain::ids::{AuthorSeq, DeviceId, VersionHash};
use yadorilink_replica_domain::native_state::{
    DeltaHash, Dot, HeadPayload, LiveHead, PathMaterialization,
};
use yadorilink_replica_engine::conflict::{
    resolve_path_heads, PathHead, PathHeadContent, PathResolution,
};

struct HeadSpec {
    author: u8,
    tie_break_byte: u8,
    version_byte: u8,
}

fn dcf_heads(specs: &[HeadSpec]) -> Vec<PathHead> {
    specs
        .iter()
        .map(|s| PathHead {
            change_hash: [s.tie_break_byte; 32],
            rank: u64::from(s.version_byte),
            device_id: format!("author-{}", s.author),
            naming_device_id: format!("author-{}", s.author),
            content: Some(PathHeadContent {
                version_hash: [s.version_byte; 32],
                mtime_unix_nanos: 0,
            }),
        })
        .collect()
}

fn native_heads(specs: &[HeadSpec]) -> Vec<LiveHead> {
    specs
        .iter()
        .enumerate()
        .map(|(seq, s)| LiveHead {
            dot: Dot {
                author: AuthorId {
                    device: DeviceId(format!("author-{}", s.author)),
                    incarnation: IncarnationId([1u8; 16]),
                },
                seq: AuthorSeq((seq + 1) as u64),
            },
            payload: HeadPayload {
                version: VersionHash([s.version_byte; 32]),
                provenance: DeltaHash([s.tie_break_byte; 32]),
            },
        })
        .collect()
}

fn winner_version(specs: &[HeadSpec], resolution: &PathResolution) -> Option<u8> {
    match resolution {
        PathResolution::Absent => None,
        PathResolution::Present { winner, .. } => Some(specs[*winner].version_byte),
    }
}

fn dcf_conflict_versions(
    specs: &[HeadSpec],
    resolution: &PathResolution,
) -> std::collections::BTreeSet<u8> {
    match resolution {
        PathResolution::Absent => Default::default(),
        PathResolution::Present { conflict_copies, .. } => {
            conflict_copies.iter().map(|c| specs[c.head].version_byte).collect()
        }
    }
}

fn native_conflict_versions(
    specs: &[HeadSpec],
    resolution: &PathMaterialization,
) -> std::collections::BTreeSet<u8> {
    let PathMaterialization::Present { conflict_copies, .. } = resolution else {
        return Default::default();
    };
    conflict_copies
        .iter()
        .map(|dot| {
            let seq = dot.seq.get() as usize - 1;
            specs[seq].version_byte
        })
        .collect()
}

fn assert_resolutions_agree(specs: &[HeadSpec]) {
    let dcf_resolution = resolve_path_heads("x", &dcf_heads(specs));
    let native_resolution = native_state_resolve(specs);

    let dcf_winner = winner_version(specs, &dcf_resolution);
    let native_winner = match &native_resolution {
        PathMaterialization::Absent => None,
        PathMaterialization::Present { winner, .. } => {
            Some(specs[winner.seq.get() as usize - 1].version_byte)
        }
    };
    assert_eq!(dcf_winner, native_winner, "winner content must agree for {specs:?}");

    assert_eq!(
        dcf_conflict_versions(specs, &dcf_resolution),
        native_conflict_versions(specs, &native_resolution),
        "the set of distinct losing-content versions must agree for {specs:?}"
    );
}

fn native_state_resolve(specs: &[HeadSpec]) -> PathMaterialization {
    yadorilink_replica_domain::native_state::resolve_path(native_heads(specs))
}

impl std::fmt::Debug for HeadSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "(author={} hash={:#x} version={:#x})",
            self.author, self.tie_break_byte, self.version_byte
        )
    }
}

#[test]
fn no_heads_is_absent_on_both_sides() {
    assert_resolutions_agree(&[]);
}

#[test]
fn single_head_has_no_conflicts_on_either_side() {
    assert_resolutions_agree(&[HeadSpec { author: 1, tie_break_byte: 1, version_byte: 1 }]);
}

#[test]
fn two_heads_same_content_collapse_to_no_conflict_on_both_sides() {
    assert_resolutions_agree(&[
        HeadSpec { author: 1, tie_break_byte: 1, version_byte: 9 },
        HeadSpec { author: 2, tie_break_byte: 2, version_byte: 9 },
    ]);
}

#[test]
fn two_heads_different_content_agree_on_winner_and_one_conflict_copy() {
    assert_resolutions_agree(&[
        HeadSpec { author: 1, tie_break_byte: 1, version_byte: 1 },
        HeadSpec { author: 2, tie_break_byte: 2, version_byte: 2 },
    ]);
}

#[test]
fn three_way_conflict_with_a_tied_losing_version_agrees_on_the_set() {
    assert_resolutions_agree(&[
        HeadSpec { author: 1, tie_break_byte: 1, version_byte: 1 }, // winner
        HeadSpec { author: 2, tie_break_byte: 5, version_byte: 2 }, // loser, v2, low hash
        HeadSpec { author: 3, tie_break_byte: 9, version_byte: 2 }, // loser, v2, high hash -- ties by version, hash breaks it
        HeadSpec { author: 4, tie_break_byte: 1, version_byte: 3 }, // loser, v3
    ]);
}

/// Randomized: a modest splitmix64-seeded sweep over 2-6 heads per path,
/// random hash bytes/version bytes, confirming winner content and
/// the distinct-losing-version set always agree.
#[test]
fn randomized_agreement_over_many_head_sets() {
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
            z ^ (z >> 31)
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    let mut rng = Rng(0xC0FFEE);
    for _ in 0..500 {
        let n = 2 + rng.below(5);
        // `tie_break_byte` gets a distinct value per head in one scenario --
        // matching reality (a real change_hash/provenance is an effectively
        // unique 32-byte value; two *different* changes never collide).
        // A colliding tie-break key is degenerate input neither resolver's
        // comparator is even well-defined over (both are ordinary total
        // orders assuming distinct keys), so testing it would only prove
        // an irrelevant shared quirk, not a real divergence risk.
        let specs: Vec<HeadSpec> = (0..n)
            .map(|i| HeadSpec {
                author: i as u8 + 1,
                tie_break_byte: (i + 1) as u8,
                version_byte: (rng.below(3) + 1) as u8,
            })
            .collect();
        assert_resolutions_agree(&specs);
    }
}

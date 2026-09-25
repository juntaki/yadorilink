#![cfg(test)]

use super::*;
use prost::Message;
use yadorilink_ipc_proto::framing::MAX_FRAME_LEN;
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_replica_domain::rewind::{
    RewindPathAction, RewindPathEntry, RewindPlan, RewindRenameCandidate,
};

/// A plan far past the scale the read-side benchmark measures, built to
/// be as expensive to encode as a real one can plausibly be: long
/// nested paths, and an `unavailable` reason on every path that can
/// carry one.
fn huge_plan(paths: usize) -> RewindPlan {
    let entries = (0..paths)
        .map(|i| {
            let action = match i % 4 {
                0 => RewindPathAction::Unchanged,
                1 => RewindPathAction::Delete,
                2 => RewindPathAction::Replace {
                    from_version_seq: 9,
                    to_version_seq: 4,
                    to_version_hash: VersionHash([1u8; 32]),
                },
                _ => RewindPathAction::Unavailable {
                    reason: "this device holds no version of this path from at or before \
                             the target time (its earliest retained version is 7); earlier \
                             versions were either expired by version retention or never \
                             held by this device"
                        .to_string(),
                },
            };
            RewindPathEntry {
                path: format!("some/reasonably/deep/project/directory/tree/file-{i:07}.bin"),
                action,
            }
        })
        .collect();
    RewindPlan {
        group_id: "group-with-a-lot-in-it".to_string(),
        target_unix_nanos: 1_750_000_000_000_000_000,
        entries,
        rename_candidates: (0..paths / 10)
            .map(|i| RewindRenameCandidate {
                from_path: format!("some/reasonably/deep/moved/from-{i:07}.bin"),
                to_path: format!("some/reasonably/deep/moved/to-{i:07}.bin"),
                version_hash: VersionHash([2u8; 32]),
            })
            .collect(),
    }
}

/// The response has to fit in one frame or the CLI cannot read it at
/// all -- the reader rejects an oversized frame outright, and now so
/// does the writer. Asserted at a scale well past the 50k the read-side
/// benchmark covers, in BOTH modes: the `unchanged` filter is the
/// ordinary saving, but the byte budget is what makes the guarantee
/// unconditional.
#[test]
fn a_huge_plan_still_produces_a_response_that_fits_in_one_frame() {
    for include_unchanged in [false, true] {
        let response = rewind_preview_to_proto(crate::rewind::trim_for_wire(
            huge_plan(200_000),
            include_unchanged,
        ));
        let encoded_len = response.encoded_len();
        assert!(
            encoded_len < MAX_FRAME_LEN as usize,
            "include_unchanged={include_unchanged}: response of {encoded_len} bytes would \
             not fit in a {MAX_FRAME_LEN}-byte frame"
        );
        // The summary must still describe the WHOLE plan, or the
        // trimming would have quietly changed the answer.
        let counts = response.counts.as_ref().expect("counts are always sent");
        assert_eq!(response.total_entry_count, 200_000);
        assert_eq!(
            counts.create + counts.delete + counts.replace + counts.unchanged + counts.unavailable,
            200_000
        );
        assert!(response.listing_truncated, "a listing this big cannot have fit whole");
    }
}

/// The ordinary case: a folder small enough to describe completely must
/// come back complete, with nothing flagged as cut.
#[test]
fn a_small_plan_is_delivered_whole() {
    let response = rewind_preview_to_proto(crate::rewind::trim_for_wire(huge_plan(40), true));
    assert_eq!(response.entries.len(), 40);
    assert_eq!(response.rename_candidates.len(), 4);
    assert!(!response.listing_truncated);
    assert!(response.encoded_len() < MAX_FRAME_LEN as usize);
}

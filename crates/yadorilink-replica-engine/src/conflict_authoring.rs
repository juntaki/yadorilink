//! Pure decision logic for conflict-copy authoring and validation, split out
//! of `yadorilink-sync-sqlite`'s `dag_store::conflict_authoring` (Phase
//! 7D-7.4): whether a conflict copy is required, which ops a carrier must
//! carry, and structural validation of a claimed carrier's conflict-copy
//! ops -- all expressed as plain functions over `PathHead`/`Op` domain
//! values, never a SQLite row or `Connection`/`Transaction`.
//!
//! The SQL-dependent half stays in
//! `yadorilink-sync-sqlite::dag_store::conflict_authoring`: fetching a
//! path's live heads at a historical frontier
//! (`path_heads_at_frontier`, which itself walks the DAG stored in SQLite),
//! checking durable provenance (`conflict_copy_already_provisioned`), and
//! walking ancestry (`retained_history_integrity::is_ancestor`). That module
//! fetches the data these functions need and calls them with it already in
//! hand -- see its own module doc comment for the fuller design context
//! (idempotency, causal identity) this split does not repeat here.

use std::collections::BTreeSet;

use yadorilink_replica_domain::change::{ChangePurpose, Op, PutOrigin};
use yadorilink_replica_domain::ids::{ChangeHash, SyncPath, VersionHash};

use crate::conflict::{
    conflict_copy_path_for_losing_change, resolve_path_heads_keeping_directory, PathHead,
    PathHeadContent, PathResolution,
};

/// Every path a set of direct ops touches -- a `Put`'s `path`, a `Delete`'s
/// `path`, or either side of a `Move` -- since a removal dominates a prior
/// fork just as much as a new put does.
pub fn collect_touched_paths(direct_ops: &[Op]) -> BTreeSet<String> {
    let mut touched_paths = BTreeSet::new();
    for op in direct_ops {
        match op {
            Op::Put { path, .. } | Op::Delete { path } => {
                touched_paths.insert(path.as_str().to_string());
            }
            Op::Move { from, to, .. } => {
                touched_paths.insert(from.as_str().to_string());
                touched_paths.insert(to.as_str().to_string());
            }
        }
    }
    touched_paths
}

/// One losing content head at a path's live heads, competing to be
/// materialized as a conflict copy -- the pure per-loser projection of
/// [`resolve_path_heads_keeping_directory`]'s own
/// `PathResolution::Present.conflict_copies`.
#[derive(Clone, Debug)]
pub struct ConflictCopyCandidate {
    pub target_path: String,
    pub losing_change: ChangeHash,
    pub losing_content: PathHeadContent,
}

/// Every conflict-copy candidate `path`'s live `heads` (already fetched by
/// the caller, e.g. via `path_heads_at_frontier`) produce, in
/// [`resolve_path_heads_keeping_directory`]'s own deterministic order
/// (`is_directory` says which content heads are Directories). Empty when
/// the path resolves to `Absent` or has no losing content head at all.
pub fn conflict_copy_candidates(
    path: &str,
    heads: &[PathHead],
    is_directory: impl Fn(&PathHead) -> bool,
) -> Vec<ConflictCopyCandidate> {
    let PathResolution::Present { conflict_copies, .. } =
        resolve_path_heads_keeping_directory(path, heads, is_directory)
    else {
        return Vec::new();
    };
    conflict_copies
        .into_iter()
        .map(|cc| {
            let losing_head = &heads[cc.head];
            ConflictCopyCandidate {
                target_path: cc.path,
                losing_change: ChangeHash(losing_head.change_hash),
                losing_content: losing_head
                    .content
                    .clone()
                    .expect("resolve_path_heads only names content heads in conflict_copies"),
            }
        })
        .collect()
}

/// Whether `target_heads` (a target path's own live heads at the same
/// frontier, already fetched by the caller) already carry content
/// byte-identical to `losing_content_version_hash`, regardless of which
/// change put it there. Suppresses re-deriving a copy of content some other
/// carrier already preserved at the deterministic target -- see
/// `yadorilink-sync-sqlite`'s `derive_required_conflict_copy_ops`'s own doc
/// comment for the carrier-storm regression this guards.
pub fn content_already_preserved_at_target(
    target_heads: &[PathHead],
    losing_content_version_hash: &[u8; 32],
) -> bool {
    target_heads
        .iter()
        .any(|h| h.content.as_ref().is_some_and(|c| c.version_hash == *losing_content_version_hash))
}

/// Builds the deterministic `ConflictCopy` `Put` op for one required
/// candidate, carried by the change `source_path`'s direct ops are folded
/// into.
pub fn build_conflict_copy_op(source_path: &str, candidate: &ConflictCopyCandidate) -> Op {
    Op::Put {
        path: SyncPath(candidate.target_path.clone()),
        version: VersionHash(candidate.losing_content.version_hash),
        origin: PutOrigin::ConflictCopy {
            source_path: SyncPath(source_path.to_string()),
            losing_change: candidate.losing_change,
        },
    }
}

/// Structural validation of one claimed `ConflictCopy` `Put` op against
/// `source_path`'s own live heads at the carrier's parent frontier
/// (`heads`, already fetched by the caller) -- everything
/// `validate_conflict_copy_origin`'s own doc comment lists EXCEPT
/// reachability of `losing_change` from the carrier's parents, which needs
/// the caller's own ancestry index and must be checked before calling this.
#[derive(Debug, thiserror::Error)]
pub enum ConflictCopyClaimError {
    #[error(
        "conflict-copy put's losing_change {losing_change} is not a live head for \
         {source_path:?} at its carrier's parent frontier"
    )]
    NotALiveHead { losing_change: String, source_path: String },
    #[error(
        "conflict-copy put's losing_change {losing_change} does not put content at \
         {source_path:?}"
    )]
    NoContentAtSource { losing_change: String, source_path: String },
    #[error("conflict-copy put's version does not match its losing_change's actual version")]
    VersionMismatch,
    #[error(
        "conflict-copy put claims a loser for {source_path:?}, but that path resolves to Absent \
         at its carrier's parent frontier"
    )]
    SourceResolvesAbsent { source_path: String },
    #[error(
        "conflict-copy put's losing_change {losing_change} is not a genuine concurrent loser for \
         {source_path:?} at its carrier's parent frontier (it is the winner, or already \
         superseded there)"
    )]
    NotAGenuineLoser { losing_change: String, source_path: String },
    #[error(
        "conflict-copy put's path {path:?} does not match the deterministic name {expected:?} \
         derived from its losing_change"
    )]
    PathDoesNotMatchCandidate { path: String, expected: String },
    #[error(
        "conflict-copy put's path {path:?} does not match the deterministic name {expected:?}"
    )]
    PathDoesNotMatchDeterministicName { path: String, expected: String },
}

pub fn validate_conflict_copy_claim(
    heads: &[PathHead],
    path: &str,
    version: &VersionHash,
    source_path: &str,
    losing_change: &ChangeHash,
    is_directory: impl Fn(&PathHead) -> bool,
) -> Result<(), ConflictCopyClaimError> {
    let Some(losing_head) = heads.iter().find(|h| h.change_hash == losing_change.0) else {
        return Err(ConflictCopyClaimError::NotALiveHead {
            losing_change: hex::encode(losing_change.0),
            source_path: source_path.to_string(),
        });
    };
    let Some(content) = losing_head.content.as_ref() else {
        return Err(ConflictCopyClaimError::NoContentAtSource {
            losing_change: hex::encode(losing_change.0),
            source_path: source_path.to_string(),
        });
    };
    if content.version_hash != version.0 {
        return Err(ConflictCopyClaimError::VersionMismatch);
    }

    let PathResolution::Present { conflict_copies, .. } =
        resolve_path_heads_keeping_directory(source_path, heads, is_directory)
    else {
        return Err(ConflictCopyClaimError::SourceResolvesAbsent {
            source_path: source_path.to_string(),
        });
    };
    let Some(cc) = conflict_copies.iter().find(|cc| heads[cc.head].change_hash == losing_change.0)
    else {
        return Err(ConflictCopyClaimError::NotAGenuineLoser {
            losing_change: hex::encode(losing_change.0),
            source_path: source_path.to_string(),
        });
    };
    if cc.path != path {
        return Err(ConflictCopyClaimError::PathDoesNotMatchCandidate {
            path: path.to_string(),
            expected: cc.path.clone(),
        });
    }
    let expected_name = conflict_copy_path_for_losing_change(
        source_path,
        // The content's author, not this head's carrier -- the same field
        // `resolve_path_heads` names the copy after, and for the same reason:
        // a repair re-assertion carries someone else's content forward, so
        // the carrier is a device that never wrote it. Deriving this one from
        // `device_id` made the two disagree for exactly those heads, and then
        // the claim could never be accepted: the copy `resolve_path_heads`
        // asks for is the only copy anyone can author, and this rejected it
        // by name. Observed as `retroactive conflict-copy repair deferred`
        // repeating until the group stopped converging.
        &losing_head.naming_device_id,
        content.mtime_unix_nanos,
        &content.version_hash,
    );
    if expected_name != path {
        return Err(ConflictCopyClaimError::PathDoesNotMatchDeterministicName {
            path: path.to_string(),
            expected: expected_name,
        });
    }
    Ok(())
}

/// Why a `PutOrigin::Reasserted` op's provenance claim does not hold.
///
/// The claim is exactly "the head I name is this path's current winner, and
/// the naming identity I carry is that head's own". Both halves are
/// re-derivable from the carrier's parents, so a receiver checks them rather
/// than trusting the carrier -- which matters precisely because
/// `naming_device_id` is the one field a malicious or buggy carrier could
/// use to attribute its own content to another device.
#[derive(Debug, thiserror::Error)]
pub enum ReassertionClaimError {
    #[error("re-asserted put at {source_path:?} names a path with no live content head")]
    NoLiveContentHead { source_path: String },
    #[error(
        "re-asserted put at {source_path:?} names original_change {original_change}, which is \
         not that path's winning head"
    )]
    NotTheWinner { original_change: String, source_path: String },
    #[error(
        "re-asserted put at {source_path:?} carries version {version} but the head it names \
         holds {expected}"
    )]
    VersionDoesNotMatchHead { source_path: String, version: String, expected: String },
    #[error(
        "re-asserted put at {source_path:?} claims naming_device_id {claimed:?} but the head it \
         carries forward names {expected:?}"
    )]
    NamingIdentityDoesNotMatchHead { source_path: String, claimed: String, expected: String },
}

/// Validates one `PutOrigin::Reasserted` op against `source_path`'s own live
/// heads at the carrier's parent frontier (`heads`, already fetched by the
/// caller, exactly as [`validate_conflict_copy_claim`] takes them).
///
/// A re-assertion is only ever legitimate as "carry the current winner
/// forward unchanged", so all three of the head it names, the content it
/// carries, and the naming identity it claims must agree with what the
/// frontier already says. Checking the naming identity here is what keeps
/// `naming_device_id` a verifiable fact rather than an assertion a carrier
/// could use to relabel someone else's content as its own.
pub fn validate_reassertion_claim(
    heads: &[PathHead],
    source_path: &str,
    version: &VersionHash,
    original_change: &ChangeHash,
    naming_device_id: &str,
    is_directory: impl Fn(&PathHead) -> bool,
) -> Result<(), ReassertionClaimError> {
    let PathResolution::Present { winner, .. } =
        resolve_path_heads_keeping_directory(source_path, heads, is_directory)
    else {
        return Err(ReassertionClaimError::NoLiveContentHead {
            source_path: source_path.to_string(),
        });
    };
    let winning_head = &heads[winner];
    if winning_head.change_hash != original_change.0 {
        return Err(ReassertionClaimError::NotTheWinner {
            original_change: hex::encode(original_change.0),
            source_path: source_path.to_string(),
        });
    }
    let content = winning_head
        .content
        .as_ref()
        .expect("resolve_path_heads only selects a content head as winner");
    if content.version_hash != version.0 {
        return Err(ReassertionClaimError::VersionDoesNotMatchHead {
            source_path: source_path.to_string(),
            version: hex::encode(version.0),
            expected: hex::encode(content.version_hash),
        });
    }
    if winning_head.naming_device_id != naming_device_id {
        return Err(ReassertionClaimError::NamingIdentityDoesNotMatchHead {
            source_path: source_path.to_string(),
            claimed: naming_device_id.to_string(),
            expected: winning_head.naming_device_id.clone(),
        });
    }
    Ok(())
}

/// Points 6/7 of `validate_carrier_conflict_copy_ops`'s own doc comment,
/// restricted to `ChangePurpose::RetroactiveRepair`: the carrier's declared
/// obligations must exactly match its own claimed `ConflictCopy` ops, and
/// its direct ops must be exactly one reassertion `Put` per declared source
/// path, no more, no less. A no-op for `ChangePurpose::Ordinary`.
#[derive(Debug, thiserror::Error)]
pub enum RetroactiveRepairClaimError {
    #[error(
        "retroactive-repair carrier's signed obligations do not exactly match its conflict-copy \
         puts"
    )]
    ObligationsMismatch,
    #[error("retroactive-repair carrier reasserts undeclared source path {0:?}")]
    UndeclaredReassertion(String),
    #[error(
        "retroactive-repair carrier may contain only direct source-path puts plus its declared \
         conflict-copy puts"
    )]
    NonReassertionDirectOp,
    #[error("retroactive-repair carrier does not reassert every declared source path")]
    MissingReassertion,
}

pub fn validate_retroactive_repair_claims(
    purpose: &ChangePurpose,
    direct_ops: &[Op],
    claimed: &BTreeSet<(String, ChangeHash)>,
) -> Result<(), RetroactiveRepairClaimError> {
    let ChangePurpose::RetroactiveRepair { obligations } = purpose else { return Ok(()) };
    let declared: BTreeSet<(String, ChangeHash)> = obligations
        .iter()
        .map(|obligation| (obligation.source_path.as_str().to_string(), obligation.losing_change))
        .collect();
    if &declared != claimed {
        return Err(RetroactiveRepairClaimError::ObligationsMismatch);
    }

    let declared_sources: BTreeSet<&str> =
        obligations.iter().map(|obligation| obligation.source_path.as_str()).collect();
    let mut reasserted_sources = BTreeSet::new();
    for op in direct_ops {
        match op {
            // `Reasserted` is the only shape a carrier's own direct op may
            // take. A bare `Direct` put would assert that the repairer wrote
            // this content, which is exactly the misattribution this origin
            // exists to prevent -- and accepting both forms would leave two
            // encodings of the same fact, so a carrier could pick the one
            // that drops the author's identity.
            Op::Put { path, origin: PutOrigin::Reasserted { .. }, .. } => {
                if !declared_sources.contains(path.as_str()) {
                    return Err(RetroactiveRepairClaimError::UndeclaredReassertion(
                        path.as_str().to_string(),
                    ));
                }
                reasserted_sources.insert(path.as_str());
            }
            _ => return Err(RetroactiveRepairClaimError::NonReassertionDirectOp),
        }
    }
    if reasserted_sources != declared_sources {
        return Err(RetroactiveRepairClaimError::MissingReassertion);
    }
    Ok(())
}

/// Point 6 (no deficient claims) and its reverse direction (no excess
/// claims) of `validate_carrier_conflict_copy_ops`'s own doc comment:
/// every op in `required` (already causally-scoped-filtered by the caller)
/// must be present in `claimed`, and every entry in `claimed` must be
/// present in `required`.
#[derive(Debug, thiserror::Error)]
pub enum ConflictCopyClaimSetError {
    #[error(
        "carrier change is missing a required conflict-copy put for losing_change \
         {losing_change} at {source_path:?}"
    )]
    Missing { losing_change: String, source_path: String },
    #[error(
        "carrier change claims a conflict-copy put for losing_change {losing_change} at \
         {source_path:?} that nothing in its own direct ops actually requires"
    )]
    Unrequired { losing_change: String, source_path: String },
}

pub fn validate_claimed_matches_required(
    required: &[Op],
    claimed: &BTreeSet<(String, ChangeHash)>,
) -> Result<(), ConflictCopyClaimSetError> {
    let mut required_claims: BTreeSet<(String, ChangeHash)> = BTreeSet::new();
    for op in required {
        let Op::Put { origin: PutOrigin::ConflictCopy { source_path, losing_change }, .. } = op
        else {
            unreachable!("derive_required_conflict_copy_ops only ever returns ConflictCopy puts");
        };
        required_claims.insert((source_path.as_str().to_string(), *losing_change));
        if !claimed.contains(&(source_path.as_str().to_string(), *losing_change)) {
            return Err(ConflictCopyClaimSetError::Missing {
                losing_change: hex::encode(losing_change.0),
                source_path: source_path.as_str().to_string(),
            });
        }
    }
    if let Some((source_path, losing_change)) =
        claimed.iter().find(|claim| !required_claims.contains(*claim))
    {
        return Err(ConflictCopyClaimSetError::Unrequired {
            losing_change: hex::encode(losing_change.0),
            source_path: source_path.clone(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests;

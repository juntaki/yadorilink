//! Folder Rewind's read-only plan: a deterministic description of what
//! *would* have to change, per path, to bring a group's desired state back
//! to what this device held at some wall-clock time T.
//!
//! Pure data. Nothing here emits a signed [`crate::change::Change`], touches
//! a filesystem, creates a materialization obligation, or otherwise
//! commits to anything -- a [`RewindPlan`] is a preview a caller renders
//! and a human decides about. The types deliberately carry enough to
//! render that decision honestly, including an explicit "this device
//! cannot answer for this path" outcome ([`RewindPathAction::Unavailable`])
//! that must never be quietly folded into "nothing to do".

use crate::ids::VersionHash;

/// What a rewind to `target_unix_nanos` would have to do to `group_id`'s
/// desired state, path by path.
///
/// `entries` is the authoritative part: exactly one entry per path this
/// device has ever indexed for this group, each carrying an independent
/// per-path verdict. `rename_candidates` is a purely auxiliary annotation
/// derived from `entries` afterwards -- see its own field comment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewindPlan {
    pub group_id: String,
    /// The rewind target, in nanoseconds since the Unix epoch, on the
    /// clock of the device that computed the plan. A plan is only ever
    /// meaningful against the device that produced it: the admission
    /// timestamps it is computed from are that device's own local
    /// observations, deliberately not a replicated value (see
    /// `files.admitted_at_unix_nanos`'s migration comment).
    pub target_unix_nanos: i64,
    pub entries: Vec<RewindPathEntry>,
    /// Best-effort "this looks like it was a rename" pairings between the
    /// [`RewindPathAction::Create`] and [`RewindPathAction::Delete`]
    /// entries above, matched purely on identical content
    /// ([`VersionHash`]). Advisory only, and always overridable: two
    /// unrelated paths that genuinely happen to hold byte-identical
    /// content produce a false pairing here, which is expected and
    /// harmless precisely because nothing in `entries` depends on this
    /// list. A renderer may present a pairing instead of its two separate
    /// entries; an executor (which does not exist in this read-only layer)
    /// would still have to act on `entries`, never on this.
    pub rename_candidates: Vec<RewindRenameCandidate>,
}

/// One path's verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewindPathEntry {
    /// Group-relative path, exactly as the index stores it.
    pub path: String,
    pub action: RewindPathAction,
}

/// What would have to happen to one path.
///
/// Every variant is a statement about this device's own index, not about
/// any filesystem: "present" means a non-tombstone version row, "absent"
/// means either a tombstone or no row at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewindPathAction {
    /// Present at T, absent now -- the path would come back, restored to
    /// the version identified here.
    Create { version_seq: i64, version_hash: VersionHash },
    /// Absent at T, present now -- the path would go away again.
    Delete,
    /// Present in both states but holding different content -- the path
    /// would be rolled back from `from_version_seq` to `to_version_seq`.
    Replace { from_version_seq: i64, to_version_seq: i64, to_version_hash: VersionHash },
    /// Present in both states with the identical [`VersionHash`], or
    /// absent in both. Nothing to do.
    Unchanged,
    /// This device cannot honestly say what this path held at T.
    ///
    /// A real, distinct outcome -- never a soft synonym for [`Self::
    /// Unchanged`] and never silently rounded to the nearest surviving
    /// version. Three things produce it: the evidence needed to answer is
    /// gone (the path's history at that point fell out of the retention
    /// window); this device never held any history reaching back that far
    /// in the first place (it joined the group late, or its own local
    /// history was replaced wholesale by a re-bootstrap more recently than
    /// the target); or the evidence was never recorded (a row predating the
    /// admission-timestamp column). All three are genuine "no answer exists
    /// here", and a rewind that quietly treated them as "leave it alone"
    /// would be presenting a guess as a plan.
    ///
    /// "Here" is the operative word for the middle one: another device that
    /// does hold the history can still answer it.
    Unavailable { reason: String },
}

/// One heuristic rename pairing. See [`RewindPlan::rename_candidates`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewindRenameCandidate {
    /// The path that would be deleted -- i.e. where this content lives now.
    pub from_path: String,
    /// The path that would be created -- i.e. where this content lived at T.
    pub to_path: String,
    /// The content both sides share, which is the entire basis for the
    /// guess.
    pub version_hash: VersionHash,
}

impl RewindPlan {
    /// Per-action tallies, in the fixed order a renderer wants them:
    /// creates, deletes, replaces, unchanged, unavailable.
    pub fn action_counts(&self) -> RewindActionCounts {
        let mut counts = RewindActionCounts::default();
        for entry in &self.entries {
            match entry.action {
                RewindPathAction::Create { .. } => counts.create += 1,
                RewindPathAction::Delete => counts.delete += 1,
                RewindPathAction::Replace { .. } => counts.replace += 1,
                RewindPathAction::Unchanged => counts.unchanged += 1,
                RewindPathAction::Unavailable { .. } => counts.unavailable += 1,
            }
        }
        counts
    }
}

/// How many paths fall into each [`RewindPathAction`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RewindActionCounts {
    pub create: u64,
    pub delete: u64,
    pub replace: u64,
    pub unchanged: u64,
    pub unavailable: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_counts_tallies_every_variant_separately() {
        let plan = RewindPlan {
            group_id: "g".into(),
            target_unix_nanos: 100,
            entries: vec![
                RewindPathEntry {
                    path: "a".into(),
                    action: RewindPathAction::Create {
                        version_seq: 1,
                        version_hash: VersionHash([1u8; 32]),
                    },
                },
                RewindPathEntry { path: "b".into(), action: RewindPathAction::Delete },
                RewindPathEntry {
                    path: "c".into(),
                    action: RewindPathAction::Replace {
                        from_version_seq: 3,
                        to_version_seq: 1,
                        to_version_hash: VersionHash([2u8; 32]),
                    },
                },
                RewindPathEntry { path: "d".into(), action: RewindPathAction::Unchanged },
                RewindPathEntry {
                    path: "e".into(),
                    action: RewindPathAction::Unavailable { reason: "gone".into() },
                },
                RewindPathEntry { path: "f".into(), action: RewindPathAction::Unchanged },
            ],
            rename_candidates: Vec::new(),
        };
        assert_eq!(
            plan.action_counts(),
            RewindActionCounts { create: 1, delete: 1, replace: 1, unchanged: 2, unavailable: 1 }
        );
    }

    /// An `Unavailable` path must never be counted as, or collapse into,
    /// `Unchanged`: the whole point of the variant is that "no answer
    /// exists" is reported as itself.
    #[test]
    fn unavailable_is_never_tallied_as_unchanged() {
        let plan = RewindPlan {
            group_id: "g".into(),
            target_unix_nanos: 0,
            entries: vec![RewindPathEntry {
                path: "a".into(),
                action: RewindPathAction::Unavailable { reason: "no history".into() },
            }],
            rename_candidates: Vec::new(),
        };
        let counts = plan.action_counts();
        assert_eq!(counts.unavailable, 1);
        assert_eq!(counts.unchanged, 0);
    }
}

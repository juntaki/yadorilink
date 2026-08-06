//! Fast-path selection for optimistic placement preparation (7D-9D move
//! from `yadorilink-sync-core::optimistic_placement`). Pure — no I/O, no
//! `Connection`. The rest of that module (actually staging bytes on disk,
//! the short atomic commit window, and the SQLite publish) stays in
//! `yadorilink-sync-core`: it reads `std::fs`, holds an already-open
//! `yadorilink_filesystem_sync::fs_commit::ParentDirHandle`, and writes
//! through a `rusqlite::Connection`, none of which this crate may depend
//! on. That module calls [`select_fast_path`] with an already-built
//! [`PlacementInputs`] snapshot and acts on the [`FastPathDecision`] it
//! returns.

use yadorilink_root_authority::fs_capabilities::FilesystemSafetyCapabilities;
use std::path::Path;

/// Preparation's I/O fast paths, strongest (cheapest, least data moved)
/// first. Selection never assumes a capability works — it is only chosen
/// when the caller's probed [`FilesystemSafetyCapabilities`] snapshot
/// reports it `Supported`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastPath {
    /// The target generation is already materialized; nothing to prepare.
    NoOp,
    /// Content identity is unchanged; only tracked metadata differs.
    MetadataOnly,
    /// Whole-file reflink/clone from an existing local version.
    ReflinkClone,
    /// Byte-range clone (plus, in a later phase with a real changed-block
    /// plan, changed-block writes — see the caller's own
    /// `range_clone_whole_file` doc for what today's implementation
    /// actually does).
    RangeClone,
    /// A hardlink from an immutable content-store object. Never selected
    /// for a mutable user-visible source — see [`CloneSource`].
    Hardlink,
    /// Full streaming reconstruction from blocks. Stubbed in this phase —
    /// see `yadorilink-sync-core::optimistic_placement::prepare_target`'s
    /// doc.
    StreamingReconstruction,
}

/// Why a stronger [`FastPath`] was rejected in favor of a weaker one.
/// Recorded, never silent — a slow safe fallback is permitted; an
/// unexplained one is a regression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastPathRejection {
    /// The target generation is not already materialized.
    TargetNotAlreadyMaterialized,
    /// The desired content identity differs from what a metadata-only
    /// update could preserve.
    ContentIdentityChanged,
    /// No [`CloneSource`] was supplied to clone or link from.
    NoLocalVersionAvailable,
    /// The relevant capability was not confirmed `Supported` on this
    /// volume — `Unsupported` or `Unknown` are treated identically here,
    /// per [`Capability::is_supported`][yadorilink_root_authority::fs_capabilities::Capability::is_supported].
    CapabilityNotConfirmedSupported,
    /// The only clone source supplied is not an immutable content-store
    /// object, so linking it would create a hardlink to a mutable
    /// user-visible target — never done.
    NoImmutableContentStoreSource,
}

/// The result of [`select_fast_path`]: the chosen path, plus every stronger
/// path considered and why it was rejected, strongest-considered-first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastPathDecision {
    pub selected: FastPath,
    pub rejected: Vec<(FastPath, FastPathRejection)>,
}

/// Where [`select_fast_path`] may clone or link bytes from. The two variants
/// are not interchangeable: only [`ImmutableContentStoreObject`] may ever be
/// hardlinked — see [`FastPath::Hardlink`].
///
/// [`ImmutableContentStoreObject`]: CloneSource::ImmutableContentStoreObject
#[derive(Debug, Clone, Copy)]
pub enum CloneSource<'a> {
    /// An existing local version of the same logical file — potentially
    /// still user-visible and mutable. Eligible for reflink/range clone,
    /// never for a hardlink.
    LocalVersionPath(&'a Path),
    /// An object under content-store custody, never exposed as a
    /// mutable user-visible path. Eligible for every fast path, including
    /// [`FastPath::Hardlink`].
    ImmutableContentStoreObject(&'a Path),
}

impl<'a> CloneSource<'a> {
    /// Public so `yadorilink-sync-core::optimistic_placement`'s own staging
    /// code -- which actually opens and reads/clones/hardlinks this path,
    /// none of which this crate may do -- can get at it.
    pub fn path(self) -> &'a Path {
        match self {
            CloneSource::LocalVersionPath(p) => p,
            CloneSource::ImmutableContentStoreObject(p) => p,
        }
    }
}

/// Everything [`select_fast_path`] needs to make its decision, all known
/// before any I/O the caller performs.
#[derive(Debug, Clone, Copy)]
pub struct PlacementInputs<'a> {
    pub target_already_materialized: bool,
    pub content_identity_unchanged: bool,
    pub clone_source: Option<CloneSource<'a>>,
    pub capabilities: &'a FilesystemSafetyCapabilities,
}

/// Selects the strongest verified [`FastPath`] for `inputs`, in exactly the
/// order fixed for preparation: no-op, metadata-only, reflink/clone,
/// range-clone, hardlink, full reconstruction. Pure — no I/O, no panics.
pub fn select_fast_path(inputs: &PlacementInputs) -> FastPathDecision {
    let mut rejected = Vec::new();

    if inputs.target_already_materialized {
        return FastPathDecision { selected: FastPath::NoOp, rejected };
    }
    rejected.push((FastPath::NoOp, FastPathRejection::TargetNotAlreadyMaterialized));

    if inputs.content_identity_unchanged && inputs.clone_source.is_some() {
        return FastPathDecision { selected: FastPath::MetadataOnly, rejected };
    }
    rejected.push((
        FastPath::MetadataOnly,
        if inputs.content_identity_unchanged {
            FastPathRejection::NoLocalVersionAvailable
        } else {
            FastPathRejection::ContentIdentityChanged
        },
    ));

    if inputs.clone_source.is_some() {
        if inputs.capabilities.reflink_or_clone.is_supported() {
            return FastPathDecision { selected: FastPath::ReflinkClone, rejected };
        }
        rejected.push((FastPath::ReflinkClone, FastPathRejection::CapabilityNotConfirmedSupported));

        if inputs.capabilities.range_clone.is_supported() {
            return FastPathDecision { selected: FastPath::RangeClone, rejected };
        }
        rejected.push((FastPath::RangeClone, FastPathRejection::CapabilityNotConfirmedSupported));
    } else {
        rejected.push((FastPath::ReflinkClone, FastPathRejection::NoLocalVersionAvailable));
        rejected.push((FastPath::RangeClone, FastPathRejection::NoLocalVersionAvailable));
    }

    if let Some(CloneSource::ImmutableContentStoreObject(_)) = inputs.clone_source {
        return FastPathDecision { selected: FastPath::Hardlink, rejected };
    }
    rejected.push((FastPath::Hardlink, FastPathRejection::NoImmutableContentStoreSource));

    FastPathDecision { selected: FastPath::StreamingReconstruction, rejected }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yadorilink_root_authority::fs_capabilities::Capability;

    fn caps(reflink: Capability, range: Capability) -> FilesystemSafetyCapabilities {
        FilesystemSafetyCapabilities {
            atomic_exchange: Capability::Supported,
            durable_file_flush: Capability::Supported,
            durable_directory_flush: Capability::Supported,
            stable_source_identity: Capability::Supported,
            stable_owned_marker_identity: Capability::Supported,
            stale_handle_preservation: Capability::Supported,
            metadata_fidelity: Capability::Supported,
            reflink_or_clone: reflink,
            range_clone: range,
        }
    }

    #[test]
    fn already_materialized_target_selects_no_op_with_no_rejections_recorded() {
        let capabilities = caps(Capability::Supported, Capability::Supported);
        let inputs = PlacementInputs {
            target_already_materialized: true,
            content_identity_unchanged: false,
            clone_source: None,
            capabilities: &capabilities,
        };
        let decision = select_fast_path(&inputs);
        assert_eq!(decision.selected, FastPath::NoOp);
        assert!(decision.rejected.is_empty());
    }

    #[test]
    fn unchanged_content_with_a_source_selects_metadata_only() {
        let capabilities = caps(Capability::Supported, Capability::Supported);
        let path = Path::new("/tmp/does-not-need-to-exist-for-this-pure-check");
        let inputs = PlacementInputs {
            target_already_materialized: false,
            content_identity_unchanged: true,
            clone_source: Some(CloneSource::LocalVersionPath(path)),
            capabilities: &capabilities,
        };
        let decision = select_fast_path(&inputs);
        assert_eq!(decision.selected, FastPath::MetadataOnly);
        assert_eq!(
            decision.rejected,
            vec![(FastPath::NoOp, FastPathRejection::TargetNotAlreadyMaterialized)]
        );
    }

    #[test]
    fn unchanged_content_without_a_source_falls_further_than_metadata_only() {
        // Content is unchanged, but nothing was supplied to clone even the
        // unchanged bytes from -- `MetadataOnly` cannot be selected without
        // a byte source, so this must fall through past it, not silently
        // claim a metadata-only update with nothing to metadata-patch.
        let capabilities = caps(Capability::Unsupported, Capability::Unsupported);
        let inputs = PlacementInputs {
            target_already_materialized: false,
            content_identity_unchanged: true,
            clone_source: None,
            capabilities: &capabilities,
        };
        let decision = select_fast_path(&inputs);
        assert_eq!(decision.selected, FastPath::StreamingReconstruction);
        assert!(decision
            .rejected
            .contains(&(FastPath::MetadataOnly, FastPathRejection::NoLocalVersionAvailable)));
    }

    #[test]
    fn changed_content_with_supported_reflink_selects_reflink_clone() {
        let capabilities = caps(Capability::Supported, Capability::Supported);
        let path = Path::new("/tmp/does-not-need-to-exist-for-this-pure-check");
        let inputs = PlacementInputs {
            target_already_materialized: false,
            content_identity_unchanged: false,
            clone_source: Some(CloneSource::LocalVersionPath(path)),
            capabilities: &capabilities,
        };
        let decision = select_fast_path(&inputs);
        assert_eq!(decision.selected, FastPath::ReflinkClone);
    }

    #[test]
    fn unsupported_reflink_falls_back_to_range_clone_when_supported() {
        let capabilities = caps(Capability::Unsupported, Capability::Supported);
        let path = Path::new("/tmp/does-not-need-to-exist-for-this-pure-check");
        let inputs = PlacementInputs {
            target_already_materialized: false,
            content_identity_unchanged: false,
            clone_source: Some(CloneSource::LocalVersionPath(path)),
            capabilities: &capabilities,
        };
        let decision = select_fast_path(&inputs);
        assert_eq!(decision.selected, FastPath::RangeClone);
        assert!(decision.rejected.contains(&(
            FastPath::ReflinkClone,
            FastPathRejection::CapabilityNotConfirmedSupported
        )));
    }

    #[test]
    fn unknown_capability_is_never_treated_as_supported() {
        // `Unknown` (not yet probed) must fall back exactly like
        // `Unsupported` -- never assumed to work.
        let capabilities = caps(Capability::Unknown, Capability::Unknown);
        let path = Path::new("/tmp/does-not-need-to-exist-for-this-pure-check");
        let inputs = PlacementInputs {
            target_already_materialized: false,
            content_identity_unchanged: false,
            clone_source: Some(CloneSource::LocalVersionPath(path)),
            capabilities: &capabilities,
        };
        let decision = select_fast_path(&inputs);
        assert_eq!(decision.selected, FastPath::StreamingReconstruction);
    }

    #[test]
    fn mutable_local_version_source_never_selects_hardlink() {
        let capabilities = caps(Capability::Unsupported, Capability::Unsupported);
        let path = Path::new("/tmp/does-not-need-to-exist-for-this-pure-check");
        let inputs = PlacementInputs {
            target_already_materialized: false,
            content_identity_unchanged: false,
            clone_source: Some(CloneSource::LocalVersionPath(path)),
            capabilities: &capabilities,
        };
        let decision = select_fast_path(&inputs);
        assert_ne!(decision.selected, FastPath::Hardlink);
        assert_eq!(decision.selected, FastPath::StreamingReconstruction);
    }

    #[test]
    fn immutable_content_store_source_with_no_clone_capability_selects_hardlink() {
        let capabilities = caps(Capability::Unsupported, Capability::Unsupported);
        let path = Path::new("/tmp/does-not-need-to-exist-for-this-pure-check");
        let inputs = PlacementInputs {
            target_already_materialized: false,
            content_identity_unchanged: false,
            clone_source: Some(CloneSource::ImmutableContentStoreObject(path)),
            capabilities: &capabilities,
        };
        let decision = select_fast_path(&inputs);
        assert_eq!(decision.selected, FastPath::Hardlink);
    }

    #[test]
    fn no_source_at_all_falls_all_the_way_to_streaming_reconstruction() {
        let capabilities = caps(Capability::Supported, Capability::Supported);
        let inputs = PlacementInputs {
            target_already_materialized: false,
            content_identity_unchanged: false,
            clone_source: None,
            capabilities: &capabilities,
        };
        let decision = select_fast_path(&inputs);
        assert_eq!(decision.selected, FastPath::StreamingReconstruction);
        // NoOp, MetadataOnly, ReflinkClone, RangeClone, Hardlink -- every
        // stronger path in the fixed order, each rejected for its own
        // reason.
        assert_eq!(decision.rejected.len(), 5);
    }
}

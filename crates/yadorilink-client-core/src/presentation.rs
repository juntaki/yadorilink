//! A renderer-neutral description of why something needs attention: a stable key (the reason
//! code), structured arguments, a suggested action and a severity. Renderers (CLI, Swift, WinUI)
//! own the final text; `fallback_en` is only an English fallback kept next to the mapping.

/// Every reason code the daemon's attention rollup and the held-file list can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasonCode {
    Degraded,
    Ambiguous,
    DurabilityAtRisk,
    DurabilityUnknown,
    FetchUnavailable,
    FetchAvailabilityUnknown,
    Conflict,
    Held,
    ProviderNotReady,
    ProviderStuck,
    KeptEdits,
    ProviderOrphanDomain,
    LowDiskCritical,
    LowDisk,
    PeerDisconnected,
    RecentError,
    UpdateFailed,
    CaseCollision,
    NormalizationCollision,
    CaseAndNormalizationCollision,
    InvalidName,
    MetadataUnprovable,
    VolumeChanged,
    OwnershipLost,
}

impl ReasonCode {
    pub const ALL: [ReasonCode; 24] = [
        Self::Degraded,
        Self::Ambiguous,
        Self::DurabilityAtRisk,
        Self::DurabilityUnknown,
        Self::FetchUnavailable,
        Self::FetchAvailabilityUnknown,
        Self::Conflict,
        Self::Held,
        Self::ProviderNotReady,
        Self::ProviderStuck,
        Self::KeptEdits,
        Self::ProviderOrphanDomain,
        Self::LowDiskCritical,
        Self::LowDisk,
        Self::PeerDisconnected,
        Self::RecentError,
        Self::UpdateFailed,
        Self::CaseCollision,
        Self::NormalizationCollision,
        Self::CaseAndNormalizationCollision,
        Self::InvalidName,
        Self::MetadataUnprovable,
        Self::VolumeChanged,
        Self::OwnershipLost,
    ];

    /// The stable wire/resource key (the daemon's code string).
    #[must_use]
    pub fn key(self) -> &'static str {
        match self {
            Self::Degraded => "degraded",
            Self::Ambiguous => "ambiguous",
            Self::DurabilityAtRisk => "durability_at_risk",
            Self::DurabilityUnknown => "durability_unknown",
            Self::FetchUnavailable => "fetch_unavailable",
            Self::FetchAvailabilityUnknown => "fetch_availability_unknown",
            Self::Conflict => "conflict",
            Self::Held => "held",
            Self::ProviderNotReady => "provider_not_ready",
            Self::ProviderStuck => "provider_stuck",
            Self::KeptEdits => "kept_edits",
            Self::ProviderOrphanDomain => "provider_orphan_domain",
            Self::LowDiskCritical => "low_disk_critical",
            Self::LowDisk => "low_disk",
            Self::PeerDisconnected => "peer_disconnected",
            Self::RecentError => "recent_error",
            Self::UpdateFailed => "update_failed",
            Self::CaseCollision => "case_collision",
            Self::NormalizationCollision => "normalization_collision",
            Self::CaseAndNormalizationCollision => "case_and_normalization_collision",
            Self::InvalidName => "invalid_name",
            Self::MetadataUnprovable => "metadata_unprovable",
            Self::VolumeChanged => "volume_changed",
            Self::OwnershipLost => "ownership_lost",
        }
    }

    /// Parses the part of a raw reason before the first `:`.
    #[must_use]
    pub fn parse(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.key() == code)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuggestedAction {
    None,
    /// Look at the folder's details.
    ReviewDetails,
    /// Fix the folder's link(s).
    Relink,
    ReviewConflicts,
    FreeDiskSpace,
    /// Another device must come back; diagnostics show what is reachable.
    WaitForPeer,
    CheckUpdate,
    ManageProviderFolder,
    /// Rename one of the colliding files.
    RenameFile,
    /// Rename the file on the device that has it.
    RenameOnOriginDevice,
    MakeFileReadable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Attention,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Presentation {
    pub key: ReasonCode,
    /// Structured argument: the subject after the first `:` (folder, device, ...), if any.
    pub subject: Option<String>,
    pub action: SuggestedAction,
    pub severity: Severity,
    /// English fallback sentence; renderers own the final text.
    pub fallback_en: &'static str,
}

/// Maps a reason code to its presentation. The one place these mappings live.
#[must_use]
pub fn presentation(code: ReasonCode, subject: &str) -> Presentation {
    use ReasonCode as R;
    use Severity::{Attention, Error, Info};
    use SuggestedAction as A;
    let (action, severity, fallback_en) = match code {
        R::Degraded => (A::ReviewDetails, Error, "This folder is paused by a problem and will retry."),
        R::Ambiguous => (A::Relink, Error, "This folder is linked in more than one place, so nothing syncs."),
        R::DurabilityAtRisk => (A::ReviewDetails, Error, "This folder has no safe second copy; losing this disk would lose data."),
        R::DurabilityUnknown => (A::ReviewDetails, Attention, "This folder cannot confirm it is safely stored on disk yet."),
        R::FetchUnavailable => (A::WaitForPeer, Attention, "Files that are not downloaded cannot be fetched right now."),
        R::FetchAvailabilityUnknown => (A::WaitForPeer, Info, "It is not known yet whether missing files can be fetched."),
        R::Conflict => (A::ReviewConflicts, Attention, "Some files have conflicting copies."),
        R::Held => (A::ReviewDetails, Attention, "Some files were not applied to this device."),
        R::ProviderNotReady => (A::ReviewDetails, Attention, "This provider folder is not ready to use."),
        R::ProviderStuck => (A::ReviewDetails, Error, "Some files in this provider folder keep failing to download."),
        R::KeptEdits => (A::ReviewDetails, Attention, "Edits were kept beside a file instead of replacing it."),
        R::ProviderOrphanDomain => (A::ManageProviderFolder, Attention, "A File Provider folder exists that no linked folder uses."),
        R::LowDiskCritical => (A::FreeDiskSpace, Error, "The disk is almost full, so syncing is paused."),
        R::LowDisk => (A::FreeDiskSpace, Attention, "The disk is running low on space."),
        R::PeerDisconnected => (A::WaitForPeer, Attention, "Another device cannot be reached."),
        R::RecentError => (A::ReviewDetails, Error, "Something went wrong recently while syncing."),
        R::UpdateFailed => (A::CheckUpdate, Attention, "The last update did not finish."),
        R::CaseCollision => (A::RenameFile, Attention, "Its name differs only by upper/lower case from another file."),
        R::NormalizationCollision => (A::RenameFile, Attention, "Its name looks the same as another file's once accents are normalized."),
        R::CaseAndNormalizationCollision => (A::RenameFile, Attention, "Its name looks the same as another file's by case and accents."),
        R::InvalidName => (A::RenameOnOriginDevice, Attention, "Its name is not allowed on this device."),
        R::MetadataUnprovable => (A::MakeFileReadable, Attention, "The existing file on this device cannot be read by you, so its update was not applied."),
        R::VolumeChanged => (A::Relink, Attention, "This folder is no longer on the disk it was set up on, so deletions are not synced until that disk is back or the folder is linked again."),
        R::OwnershipLost => (A::Relink, Error, "This folder's ownership marker is gone; re-link or restart to continue."),
    };
    Presentation {
        key: code,
        subject: (!subject.is_empty()).then(|| subject.to_owned()),
        action,
        severity,
        fallback_en,
    }
}

/// Raw `code[:subject]` -> presentation, or `None` for a code this build does not know.
#[must_use]
pub fn presentation_for_raw(raw: &str) -> Option<Presentation> {
    let (code, subject) = raw.split_once(':').unwrap_or((raw, ""));
    ReasonCode::parse(code).map(|c| presentation(c, subject.trim()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_has_a_stable_unique_key_and_mapping() {
        let mut keys = std::collections::HashSet::new();
        for c in ReasonCode::ALL {
            assert!(keys.insert(c.key()), "duplicate key {}", c.key());
            assert_eq!(ReasonCode::parse(c.key()), Some(c));
            let p = presentation(c, "");
            assert_eq!(p.key, c);
            assert!(!p.fallback_en.is_empty());
            assert!(p.subject.is_none());
        }
        assert_eq!(keys.len(), 24);
    }

    #[test]
    fn keys_are_frozen() {
        let keys: Vec<_> = ReasonCode::ALL.iter().map(|c| c.key()).collect();
        assert_eq!(
            keys.join(","),
            "degraded,ambiguous,durability_at_risk,durability_unknown,fetch_unavailable,\
fetch_availability_unknown,conflict,held,provider_not_ready,provider_stuck,kept_edits,\
provider_orphan_domain,low_disk_critical,low_disk,peer_disconnected,recent_error,update_failed,\
case_collision,normalization_collision,case_and_normalization_collision,invalid_name,\
metadata_unprovable,volume_changed,ownership_lost"
        );
    }

    #[test]
    fn raw_splits_subject_and_unknown_is_none() {
        let p = presentation_for_raw("conflict: docs").unwrap();
        assert_eq!(p.key, ReasonCode::Conflict);
        assert_eq!(p.subject.as_deref(), Some("docs"));
        assert!(presentation_for_raw("brand_new:x").is_none());
    }
}

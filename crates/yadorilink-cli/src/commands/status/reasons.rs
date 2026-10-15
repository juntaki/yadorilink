//! Turns every problem `status` can show into its cause and the command to run next. The
//! meaning of a problem comes from the shared `AttentionItem`; only the words and commands are the
//! CLI's.

use yadorilink_client_core::attention::{Attention, AttentionItem};

/// The cause, as one sentence.
fn cause(item: AttentionItem) -> &'static str {
    use AttentionItem as I;
    match item {
        I::FolderStopped => "This folder is paused by a problem and will retry.",
        I::LinkedTwice => "This folder is linked in more than one place, so nothing syncs.",
        I::OwnershipLost => "This folder's ownership marker is gone; re-link or restart to continue.",
        I::VolumeChanged => "This folder is no longer on the disk it was set up on, so deletions are not synced until that disk is back or the folder is linked again.",
        I::NoSafeCopy => "This folder has no safe second copy; losing this disk would lose data.",
        I::SafeCopyUnconfirmed => "This folder cannot confirm it is safely stored on disk yet.",
        I::ContentUnavailable => "Files that are not downloaded cannot be fetched right now.",
        I::ContentAvailabilityUnknown => "It is not known yet whether missing files can be fetched.",
        I::ConflictNeedsReview => "Some files have conflicting copies.",
        I::FileHeld => "Some files were not applied to this device.",
        I::UnsupportedFilename => "Its name cannot be used on this device: it collides with another file's name or is not allowed here.",
        I::FileNotReadable => "The existing file on this device cannot be read by you, so its update was not applied.",
        I::StrandedDirectory => "A folder could not be removed safely and was left under a temporary name; nothing was deleted.",
        I::ProviderNotReady => "This provider folder is not ready to use.",
        I::ProviderFilesFailing => "Some files in this provider folder keep failing to download.",
        I::EditsKeptBeside => "Edits were kept beside a file instead of replacing it.",
        I::ProviderOrphan => "A File Provider folder exists that no linked folder uses.",
        I::DiskFull => "The disk is almost full, so syncing is paused.",
        I::DiskLow => "The disk is running low on space.",
        I::PeerUnavailable => "Another device cannot be reached.",
        I::RetryableFailure => "Something went wrong recently while syncing.",
        I::UpdateFailed => "The last update did not finish.",
        I::Unrecognized => "Needs attention.",
    }
}

/// What to do next, in the CLI's terms.
fn next_step(item: AttentionItem) -> &'static str {
    use AttentionItem as I;
    match item {
        I::LinkedTwice | I::OwnershipLost | I::VolumeChanged => "yadorilink links",
        I::ConflictNeedsReview => "yadorilink conflicts list",
        I::DiskFull | I::DiskLow => "yadorilink gc --dry-run",
        I::ContentUnavailable | I::ContentAvailabilityUnknown | I::PeerUnavailable => {
            "yadorilink doctor"
        }
        I::UpdateFailed => "yadorilink update status",
        I::ProviderOrphan => "yadorilink provider-folder --help",
        I::UnsupportedFilename => {
            "rename the file (on the device that has it, if the name is not allowed here)"
        }
        I::FileNotReadable => "make the file readable (chmod u+r)",
        I::FolderStopped
        | I::NoSafeCopy
        | I::SafeCopyUnconfirmed
        | I::FileHeld
        | I::StrandedDirectory
        | I::ProviderNotReady
        | I::ProviderFilesFailing
        | I::EditsKeptBeside
        | I::RetryableFailure
        | I::Unrecognized => "yadorilink status --details",
    }
}

/// The cause and the next step for a problem. `raw` stays visible only when `verbose`.
pub(super) fn explain(
    attention: &Attention,
    raw: &str,
    subject_name: &str,
    verbose: bool,
) -> String {
    let subject =
        if subject_name.is_empty() { String::new() } else { format!(" [{subject_name}]") };
    let item = attention.item;
    let mut text = if item == AttentionItem::Unrecognized && verbose {
        format!("Needs attention (code: {raw}){subject}")
    } else if item == AttentionItem::Unrecognized {
        format!("Needs attention{subject} Next: {}", next_step(item))
    } else {
        format!("{}{subject} Next: {}", cause(item), next_step(item))
    };
    if verbose && item != AttentionItem::Unrecognized {
        text.push_str(&format!("  (code: {raw})"));
    }
    text
}

/// The cause and next step for one held file's reason.
pub(super) fn explain_held(raw: &str) -> String {
    explain(&Attention::from_held_reason(raw), raw, "", false)
}

/// The cause and next step for one rollup reason (`code[:subject]`).
pub(super) fn explain_reason(raw: &str, subject_name: &str, verbose: bool) -> String {
    explain(&Attention::from_reason(raw), raw, subject_name, verbose)
}

/// A reason code split into its code and its subject (the text after the first `:`).
pub(super) fn split_code(raw: &str) -> (&str, &str) {
    raw.split_once(':').unwrap_or((raw, ""))
}

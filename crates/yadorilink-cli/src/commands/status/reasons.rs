//! Turns every reason code `status` can show into a plain sentence and the command to run next,
//! using the shared client-core `Presentation`.

use yadorilink_client_core::presentation::{presentation, ReasonCode, SuggestedAction};

/// The command to run next for a suggested action.
fn command_for(action: SuggestedAction) -> &'static str {
    match action {
        SuggestedAction::None | SuggestedAction::ReviewDetails => "yadorilink status --details",
        SuggestedAction::Relink => "yadorilink links",
        SuggestedAction::ReviewConflicts => "yadorilink conflicts list",
        SuggestedAction::FreeDiskSpace => "yadorilink gc --dry-run",
        SuggestedAction::WaitForPeer => "yadorilink doctor",
        SuggestedAction::CheckUpdate => "yadorilink update status",
        SuggestedAction::ManageProviderFolder => "yadorilink provider-folder --help",
        SuggestedAction::RenameFile => "rename one of the files",
        SuggestedAction::RenameOnOriginDevice => "rename the file on the device that has it",
        SuggestedAction::MakeFileReadable => "make the file readable (chmod u+r)",
    }
}

/// A reason code split into its code and its subject (the text after the first `:`).
pub(super) fn split_code(raw: &str) -> (&str, &str) {
    raw.split_once(':').unwrap_or((raw, ""))
}

/// The plain sentence and the next command for a code, or the fallback.
/// `raw` stays visible only when `verbose`.
pub(super) fn explain(raw: &str, subject_name: &str, verbose: bool) -> String {
    let (code, _) = split_code(raw);
    let subject =
        if subject_name.is_empty() { String::new() } else { format!(" [{subject_name}]") };
    let known = ReasonCode::parse(code).map(|c| presentation(c, ""));
    let mut text = match &known {
        Some(p) => format!("{}{subject} Next: {}", p.fallback_en, command_for(p.action)),
        None if verbose => format!("Needs attention (code: {raw}){subject}"),
        None => format!("Needs attention{subject} Next: yadorilink status --details"),
    };
    if verbose && known.is_some() {
        text.push_str(&format!("  (code: {raw})"));
    }
    text
}

//! The combined case-fold-and-Unicode-normalization equivalence key two
//! names collide under on a volume that is simultaneously case-insensitive
//! AND normalization-insensitive (the macOS default, both HFS+ and APFS).
//! Shared between `yadorilink-peer-session`'s hazard checks and
//! `yadorilink-sync-core`'s path-lock keying (`sync_runtime::path_locks`)
//! so the lock a hazard check runs under and the equivalence the hazard
//! check itself applies never drift apart from each other -- moved here in
//! Phase 7D-6 since both are real production consumers on either side of
//! the peer-session/sync-core boundary.

/// Folds `path` to the case-and-normalization-insensitive key two
/// differently-encoded names collapse to on such a volume: NFC-normalize,
/// then case-fold (`caseless::default_case_fold_str`, not
/// `str::to_lowercase` -- case folding, not the lowercase *mapping*, is
/// what matches how a case-insensitive filesystem actually collides two
/// names), then NFC-normalize again (case folding can itself introduce a
/// decomposed form).
pub fn canonical_fold(path: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    let step1: String = path.nfc().collect();
    let folded = caseless::default_case_fold_str(&step1);
    folded.nfc().collect()
}

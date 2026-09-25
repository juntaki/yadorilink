#![cfg(test)]

use super::*;

#[test]
fn the_probe_covers_more_than_one_script() {
    // A probe of kanji alone would accept a Chinese face that draws no
    // kana at all -- exactly the font sitting next to the Japanese one
    // in the same directory on macOS.
    assert!(PROBE.chars().any(|c| ('\u{3040}'..='\u{309f}').contains(&c)), "hiragana");
    assert!(PROBE.chars().any(|c| ('\u{4e00}'..='\u{9fff}').contains(&c)), "han");
    assert!(PROBE.chars().any(|c| ('\u{ac00}'..='\u{d7af}').contains(&c)), "hangul");
    assert!(PROBE.chars().any(|c| ('\u{0400}'..='\u{04ff}').contains(&c)), "cyrillic");
}

#[test]
fn preferred_names_sort_ahead_of_unknown_ones() {
    let known = preference_rank(Path::new("/x/HiraginoSans-W3.ttc"));
    let unknown = preference_rank(Path::new("/x/SomeDisplayFace.ttf"));
    assert!(known < unknown);
}

#[test]
fn preference_is_only_a_hint_so_unknown_names_are_still_ranked() {
    // An unknown name must come back with a real rank rather than
    // being dropped: the search still has to try it.
    assert_eq!(preference_rank(Path::new("/x/Unknown.ttf")), PREFERRED_HINTS.len());
}

#[test]
fn a_failed_search_records_the_consequence_rather_than_just_a_flag() {
    // The point of the status file is that a machine rendering boxes
    // says so. A bare `resolved: false` with nothing else would leave
    // the next reader exactly as puzzled as the original bug did.
    let outcome = Outcome::NotFound { searched: vec![PathBuf::from("/x")], examined: 7 };
    assert_eq!(outcome.installed_path(), None);
    let Outcome::NotFound { searched, examined } = &outcome else {
        unreachable!();
    };
    assert_eq!(examined, &7);
    assert_eq!(searched.len(), 1);
}

#[test]
fn font_files_finds_nothing_in_a_directory_that_does_not_exist() {
    let mut out = Vec::new();
    font_files(Path::new("/definitely/not/a/font/directory"), 0, &mut out);
    assert!(out.is_empty());
}

#[test]
fn a_font_that_is_not_a_font_at_all_covers_nothing() {
    assert!(!covers_probe(b"this is not a font file", 0));
}

#[test]
fn every_search_directory_is_absolute() {
    for dir in font_dirs() {
        assert!(dir.is_absolute(), "{dir:?} must be absolute");
    }
}

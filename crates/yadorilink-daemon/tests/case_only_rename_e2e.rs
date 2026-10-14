//! A case-only rename on one device reaches its peer as the new spelling alone, whatever the
//! case sensitivity of either volume: the old name's observed absence is the rename's delete,
//! and the delete must not remove the new name on a peer that folds the two together.

mod native_e2e_support;
mod support;

use native_e2e_support::*;

const GROUP: &str = "case-only-rename-group";

fn setup() {
    support::ensure_isolated_config_dir();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_case_only_rename_leaves_the_new_spelling_alone_on_both_devices() {
    setup();
    let a = device("case-a", GROUP);
    let b = device("case-b", GROUP);
    pair(&a, &b, GROUP).await;
    write(&a, "Photo.jpg", b"pixels");
    converge_to(&[&a, &b], &[("Photo.jpg", b"pixels")], "the file replicated").await;

    rename(&a, "Photo.jpg", "photo.jpg");

    converge_to(&[&a, &b], &[("photo.jpg", b"pixels")], "the new spelling replicated").await;
    assert_eq!(tree(&a).keys().collect::<Vec<_>>(), vec!["photo.jpg"]);
    assert_eq!(tree(&b).keys().collect::<Vec<_>>(), vec!["photo.jpg"]);
}

/// The same rename of a name with an accent: a volume that lists it decomposed still has the old
/// entry, and the new spelling replaces it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_case_only_rename_of_an_accented_name_reaches_the_peer() {
    setup();
    let a = device("case-nfc-a", GROUP);
    let b = device("case-nfc-b", GROUP);
    pair(&a, &b, GROUP).await;
    write(&a, "Caf\u{e9}.jpg", b"pixels");
    converge_to(&[&a, &b], &[("Caf\u{e9}.jpg", b"pixels")], "the file replicated").await;

    rename(&a, "Caf\u{e9}.jpg", "caf\u{e9}.jpg");

    converge_to(&[&a, &b], &[("caf\u{e9}.jpg", b"pixels")], "the new spelling replicated").await;
}

/// A zero-byte file has no blocks, and its case-only rename must still reach the peer: the
/// old spelling's tombstone may not wait on a new spelling that is itself held by that sibling.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_case_only_rename_of_a_zero_byte_file_reaches_the_peer() {
    setup();
    let a = device("case-empty-a", GROUP);
    let b = device("case-empty-b", GROUP);
    pair(&a, &b, GROUP).await;
    write(&a, "Empty.txt", b"");
    converge_to(&[&a, &b], &[("Empty.txt", b"")], "the empty file replicated").await;

    rename(&a, "Empty.txt", "empty.txt");

    converge_to(&[&a, &b], &[("empty.txt", b"")], "the new spelling replicated").await;
    assert_eq!(tree(&b).keys().collect::<Vec<_>>(), vec!["empty.txt"]);
}

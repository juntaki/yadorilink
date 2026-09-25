#![cfg(test)]

use super::test_support::{
    a_file_version, bundle_carrying, change_putting, checkpoint, conn, stage_in_tx, GROUP,
};
use super::*;

/// Possession and admissibility become true together, or neither does.
///
/// This module is where possession is *defined* — a row here is what
/// `servable_change_hashes` returns and what a peer reads as "already
/// delivered, do not send again". So the exact-set contract is enforced
/// here as well as at the wire boundary, not only there: a Change staged
/// without the versions it refers to would be advertised as possessed and
/// could never be admitted, and no peer would ever send it again.
#[test]
fn a_change_that_writes_content_is_staged_only_with_the_versions_it_refers_to() {
    let c = conn();
    let version = a_file_version(0x11);
    let change = change_putting("photo.jpg", &version);

    // Without them: refused whole, nothing possessed.
    let missing = bundle_carrying(change.clone(), checkpoint(1), vec![]);
    assert!(stage_in_tx(&c, std::slice::from_ref(&missing), 1).is_err());
    assert!(servable_change_hashes(&c, &FolderGroupId(GROUP.into())).unwrap().is_empty());

    // With something else as well: also refused. A Change must not be
    // usable as a carrier for metadata it does not refer to.
    let extra =
        bundle_carrying(change.clone(), checkpoint(1), vec![version.clone(), a_file_version(0x22)]);
    assert!(stage_in_tx(&c, std::slice::from_ref(&extra), 1).is_err());
    assert!(servable_change_hashes(&c, &FolderGroupId(GROUP.into())).unwrap().is_empty());

    // Exactly right: staged, and the version is durable alongside it.
    let honest = bundle_carrying(change.clone(), checkpoint(1), vec![version.clone()]);
    let staged = stage_in_tx(&c, std::slice::from_ref(&honest), 1).unwrap();
    assert_eq!(staged, vec![change.compute_hash()]);

    let stored: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM verified_change_versions WHERE version_hash = ?1",
            rusqlite::params![&version.version_hash.0[..]],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored, 1);

    // And it is served back whole, so the next peer gets the same
    // self-contained bundle this one did.
    let served = load_servable(&c, &change.compute_hash()).unwrap().unwrap();
    assert_eq!(
        served.versions.iter().map(|v| v.version_hash).collect::<Vec<_>>(),
        vec![version.version_hash]
    );
}

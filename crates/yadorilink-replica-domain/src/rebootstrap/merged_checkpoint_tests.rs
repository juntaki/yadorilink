//! How a base minted over the join of two histories is bound to the
//! checkpoint, the manifest and the advertisement that name it.

use super::*;
use crate::base_negotiation::{AdvertisedBase, BaseAdvertisement, SummaryIdentity};

fn group() -> FolderGroupId {
    FolderGroupId("g".to_string())
}

fn base(byte: u8) -> HistoryBase {
    HistoryBase([byte; 32])
}

fn joined(byte: u8) -> SummaryIdentity {
    SummaryIdentity([byte; 32])
}

fn merged(snapshot_seed: u8) -> Checkpoint {
    Checkpoint::new_merged(
        group(),
        Vec::new(),
        [snapshot_seed; 32],
        MergedFrom::new(base(2), base(1), joined(9)).unwrap(),
    )
}

/// The base above a merged checkpoint is the one minted over what it
/// merged -- not one derived from the checkpoint's hash -- so every path
/// that names a base by its checkpoint names the minted base.
#[test]
fn a_merged_checkpoint_derives_the_minted_base() {
    let minted = HistoryBase::mint_merged(&group(), base(1), base(2), &joined(9));

    assert_eq!(HistoryBase::from_checkpoint(&merged(5)), minted);
}

/// Two replicas lay out the rows of the same joined summary however each
/// does; the base they found is the same.
#[test]
fn the_minted_base_does_not_depend_on_the_snapshot_bytes() {
    assert_ne!(merged(5).checkpoint_hash(), merged(6).checkpoint_hash());
    assert_eq!(HistoryBase::from_checkpoint(&merged(5)), HistoryBase::from_checkpoint(&merged(6)));
}

/// A merged checkpoint is not a sealing one with the same fields: it
/// encodes under its own tag, round-trips, and a sealing checkpoint's
/// bytes are what they always were.
#[test]
fn a_merged_checkpoint_has_its_own_encoding() {
    let checkpoint = merged(5);
    let sealing = Checkpoint::new(group(), Vec::new(), [5; 32]);

    assert_eq!(Checkpoint::decode(&checkpoint.canonical_encoding()).unwrap(), checkpoint);
    assert_ne!(checkpoint.canonical_encoding(), sealing.canonical_encoding());
    assert_ne!(checkpoint.checkpoint_hash(), sealing.checkpoint_hash());

    let mut expected = b"YLNKckp\x03".to_vec();
    expected.extend_from_slice(&1u32.to_be_bytes());
    expected.extend_from_slice(b"g");
    expected.extend_from_slice(&0u32.to_be_bytes());
    expected.extend_from_slice(&[5; 32]);
    assert_eq!(sealing.canonical_encoding(), expected, "a sealing checkpoint's bytes are pinned");
}

/// The merged bases are carried in one canonical order, and a merge of a
/// base with itself is not a merge.
#[test]
fn a_merged_checkpoint_is_canonical() {
    assert_eq!(
        MergedFrom::new(base(1), base(2), joined(9)).unwrap(),
        MergedFrom::new(base(2), base(1), joined(9)).unwrap()
    );
    assert!(MergedFrom::new(base(1), base(1), joined(9)).is_err());

    let mut swapped = merged(5).canonical_encoding();
    let tail = swapped.len() - 96;
    let (low, high) = (swapped[tail..tail + 32].to_vec(), swapped[tail + 32..tail + 64].to_vec());
    swapped[tail..tail + 32].copy_from_slice(&high);
    swapped[tail + 32..tail + 64].copy_from_slice(&low);
    assert!(Checkpoint::decode(&swapped).is_err(), "bases out of order do not decode");
}

/// A manifest over a merged checkpoint is signed and verified exactly as
/// one over a sealing checkpoint, and names the minted base.
#[test]
fn a_manifest_over_a_merged_checkpoint_names_the_minted_base() {
    let key = SigningKey::from_bytes(&[3; 32]);
    let manifest = SnapshotManifest::new_signed(
        merged(5),
        Vec::new(),
        None,
        DeviceId("signer".to_string()),
        &key,
    )
    .unwrap();
    let trust = |_: &str| Some(key.verifying_key().to_bytes());

    manifest.verify(&trust).unwrap();
    assert_eq!(manifest.history_base, HistoryBase::from_checkpoint(&merged(5)));
    assert_eq!(SnapshotManifest::decode(&manifest.canonical_encoding()).unwrap(), manifest);
}

/// An advertisement of a merged base decodes, and names the minted base.
#[test]
fn an_advertisement_of_a_merged_base_names_the_minted_base() {
    let advertisement = BaseAdvertisement::new(
        group(),
        AdvertisedBase::Installed { checkpoint: Box::new(merged(5)), summary: joined(9) },
        Vec::new(),
    )
    .unwrap();

    let decoded = BaseAdvertisement::decode(&advertisement.encode()).unwrap();

    assert_eq!(decoded, advertisement);
    assert_eq!(
        decoded.base.epoch(),
        HistoryEpoch::Base(HistoryBase::mint_merged(&group(), base(1), base(2), &joined(9)))
    );
}

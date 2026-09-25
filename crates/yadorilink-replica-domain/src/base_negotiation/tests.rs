use super::*;

fn group() -> FolderGroupId {
    FolderGroupId("group-base-negotiation".into())
}

fn hash(seed: u8) -> ChangeHash {
    ChangeHash([seed; 32])
}

fn checkpoint(snapshot_seed: u8) -> Checkpoint {
    Checkpoint::new(group(), vec![hash(1), hash(2)], [snapshot_seed; 32])
}

fn genesis(heads: Vec<ChangeHash>) -> BaseAdvertisement {
    BaseAdvertisement::new(group(), AdvertisedBase::Genesis, heads).unwrap()
}

fn installed(snapshot_seed: u8, summary_seed: u8) -> BaseAdvertisement {
    BaseAdvertisement::new(
        group(),
        AdvertisedBase::Installed {
            checkpoint: Box::new(checkpoint(snapshot_seed)),
            summary: SummaryIdentity([summary_seed; 32]),
        },
        vec![hash(9)],
    )
    .unwrap()
}

fn kind(negotiation: &BaseNegotiation) -> &'static str {
    match negotiation {
        BaseNegotiation::SameBase => "same",
        BaseNegotiation::MergeRequired(_) => "merge",
        BaseNegotiation::Refused(_) => "refused",
    }
}

#[test]
fn advertisements_round_trip_through_their_encoding() {
    for advertisement in [genesis(vec![hash(3), hash(1)]), genesis(Vec::new()), installed(5, 6)] {
        let decoded = BaseAdvertisement::decode(&advertisement.encode()).unwrap();
        assert_eq!(decoded, advertisement);
    }
}

#[test]
fn heads_are_canonicalized_and_cut_at_the_bound_with_the_true_count_kept() {
    let heads: Vec<ChangeHash> = (0..(MAX_ADVERTISED_HEADS as u32 + 5))
        .rev()
        .map(|index| {
            let mut bytes = [0u8; 32];
            bytes[..4].copy_from_slice(&index.to_be_bytes());
            ChangeHash(bytes)
        })
        .collect();
    let advertisement = genesis(heads);
    assert_eq!(advertisement.active_heads.len(), MAX_ADVERTISED_HEADS);
    assert_eq!(advertisement.active_head_count, MAX_ADVERTISED_HEADS as u64 + 5);
    assert!(advertisement.active_heads.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(BaseAdvertisement::decode(&advertisement.encode()).unwrap(), advertisement);
}

/// A peer cannot name one base and carry another base's checkpoint: the
/// named base must be the one the carried checkpoint derives.
#[test]
fn a_base_that_does_not_derive_from_its_checkpoint_is_refused_on_decode() {
    let mut bytes = installed(5, 6).encode();
    // The claimed base sits right after the domain tag, the group and the
    // installed tag.
    let at = 8 + 4 + group().as_str().len() + 1;
    bytes[at] ^= 0xFF;
    let error = BaseAdvertisement::decode(&bytes).unwrap_err();
    assert!(error.to_string().contains("does not derive"), "{error}");
}

#[test]
fn a_checkpoint_of_another_group_is_refused() {
    let other = Checkpoint::new(FolderGroupId("elsewhere".into()), vec![hash(1)], [5; 32]);
    let error = BaseAdvertisement::new(
        group(),
        AdvertisedBase::Installed {
            checkpoint: Box::new(other.clone()),
            summary: SummaryIdentity([6; 32]),
        },
        Vec::new(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("another group"), "{error}");

    // The same, arriving over the wire rather than built here.
    let honest = BaseAdvertisement {
        group_id: group(),
        base: AdvertisedBase::Installed {
            checkpoint: Box::new(other),
            summary: SummaryIdentity([6; 32]),
        },
        active_heads: Vec::new(),
        active_head_count: 0,
    };
    assert!(BaseAdvertisement::decode(&honest.encode()).is_err());
}

#[test]
fn non_canonical_or_inconsistent_head_lists_are_refused() {
    let descending = BaseAdvertisement {
        group_id: group(),
        base: AdvertisedBase::Genesis,
        active_heads: vec![hash(2), hash(1)],
        active_head_count: 2,
    };
    assert!(BaseAdvertisement::decode(&descending.encode()).is_err());

    // A count above the list is only honest where the list was cut.
    let short = BaseAdvertisement {
        group_id: group(),
        base: AdvertisedBase::Genesis,
        active_heads: vec![hash(1)],
        active_head_count: 7,
    };
    assert!(BaseAdvertisement::decode(&short.encode()).is_err());

    let under = BaseAdvertisement {
        group_id: group(),
        base: AdvertisedBase::Genesis,
        active_heads: vec![hash(1), hash(2)],
        active_head_count: 1,
    };
    assert!(BaseAdvertisement::decode(&under.encode()).is_err());

    let mut trailing = genesis(vec![hash(1)]).encode();
    trailing.push(0);
    assert!(BaseAdvertisement::decode(&trailing).is_err());

    let mut truncated = genesis(vec![hash(1)]).encode();
    truncated.pop();
    assert!(BaseAdvertisement::decode(&truncated).is_err());
}

#[test]
fn the_same_base_reconciles_whatever_the_heads() {
    assert_eq!(
        negotiate(&genesis(vec![hash(1)]), &genesis(vec![hash(2)])),
        BaseNegotiation::SameBase
    );
    assert_eq!(negotiate(&installed(5, 6), &installed(5, 6)), BaseNegotiation::SameBase);
}

#[test]
fn a_different_base_requires_a_merge_and_carries_the_claim_as_made() {
    let local = genesis(vec![hash(1)]);
    let peer = installed(5, 6);
    match negotiate(&local, &peer) {
        BaseNegotiation::MergeRequired(foreign) => {
            assert_eq!(foreign.local_epoch, HistoryEpoch::Genesis);
            assert_eq!(foreign.claim, peer);
        }
        other => panic!("expected a merge to be required, got {other:?}"),
    }

    // Two different installed bases, too.
    assert!(matches!(
        negotiate(&installed(5, 6), &installed(7, 6)),
        BaseNegotiation::MergeRequired(_)
    ));
}

#[test]
fn one_base_with_two_summaries_is_refused_rather_than_reconciled_or_merged() {
    match negotiate(&installed(5, 6), &installed(5, 8)) {
        BaseNegotiation::Refused(BaseRefusal::SummaryConflict { local, peer, .. }) => {
            assert_eq!(local, SummaryIdentity([6; 32]));
            assert_eq!(peer, SummaryIdentity([8; 32]));
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn an_advertisement_for_another_group_is_refused() {
    let other = BaseAdvertisement::new(
        FolderGroupId("elsewhere".into()),
        AdvertisedBase::Genesis,
        Vec::new(),
    )
    .unwrap();
    assert!(matches!(
        negotiate(&genesis(Vec::new()), &other),
        BaseNegotiation::Refused(BaseRefusal::GroupMismatch { .. })
    ));
}

/// Both sides of a session compare the same two advertisements from
/// opposite ends. If they could disagree about the kind of verdict, one
/// would wait for a reconciliation the other had declined.
#[test]
fn the_verdict_is_the_same_kind_from_either_side() {
    let other_group =
        BaseAdvertisement::new(FolderGroupId("elsewhere".into()), AdvertisedBase::Genesis, vec![])
            .unwrap();
    let all = [
        genesis(Vec::new()),
        genesis(vec![hash(4)]),
        installed(5, 6),
        installed(5, 8),
        installed(7, 6),
        other_group,
    ];
    for left in &all {
        for right in &all {
            assert_eq!(
                kind(&negotiate(left, right)),
                kind(&negotiate(right, left)),
                "{left:?} vs {right:?}"
            );
        }
    }
}

#[test]
fn summary_identity_is_deterministic_and_sensitive_to_its_fields() {
    let identity = |device: &str, path: &str| {
        let mut builder = SummaryIdentityBuilder::new(1);
        builder.author(device, 1, &hash(1));
        builder.begin_heads(1);
        builder.head(path, &hash(2), device, 1, 1, &[3; 32], device);
        builder.finish(1)
    };
    assert_ne!(identity("ab", "c"), identity("a", "bc"));
    assert_eq!(identity("ab", "c"), identity("ab", "c"));
}

#![cfg(test)]

use super::*;
use crate::dag_store::init_dag_schema;

fn conn() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    init_dag_schema(&c).unwrap();
    c
}

fn hash(byte: u8) -> ChangeHash {
    ChangeHash([byte; 32])
}

#[test]
fn records_and_queries_a_rejection() {
    let c = conn();
    assert!(!is_change_rejected(&c, &hash(1)).unwrap());
    record_rejected_change(
        &c,
        &hash(1),
        "g",
        RejectionDomain::Path,
        "reserved namespace: foo",
        100,
    )
    .unwrap();
    assert!(is_change_rejected(&c, &hash(1)).unwrap());
    assert!(!is_change_rejected(&c, &hash(2)).unwrap());
}

#[test]
fn re_recording_the_same_hash_overwrites_rather_than_errors() {
    let c = conn();
    record_rejected_change(&c, &hash(1), "g", RejectionDomain::Path, "first reason", 100).unwrap();
    record_rejected_change(&c, &hash(1), "g", RejectionDomain::Path, "second reason", 200).unwrap();
    let listed = list_rejected_changes(&c, "g").unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].1, "second reason");
    assert_eq!(listed[0].2, 200);
}

#[test]
fn lists_only_the_requested_group_most_recent_first() {
    let c = conn();
    record_rejected_change(&c, &hash(1), "g1", RejectionDomain::Path, "first", 100).unwrap();
    record_rejected_change(&c, &hash(2), "g1", RejectionDomain::Path, "second", 200).unwrap();
    record_rejected_change(&c, &hash(3), "g2", RejectionDomain::Path, "other group", 300).unwrap();

    let g1 = list_rejected_changes(&c, "g1").unwrap();
    assert_eq!(g1.len(), 2);
    assert_eq!(g1[0].0, hash(2), "most recent first");
    assert_eq!(g1[1].0, hash(1));

    let g2 = list_rejected_changes(&c, "g2").unwrap();
    assert_eq!(g2.len(), 1);
    assert_eq!(g2[0].0, hash(3));
}

/// The whole point of the version stamp: a row recorded under a rules
/// version older than the one running right now must NOT be trusted as
/// a settled rejection — a corrected predicate might have accepted the
/// same change, and nothing may ever re-evaluate it if this row is
/// allowed to stand in for that judgment forever.
#[test]
fn a_rejection_stamped_with_an_older_rules_version_is_not_trusted() {
    let c = conn();
    // Simulate a row recorded by a hypothetical earlier build, before
    // rewriting it through `record_rejected_change` (which always
    // stamps the CURRENT version) would defeat the point of this test.
    c.execute(
        "INSERT INTO rejected_changes \
             (change_hash, group_id, reason, rejected_at, rejection_domain, rules_version) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            &hash(1).0[..],
            "g",
            "an old build's verdict",
            100,
            RejectionDomain::Path.as_str(),
            RejectionDomain::Path.rules_version().saturating_sub(1),
        ],
    )
    .unwrap();

    assert!(
        !is_change_rejected(&c, &hash(1)).unwrap(),
        "a rejection stamped with an older rules version must not be trusted as settled"
    );
    assert!(
        list_rejected_changes(&c, "g").unwrap().is_empty(),
        "a stale-versioned row must not appear as a currently-settled rejection"
    );
}

/// Converse of the test above: a row stamped with the CURRENT version
/// (what every real call through `record_rejected_change` produces) is
/// trusted exactly as before — the version check must not make every
/// rejection stale by accident.
#[test]
fn a_rejection_stamped_with_the_current_rules_version_is_trusted() {
    let c = conn();
    record_rejected_change(&c, &hash(1), "g", RejectionDomain::Path, "current rules", 100).unwrap();
    assert!(is_change_rejected(&c, &hash(1)).unwrap());
    assert_eq!(list_rejected_changes(&c, "g").unwrap().len(), 1);
}

/// The reason the stamp is a domain and not one number. Path rules and
/// author-chain rules change for unrelated reasons; a verdict must be
/// re-opened when ITS rules move and left alone when some other domain's
/// do. One shared number gets both halves wrong at once: it leaves old
/// author-chain verdicts looking settled after the author chain changes,
/// permanently excluding changes the new rules would admit, and it
/// invalidates every author-chain verdict whenever a path rule moves,
/// re-asking peers for changes whose answer cannot have changed.
#[test]
fn one_domains_rules_moving_does_not_touch_another_domains_verdicts() {
    let c = conn();
    record_rejected_change(&c, &hash(1), "g", RejectionDomain::Path, "a path verdict", 100)
        .unwrap();
    record_rejected_change(
        &c,
        &hash(2),
        "g",
        RejectionDomain::AuthorChain,
        "an author-chain verdict",
        200,
    )
    .unwrap();
    assert!(is_change_rejected(&c, &hash(1)).unwrap());
    assert!(is_change_rejected(&c, &hash(2)).unwrap());

    // The author chain's rules move on. Its own verdict is re-opened;
    // the path verdict is untouched.
    c.execute(
        "UPDATE rejected_changes SET rules_version = rules_version - 1 \
         WHERE rejection_domain = ?1",
        [RejectionDomain::AuthorChain.as_str()],
    )
    .unwrap();

    assert!(
        is_change_rejected(&c, &hash(1)).unwrap(),
        "a path verdict must survive an author-chain rules change untouched"
    );
    assert!(
        !is_change_rejected(&c, &hash(2)).unwrap(),
        "and the author-chain verdict recorded under the superseded rules must be re-opened"
    );
    assert_eq!(
        list_rejected_changes(&c, "g").unwrap().len(),
        1,
        "the listing agrees with the single-hash verdict, per domain"
    );
}

/// The two domains are distinct values and version independently. If they
/// ever collapse back to one number, this says so.
#[test]
fn the_two_domains_are_distinct_and_versioned_apart() {
    assert_ne!(RejectionDomain::Path.as_str(), RejectionDomain::AuthorChain.as_str());
    assert!(current_domain(
        RejectionDomain::AuthorChain.as_str(),
        RejectionDomain::Path.rules_version().wrapping_add(7)
    )
    .is_none());
    assert!(
        current_domain("a-domain-this-build-does-not-know", 1).is_none(),
        "an unrecognized domain is not settled: re-evaluate rather than trust it"
    );
}

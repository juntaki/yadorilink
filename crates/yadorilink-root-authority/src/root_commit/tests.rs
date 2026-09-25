#![cfg(test)]

use super::*;

#[test]
fn for_tests_permit_always_verifies() {
    assert!(RootCommitPermit::for_tests().verify().is_ok());
}

#[test]
fn an_operation_admitted_before_stopping_is_not_refused_by_a_racing_begin_stopping() {
    let lease = RootLease::for_tests();
    let op = lease.begin_operation().unwrap();
    lease.begin_stopping();
    // The already-admitted operation's permit must still verify -- a
    // caller mid-operation when stop begins must be allowed to finish.
    assert!(op.permit().verify().is_ok());
}

#[test]
fn begin_operation_refuses_once_stopping_has_begun() {
    let lease = RootLease::for_tests();
    lease.begin_stopping();
    assert!(lease.begin_operation().is_err());
}

#[tokio::test]
async fn wait_drained_blocks_until_every_admitted_operation_drops() {
    let lease = RootLease::for_tests();
    let op = lease.begin_operation().unwrap();
    lease.begin_stopping();

    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), lease.wait_drained())
            .await
            .is_err(),
        "wait_drained must not resolve while an admitted LinkOperation is still held"
    );
    drop(op);
    tokio::time::timeout(std::time::Duration::from_secs(1), lease.wait_drained())
        .await
        .expect("wait_drained must resolve promptly once the LinkOperation drops");
}

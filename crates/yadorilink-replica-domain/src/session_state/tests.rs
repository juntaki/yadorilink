#![cfg(test)]

use super::{EnrollmentKind, MaterializationPolicy, MaterializationState};
use crate::file::RecordKind;

#[test]
fn persisted_enum_values_are_exact() {
    assert_eq!(EnrollmentKind::from_db_str("create"), EnrollmentKind::Create);
    assert_eq!(EnrollmentKind::from_db_str("join"), EnrollmentKind::Join);
    assert_eq!(MaterializationState::from_db_str("hydrated"), MaterializationState::Hydrated);
    assert_eq!(MaterializationState::from_db_str("placeholder"), MaterializationState::Placeholder);
    assert_eq!(MaterializationPolicy::from_db_str("eager"), MaterializationPolicy::Eager);
    assert_eq!(MaterializationPolicy::from_db_str("ondemand"), MaterializationPolicy::OnDemand);
    assert_eq!(RecordKind::from_db_str("file"), RecordKind::File);
}

#[test]
#[should_panic(expected = "unknown persisted materialization state")]
fn unknown_materialization_state_is_not_coerced() {
    let _ = MaterializationState::from_db_str("future-state");
}

#[test]
#[should_panic(expected = "unknown persisted materialization policy")]
fn unknown_materialization_policy_is_not_coerced() {
    let _ = MaterializationPolicy::from_db_str("future-policy");
}

#[test]
#[should_panic(expected = "unknown persisted enrollment kind")]
fn unknown_enrollment_kind_is_not_coerced() {
    let _ = EnrollmentKind::from_db_str("future-kind");
}

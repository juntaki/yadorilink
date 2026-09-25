#![cfg(test)]

use super::*;

#[test]
fn unsupported_never_reports_on_demand_support() {
    assert!(!PlaceholderCapability::Unsupported.supports_on_demand());
}

#[test]
fn supported_reports_on_demand_support() {
    assert!(PlaceholderCapability::Supported { name: "test" }.supports_on_demand());
}

#[test]
fn on_demand_pipeline_is_not_yet_connected() {
    assert!(
        !on_demand_pipeline_is_connected(),
        "flip this only after real-Windows-hardware acceptance confirms every \
         condition this function's own doc comment lists -- some are already met for \
         Windows (persisted generation, real dirty detection), others still aren't (no \
         persistent per-link session object; nothing routes through the \
         PlaceholderBackend trait itself), and NONE of it has been verified against real \
         hardware yet"
    );
}

#[test]
fn override_for_test_is_scoped_to_its_own_lifetime() {
    assert!(!on_demand_pipeline_is_connected());
    {
        let _override = OverrideForTest::enable();
        assert!(on_demand_pipeline_is_connected());
    }
    assert!(
        !on_demand_pipeline_is_connected(),
        "the override must not outlive the guard that enabled it"
    );
}

#![cfg(test)]

use super::*;

#[test]
fn device_summary_carries_the_fields_device_summary_needs() {
    // Every field on `GroupMemberInfo` is `pub` (it derives `Deserialize`
    // only, no `Default`), so a plain struct literal is the fixture.
    let member = GroupMemberInfo {
        device_id: "device-a".to_string(),
        device_name: "device-device-a".to_string(),
        role: "editor".to_string(),
        is_same_account: true,
        is_caller_account: true,
        storage_mode: "eager".to_string(),
        online: true,
        last_seen_unix: 1_700_000_000,
    };
    let summary = device_summary(&member);
    assert_eq!(summary.device_id, "device-a");
    assert_eq!(summary.display_name, "device-device-a");
    assert!(summary.online);
    assert_eq!(summary.last_seen_unix, 1_700_000_000);
}

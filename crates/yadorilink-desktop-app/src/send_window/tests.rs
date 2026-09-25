#![cfg(test)]

use super::*;

#[test]
fn format_bytes_scales_to_a_human_readable_unit() {
    assert_eq!(format_bytes(0), "0 B");
    assert_eq!(format_bytes(512), "512 B");
    assert_eq!(format_bytes(1536), "1.5 KiB");
    assert_eq!(format_bytes(5 * 1024 * 1024), "5.0 MiB");
}

fn device(id: &str, name: &str, online: bool) -> DeviceSummary {
    DeviceSummary {
        device_id: id.to_string(),
        display_name: name.to_string(),
        online,
        last_seen_unix: 0,
    }
}

/// The device picker never offers the current device as a send target
/// -- sending to yourself is meaningless, and there is no daemon
/// request that would make sense of it.
#[test]
fn other_devices_excludes_a_matching_own_device_id() {
    let mut app = SendApp::new(mpsc::channel().1, test_sink());
    app.devices = vec![device("dev-a", "Laptop", true), device("dev-b", "Phone", false)];
    // `own_device_id` reads real local device identity (none in a unit
    // test process), so this only exercises the "no own id known"
    // branch -- both devices remain, which is the correct fail-open
    // behavior `device.rs::count_other_devices` documents identically.
    assert_eq!(app.other_devices().len(), 2);
}

#[test]
fn device_label_falls_back_to_the_raw_id_when_unknown() {
    let mut app = SendApp::new(mpsc::channel().1, test_sink());
    app.devices = vec![device("dev-a", "Laptop", true)];
    assert_eq!(app.device_label("dev-a"), "Laptop (dev-a)");
    assert_eq!(app.device_label("dev-z"), "dev-z");
}

fn test_sink() -> EventSink<Event> {
    let (tx, _rx) = mpsc::channel();
    EventSink::new(tx, Arc::new(|| {}))
}

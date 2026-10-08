use rusqlite::Connection;

use super::*;

fn conn() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    // A bind reads the provenance of the live head it names.
    crate::replica_tables::init_for_tests(&c).unwrap();
    c
}

#[test]
fn native_binding_round_trips() {
    let c = conn();
    let id: NativeHeadIdentity = ("x".to_string(), "device-a".to_string(), [9u8; 16], 3);
    native_bind(&c, "g", &id, "foo (conflict).txt").unwrap();
    assert_eq!(native_bindings(&c, "g").unwrap().get(&id), Some(&"foo (conflict).txt".to_string()));
}

#[test]
fn one_native_identity_at_two_paths_gets_two_independent_bindings() {
    let c = conn();
    let dot = ("device-a".to_string(), [9u8; 16], 3u64);
    let id_x: NativeHeadIdentity = ("x".to_string(), dot.0.clone(), dot.1, dot.2);
    let id_y: NativeHeadIdentity = ("y".to_string(), dot.0.clone(), dot.1, dot.2);
    native_bind(&c, "g", &id_x, "x (conflict).txt").unwrap();
    native_bind(&c, "g", &id_y, "y (conflict).txt").unwrap();

    let bindings = native_bindings(&c, "g").unwrap();
    assert_eq!(bindings.get(&id_x), Some(&"x (conflict).txt".to_string()));
    assert_eq!(bindings.get(&id_y), Some(&"y (conflict).txt".to_string()));
}

#[test]
fn native_reverse_lookup_resolves_a_bound_path_and_none_for_an_ordinary_one() {
    let c = conn();
    let id: NativeHeadIdentity = ("x".to_string(), "device-a".to_string(), [9u8; 16], 3);
    native_bind(&c, "g", &id, "x (conflict).txt").unwrap();
    assert_eq!(native_binding_at_stable_path(&c, "g", "x (conflict).txt").unwrap(), Some(id));
    assert_eq!(native_binding_at_stable_path(&c, "g", "x.txt").unwrap(), None);
}

#[test]
fn a_placement_origin_survives_its_stored_text_and_unknown_text_is_corrupt() {
    use yadorilink_replica_domain::native_resolver::PlacementOrigin;

    for origin in [
        PlacementOrigin::ConflictCopy,
        PlacementOrigin::TreeRelocation,
        PlacementOrigin::ReconciliationHold,
    ] {
        assert_eq!(parse_origin(origin_text(origin)).unwrap(), origin);
    }
    assert!(matches!(parse_origin("elsewhere"), Err(SyncSqliteError::CorruptState(_))));
}

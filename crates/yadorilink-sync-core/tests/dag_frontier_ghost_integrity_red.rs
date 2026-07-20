use rusqlite::Connection;
use yadorilink_sync_core::change::ChangeHash;
use yadorilink_sync_core::dag_store::{group_heads, init_dag_schema};

#[test]
fn schema_init_removes_group_heads_for_groups_with_no_retained_history() {
    let conn = Connection::open_in_memory().unwrap();
    init_dag_schema(&conn).unwrap();
    let ghost = ChangeHash([0x77u8; 32]);
    conn.execute(
        "INSERT INTO group_heads (group_id, change_hash) VALUES ('g', ?1)",
        [&ghost.0[..]],
    )
    .unwrap();

    init_dag_schema(&conn).unwrap();

    assert!(
        group_heads(&conn, "g").unwrap().is_empty(),
        "group_heads is fully derived from admitted changes; a group with no retained history must not keep a ghost parent"
    );
}

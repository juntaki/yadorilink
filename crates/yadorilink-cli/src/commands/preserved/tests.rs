#![cfg(test)]

use yadorilink_ipc_proto::daemonctl::PreservedItem;

use super::format_item;

fn version(content: &str, held: u32, total: u32) -> PreservedItem {
    PreservedItem {
        kind: "remote_only".into(),
        group_id: "g".into(),
        item_id: "ab".repeat(32),
        path: "doc.txt".into(),
        content: content.into(),
        size: 12,
        blocks_held: held,
        blocks_total: total,
        ..Default::default()
    }
}

#[test]
fn a_complete_version_says_so() {
    let line = format_item(&version("complete", 1, 1));
    assert!(
        line.contains("doc.txt") && line.contains("content complete") && line.contains("12 bytes")
    );
}

#[test]
fn an_unavailable_version_says_how_many_blocks_are_held() {
    let line = format_item(&version("unavailable", 1, 3));
    assert!(line.contains("content unavailable (1 of 3 blocks)"), "{line}");
}

#[test]
fn a_record_less_version_is_never_called_restorable() {
    assert!(format_item(&version("record_unavailable", 0, 0)).contains("record unavailable"));
}

#[test]
fn an_own_unit_names_its_paths_and_where_its_files_are() {
    let item = PreservedItem {
        kind: "own_unit".into(),
        group_id: "g".into(),
        group_removed: true,
        item_id: "rec:0".into(),
        paths: vec!["a.txt".into(), "b/c.txt".into()],
        recovery_id: "rec".into(),
        originals_quarantined: true,
        ..Default::default()
    };
    let line = format_item(&item);
    assert!(line.contains("a.txt, b/c.txt") && line.contains("group removed"));
    assert!(line.contains("moved out of the folder into recovery area rec"), "{line}");
}

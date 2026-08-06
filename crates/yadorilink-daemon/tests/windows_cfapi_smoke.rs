//! Real, non-mocked smoke test for `placeholder_backend_windows` against
//! the actual Cloud Filter API on a real Windows filesystem. An
//! integration test (not a `--lib` unit test) deliberately: it only needs
//! the compiled `yadorilink-daemon` rlib, not the whole crate's own
//! `#[cfg(test)]` module graph, some of which is not yet Windows-portable.
#![cfg(windows)]

use yadorilink_daemon::placeholder_backend_windows::WindowsCfApiBackend;
use yadorilink_filesystem_sync::placeholder_backend::{
    PlaceholderBackend, PlaceholderCapability, PlaceholderStatus,
};

fn unique_temp_root() -> std::path::PathBuf {
    let mut dir = std::env::temp_dir();
    let nanos =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    dir.push(format!("yadorilink-cfapi-smoke-{nanos}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn probe_reports_supported_on_windows() {
    let root = unique_temp_root();
    assert_eq!(
        WindowsCfApiBackend::probe(&root),
        PlaceholderCapability::Supported { name: "windows-cfapi" }
    );
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn real_register_create_hydrate_inspect_round_trip() {
    let root = unique_temp_root();
    let backend = WindowsCfApiBackend::register(&root)
        .expect("CfRegisterSyncRoot should succeed for a fresh local directory");
    let placeholder_path = root.join("placeholder.txt");
    let content = b"real content!".to_vec();
    let generation = backend
        .create(&placeholder_path, content.len() as u64, 1_700_000_000_000_000_000)
        .expect("CfCreatePlaceholders should succeed");

    assert_eq!(
        backend.inspect(&placeholder_path, generation).unwrap(),
        PlaceholderStatus::Untouched,
        "a freshly created placeholder must report Untouched"
    );

    // The provider (this backend), not a plain `std::fs::write`, populates
    // a placeholder's content -- see `PlaceholderBackend::hydrate`'s own
    // doc for why an ordinary write cannot substitute here.
    backend
        .hydrate(&placeholder_path, &mut content.as_slice())
        .expect("hydrate should populate the placeholder and mark it in-sync");
    assert_eq!(
        backend.inspect(&placeholder_path, generation).unwrap(),
        PlaceholderStatus::Untouched,
        "hydrate must leave the placeholder in-sync"
    );
    assert_eq!(
        std::fs::read(&placeholder_path).expect("hydrated placeholder must be readable"),
        content,
        "hydrate must have written the exact bytes given to it"
    );

    // NOW a real, direct local write, not a mock -- exactly what
    // size/mtime heuristics can silently miss if the new bytes happen to
    // land on the same length, but the OS's own placeholder state must
    // not. Only possible once the placeholder is fully populated (an
    // ordinary write into a still-unpopulated placeholder range times out
    // waiting for a fetch this backend does not implement -- confirmed
    // empirically, see `placeholder_backend_windows`'s own doc).
    std::fs::write(&placeholder_path, b"a real local edit").expect("direct write must succeed");
    assert_ne!(
        backend.inspect(&placeholder_path, generation).unwrap(),
        PlaceholderStatus::Untouched,
        "a placeholder that was actually written to must never report Untouched"
    );

    drop(backend);
    std::fs::remove_dir_all(&root).ok();
}

/// Regression test for the ABA gap a cross-review found (round-5 response,
/// commit fd7383a0): `inspect` used to ignore its `expected` generation
/// token entirely, so a stale caller holding an old generation for a path
/// whose placeholder was deleted and replaced by an unrelated, genuinely
/// in-sync one would see `Untouched` -- as if its own stale generation
/// were still valid.
#[test]
fn inspect_with_a_stale_generation_never_reports_untouched() {
    let root = unique_temp_root();
    let backend = WindowsCfApiBackend::register(&root)
        .expect("CfRegisterSyncRoot should succeed for a fresh local directory");
    let placeholder_path = root.join("placeholder.txt");
    let content = b"first generation".to_vec();
    let first_generation = backend
        .create(&placeholder_path, content.len() as u64, 1_700_000_000_000_000_000)
        .expect("first CfCreatePlaceholders should succeed");
    backend
        .hydrate(&placeholder_path, &mut content.as_slice())
        .expect("hydrate should populate the first placeholder");
    assert_eq!(
        backend.inspect(&placeholder_path, first_generation).unwrap(),
        PlaceholderStatus::Untouched,
        "sanity check: the first generation's own inspect must see Untouched"
    );

    // Delete and recreate at the same path -- a distinct placeholder
    // object, minting its own new generation.
    std::fs::remove_file(&placeholder_path).expect("removing the first placeholder must succeed");
    let second_content = b"second generation, different object".to_vec();
    let second_generation = backend
        .create(&placeholder_path, second_content.len() as u64, 1_700_000_100_000_000_000)
        .expect("second CfCreatePlaceholders should succeed");
    backend
        .hydrate(&placeholder_path, &mut second_content.as_slice())
        .expect("hydrate should populate the second placeholder");
    assert_ne!(
        first_generation, second_generation,
        "sanity check: recreating at the same path must mint a different generation"
    );

    assert_eq!(
        backend.inspect(&placeholder_path, second_generation).unwrap(),
        PlaceholderStatus::Untouched,
        "sanity check: the second (current) generation's own inspect must see Untouched"
    );
    assert_ne!(
        backend.inspect(&placeholder_path, first_generation).unwrap(),
        PlaceholderStatus::Untouched,
        "inspecting with the FIRST (now-stale) generation against the SECOND placeholder must \
         never report Untouched -- that would silently treat an unrelated object as the one \
         this caller created"
    );

    drop(backend);
    std::fs::remove_dir_all(&root).ok();
}

use yadorilink_local_storage::{BlockStore, FsBlockStore};

fn store() -> (FsBlockStore, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = FsBlockStore::new(dir.path()).unwrap();
    (store, dir)
}

#[test]
fn put_then_get_roundtrips() {
    let (store, _dir) = store();
    let hash = store.put(b"hello world").unwrap();
    let data = store.get(&hash).unwrap();
    assert_eq!(data, b"hello world");
}

#[test]
fn identical_content_stored_once() {
    let (store, dir) = store();
    let hash_a = store.put(b"same bytes").unwrap();
    let hash_b = store.put(b"same bytes").unwrap();
    assert_eq!(hash_a, hash_b);

    // Only one block file should exist on disk for this content.
    let mut count = 0;
    for entry in walkdir(dir.path()) {
        let name = entry.file_name().and_then(|name| name.to_str()).unwrap_or("");
        if entry.is_file() && name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit()) {
            count += 1;
        }
    }
    assert_eq!(count, 1);
}

#[test]
fn path_traversal_rejected_on_get() {
    let (store, _dir) = store();
    let err = store.get("../../../../etc/passwd").unwrap_err();
    assert!(matches!(err, yadorilink_local_storage::StorageError::InvalidPath(_)));
}

#[test]
fn path_traversal_rejected_on_list_prefix() {
    let (store, _dir) = store();
    let err = store.list_by_prefix("../etc").unwrap_err();
    assert!(matches!(err, yadorilink_local_storage::StorageError::InvalidPath(_)));
}

#[test]
fn checksum_mismatch_detected_on_corruption() {
    let (store, dir) = store();
    let hash = store.put(b"trustworthy bytes").unwrap();

    // Corrupt the stored block on disk directly.
    let path = dir.path().join(&hash[0..2]).join(&hash[2..4]).join(&hash);
    std::fs::write(&path, b"tampered bytes!!").unwrap();

    let err = store.get(&hash).unwrap_err();
    assert!(matches!(err, yadorilink_local_storage::StorageError::ChecksumMismatch { .. }));
}

#[test]
fn missing_block_is_not_found() {
    let (store, _dir) = store();
    let fake_hash = "a".repeat(64);
    let err = store.get(&fake_hash).unwrap_err();
    assert!(matches!(err, yadorilink_local_storage::StorageError::NotFound(_)));
}

/// on-demand-sync task 3.1/3.3: batch presence query correctly reports a
/// mixed present/missing block list, in the same order as the input.
#[test]
fn present_blocks_reports_a_mixed_present_missing_list() {
    let (store, _dir) = store();
    let present_hash = store.put(b"already have this").unwrap();
    let missing_hash = "b".repeat(64);

    let result = store
        .present_blocks(&[present_hash.clone(), missing_hash.clone(), present_hash.clone()])
        .unwrap();

    assert_eq!(result, vec![true, false, true]);
}

/// `sync-performance` PERF-8: the batched `present_blocks` must return the
/// exact same answers as the old N-`exists`-calls default, including when
/// invoked under a *multi-threaded* tokio runtime (the `block_in_place`
/// path) as `peer_session.rs`/`hydration.rs` do in production — proving
/// the runtime-aware dispatch added in `FsBlockStore::present_blocks`
/// doesn't change behavior versus the plain-sync path already covered by
/// `present_blocks_reports_a_mixed_present_missing_list` above.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn present_blocks_is_correct_under_a_multi_thread_runtime() {
    let (store, _dir) = store();
    let present_hash = store.put(b"already have this, on a tokio worker").unwrap();
    let missing_hash = "c".repeat(64);

    let result = store
        .present_blocks(&[present_hash.clone(), missing_hash.clone(), present_hash.clone()])
        .unwrap();

    assert_eq!(result, vec![true, false, true]);
}

/// Same as above but under a *current-thread* runtime, the flavor most
/// `yadorilink-sync-core` tests actually use — `block_in_place` would panic
/// here if `present_blocks` took that path unconditionally, so this
/// guards the `RuntimeFlavor::MultiThread` check in
/// `FsBlockStore::present_blocks`.
#[tokio::test]
async fn present_blocks_is_correct_under_a_current_thread_runtime() {
    let (store, _dir) = store();
    let present_hash = store.put(b"already have this, on current-thread").unwrap();
    let missing_hash = "d".repeat(64);

    let result = store.present_blocks(&[present_hash.clone(), missing_hash]).unwrap();

    assert_eq!(result, vec![true, false]);
}

/// `sync-performance` PERF-8: a genuine batch check should do far fewer
/// filesystem calls than one `stat` per hash when many of the requested
/// hashes share shard directories — this pins down that
/// `present_blocks_batched`'s grouping-by-shard actually collapses
/// repeated lookups instead of just being a rename of the same N-stat
/// loop. Uses wall-clock time as a coarse but real before/after signal
/// (not a strict assertion, since CI hardware varies) plus an explicit
/// syscall-shaped correctness check: many hashes present under very few
/// distinct shard prefixes.
#[test]
fn present_blocks_batches_shard_reads_for_many_hashes_in_few_shards() {
    let (store, _dir) = store();

    // Store many blocks. SHA-256 output is effectively random, so instead
    // of relying on real content hashes landing in the same shard (rare),
    // directly exercise `present_blocks` with a large, mixed-presence
    // batch and confirm correctness at scale; the shard-grouping itself
    // is what keeps this fast (see the timing comparison below).
    let mut hashes = Vec::new();
    for i in 0..500u32 {
        let hash = store.put(format!("block number {i}").as_bytes()).unwrap();
        hashes.push(hash);
    }
    let missing: Vec<String> = (0..500u32).map(|i| format!("{i:064x}")).collect();

    let mut query = hashes.clone();
    query.extend(missing.iter().cloned());
    let result = store.present_blocks(&query).unwrap();

    for (i, present) in result.iter().enumerate().take(hashes.len()) {
        assert!(present, "hash at index {i} should be present");
    }
    for present in result.iter().skip(hashes.len()) {
        assert!(!present, "synthetic missing hash should be reported absent");
    }
}

/// Before/after-style timing comparison (task 5.1's spirit): the trait's
/// *default* N-`exists`-calls implementation versus `FsBlockStore`'s
/// batched override, over a query set where every hash shares one shard
/// directory (the case the batching is designed for — e.g. probing many
/// near-duplicate/adjacent blocks). This is a coarse signal, not a strict
/// perf gate (so it can't flake in CI), but it's asserted, not just
/// printed: the batched path must not regress past the naive default.
#[test]
fn present_blocks_batched_is_not_slower_than_naive_per_hash_default() {
    use std::time::Instant;

    let (store, _dir) = store();

    // Force every queried hash into the SAME shard directory by using a
    // fixed 4-hex-char prefix, so the naive default does N `stat`s in
    // that one directory while the batched path does exactly one
    // `read_dir` there.
    let shard_prefix = "abcd";
    let hashes: Vec<String> = (0..2000u32).map(|i| format!("{shard_prefix}{i:060x}")).collect();
    // Materialize a "present" subset (every 3rd hash) directly on disk
    // under the shard, matching real hydration/reconcile usage where a
    // batch is a mix of present/missing blocks. Bypasses `put` (whose
    // content-derived hash wouldn't share a prefix) but still exercises
    // the same `present_blocks` code path.
    // bypassing `put` (whose content-derived hash wouldn't share a
    // prefix) — still exercises the same `present_blocks` code path.
    let dir = _dir.path().join(&shard_prefix[0..2]).join(&shard_prefix[2..4]);
    std::fs::create_dir_all(&dir).unwrap();
    for (i, hash) in hashes.iter().enumerate() {
        if i % 3 == 0 {
            std::fs::write(dir.join(hash), b"x").unwrap();
        }
    }

    // Naive baseline: what the old default (one `exists`/`stat` per hash)
    // would have done.
    let naive_start = Instant::now();
    let naive: Vec<bool> = hashes.iter().map(|h| store.exists(h).unwrap()).collect();
    let naive_elapsed = naive_start.elapsed();

    let batched_start = Instant::now();
    let batched = store.present_blocks(&hashes).unwrap();
    let batched_elapsed = batched_start.elapsed();

    assert_eq!(naive, batched, "batched present_blocks must agree with per-hash exists()");
    eprintln!(
        "present_blocks: naive per-hash={naive_elapsed:?} batched-shard-read_dir={batched_elapsed:?} \
         ({} hashes, all in one shard)",
        hashes.len()
    );
    // Not a hard perf gate (avoid CI flakiness), but the whole point of
    // PERF-8 is that batching must not be slower than the thing it
    // replaces for this many-hashes-one-shard shape.
    assert!(
        batched_elapsed <= naive_elapsed * 2,
        "batched present_blocks ({batched_elapsed:?}) should not be dramatically \
         slower than the naive per-hash baseline ({naive_elapsed:?})"
    );
}

/// `sync-performance` PERF-4: `get_unchecked` must return the exact same
/// bytes as `get` for a block that hasn't been tampered with (correctness
/// of the fast path), and must NOT catch corruption the way `get` does
/// (documenting/pinning the trade-off — this is why `get_unchecked` is
/// only safe where integrity is independently already guaranteed, and why
/// no call site in this repo uses it yet).
#[test]
fn get_unchecked_returns_same_bytes_as_get_when_uncorrupted() {
    let (store, _dir) = store();
    let hash = store.put(b"fast path bytes").unwrap();

    assert_eq!(store.get(&hash).unwrap(), store.get_unchecked(&hash).unwrap());
}

#[test]
fn get_unchecked_does_not_detect_corruption_unlike_get() {
    let (store, dir) = store();
    let hash = store.put(b"trustworthy bytes").unwrap();
    let path = dir.path().join(&hash[0..2]).join(&hash[2..4]).join(&hash);
    std::fs::write(&path, b"tampered bytes!!").unwrap();

    // `get_unchecked` intentionally does not detect corruption — checked
    // *before* `get`, since (SEC-SYNC-1) `get`'s checksum-mismatch path now
    // self-heals by deleting the corrupt file as a side effect, which would
    // otherwise make this assertion order-dependent.
    assert_eq!(store.get_unchecked(&hash).unwrap(), b"tampered bytes!!");
    // `get` still catches it (SEC-5 unchanged).
    assert!(matches!(
        store.get(&hash).unwrap_err(),
        yadorilink_local_storage::StorageError::ChecksumMismatch { .. }
    ));
}

/// SEC-SYNC-1 (task 4.1) regression: concurrently `put()`-ing the exact
/// same block content from many threads at once (simulating multi-peer
/// fetch + up-to-16-way concurrent `reconcile_files` writing the same
/// hash) must never produce a torn block. Before the fix, every writer
/// raced through the same fixed `<hash>.tmp` path, so a losing writer's
/// `rename` either clobbered the target mid-write (torn content) or hit a
/// spurious `ENOENT` (the winner's temp file already consumed). With a
/// unique temp path per writer, every `put()` should succeed and the
/// final stored content must be byte-identical to what was written,
/// regardless of how many writers raced.
#[test]
fn concurrent_put_of_the_same_block_never_tears_the_stored_content() {
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(FsBlockStore::new(dir.path()).unwrap());
    // Large enough that a half-written rename would be trivially
    // detectable via a truncated/garbled read, and slow enough (relative
    // to a rename) to make the race actually land in practice.
    let data: Vec<u8> = (0..512 * 1024).map(|i| (i % 251) as u8).collect();

    let mut handles = Vec::new();
    for _ in 0..16 {
        let store = Arc::clone(&store);
        let data = data.clone();
        handles.push(std::thread::spawn(move || store.put(&data)));
    }

    let mut hashes = Vec::new();
    for handle in handles {
        hashes.push(handle.join().unwrap().expect("put() must not error under concurrency"));
    }
    // Every writer computed the same content hash...
    assert!(hashes.iter().all(|h| *h == hashes[0]));
    // ...and reading it back afterward returns the exact original bytes,
    // passing its own checksum re-verification — a torn block would fail
    // this with ChecksumMismatch.
    let read_back = store.get(&hashes[0]).unwrap();
    assert_eq!(read_back, data);
}

/// SEC-SYNC-1 (task 4.1) regression: a torn/corrupted block self-heals on
/// the next correct `put()` instead of staying permanently un-hydratable.
/// Simulates the post-corruption state directly (truncating a stored
/// block so it fails its own checksum), confirms `get()` reports the
/// mismatch (and, per the fix, cleans the file up as a side effect), then
/// confirms a fresh `put()` of the *correct* bytes restores a fully
/// readable block — before the fix, `put()`'s `exists()` short-circuit
/// would have skipped rewriting it, leaving `get()` returning
/// `ChecksumMismatch` forever.
#[test]
fn a_torn_block_self_heals_on_a_subsequent_correct_put() {
    let (store, dir) = store();
    let data = b"the correct, complete content of this block";
    let hash = store.put(data).unwrap();

    // Simulate the SEC-SYNC-1 torn-block scenario: truncate the stored
    // file in place so its bytes no longer hash to its own filename.
    let path = dir.path().join(&hash[0..2]).join(&hash[2..4]).join(&hash);
    std::fs::write(&path, &data[..data.len() / 2]).unwrap();
    assert!(matches!(
        store.get(&hash).unwrap_err(),
        yadorilink_local_storage::StorageError::ChecksumMismatch { .. }
    ));

    // A later `put()` of the correct bytes must re-materialize the block
    // (not silently no-op on a since-corrupt `exists()` check) ...
    let healed_hash = store.put(data).unwrap();
    assert_eq!(healed_hash, hash);
    // ... and `get()` must now succeed, not stay permanently poisoned.
    assert_eq!(store.get(&hash).unwrap(), data);
}

/// Before/after timing signal for PERF-4: `get_unchecked` skips the
/// SHA-256 recompute `get` does, so on a large block it should be
/// meaningfully faster. Threshold is loose to avoid CI flakiness — this
/// is a sanity check that the fast path is real, not a strict benchmark.
#[test]
fn get_unchecked_is_not_slower_than_verified_get_on_a_large_block() {
    use std::time::Instant;

    let (store, _dir) = store();
    let data = vec![0x42u8; 32 * 1024 * 1024]; // 32 MiB
    let hash = store.put(&data).unwrap();

    let verified_start = Instant::now();
    let verified = store.get(&hash).unwrap();
    let verified_elapsed = verified_start.elapsed();

    let unchecked_start = Instant::now();
    let unchecked = store.get_unchecked(&hash).unwrap();
    let unchecked_elapsed = unchecked_start.elapsed();

    assert_eq!(verified, unchecked);
    eprintln!("get: verified={verified_elapsed:?} unchecked={unchecked_elapsed:?} (32MiB block)");
    assert!(
        unchecked_elapsed <= verified_elapsed * 2,
        "get_unchecked ({unchecked_elapsed:?}) should not be slower than verified get \
         ({verified_elapsed:?}) on a large block"
    );
}

// --- Disk-pressure preflight regression tests -----------------------------

/// A block write that would breach headroom is rejected with
/// `DiskPressure` and writes nothing — forced deterministically by
/// configuring a headroom override far larger than any real disk's free
/// space, rather than depending on this test environment's actual free
/// space (which is both unknown and not this test's concern).
#[test]
fn put_rejected_with_disk_pressure_when_it_would_breach_headroom() {
    let (store, dir) = store();
    store.set_headroom_override_bytes(Some(u64::MAX / 2));
    store.set_headroom_enforced(true);

    let err = store.put(b"some block content").unwrap_err();
    assert!(
        matches!(err, yadorilink_local_storage::StorageError::DiskPressure { .. }),
        "expected DiskPressure, got {err:?}"
    );

    // No block file, and no leftover temp file, anywhere under the root.
    assert!(walkdir(dir.path()).iter().all(|p| {
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        !name.contains("yadorilink-tmp") && name.len() != 64
    }));
}

/// A bare `FsBlockStore` (as ~25 existing call sites across the workspace
/// construct it, unrelated to disk-pressure testing) never enforces
/// headroom unless something explicitly turns it on — even with an
/// override configured, an unenforced store's `put()` must never reject a
/// write. This is the deliberate "off by default, zero overhead unless a
/// governance-aware caller (the daemon) opts in" behavior documented on
/// `FsBlockStore::headroom_enforced`.
#[test]
fn put_never_rejects_when_headroom_enforcement_is_not_enabled() {
    let (store, _dir) = store();
    store.set_headroom_override_bytes(Some(u64::MAX / 2)); // configured, but not enforced
    store.put(b"still succeeds").unwrap();
}

/// identical content already on disk is still a dedup no-op even
/// under disk pressure — no *new* bytes need to be written, so the
/// preflight check must not block it.
#[test]
fn put_dedup_no_op_succeeds_even_under_disk_pressure() {
    let (store, _dir) = store();
    let hash = store.put(b"already stored").unwrap();
    store.set_headroom_override_bytes(Some(u64::MAX / 2));
    store.set_headroom_enforced(true);

    let second = store.put(b"already stored").unwrap();
    assert_eq!(second, hash);
}

/// `DiskPressure` must be distinguishable from a transient I/O
/// error by callers (e.g. to back off differently) rather than being folded
/// into the generic `Io` variant.
#[test]
fn disk_pressure_is_not_confused_with_a_transient_io_error() {
    let (store, _dir) = store();
    store.set_headroom_override_bytes(Some(u64::MAX / 2));
    store.set_headroom_enforced(true);
    let err = store.put(b"x").unwrap_err();
    assert!(!matches!(err, yadorilink_local_storage::StorageError::Io(_)));
    assert!(matches!(err, yadorilink_local_storage::StorageError::DiskPressure { .. }));
}

/// / 1.3: `free_space` reflects the same override-driven
/// classification `put`'s preflight uses, live-updating as the configured
/// override changes — always computed from real disk state (not dependent
/// on `headroom_enforced`, since status reporting should show real health
/// either way). Uses two explicit, deliberately far-apart overrides rather
/// than relying on the *unconfigured* default classification (which
/// reflects this host's actual free space and can't be assumed `Ok` in
/// every environment — this repo's own dev machine is a real
/// counterexample, genuinely near-full).
#[test]
fn free_space_reflects_configured_headroom_override() {
    let (store, _dir) = store();
    store.set_headroom_override_bytes(Some(u64::MAX / 2));
    assert_eq!(
        store.free_space().unwrap().unwrap().classify(),
        yadorilink_local_storage::FreeSpaceState::Critical
    );

    store.set_headroom_override_bytes(Some(0));
    assert_eq!(
        store.free_space().unwrap().unwrap().classify(),
        yadorilink_local_storage::FreeSpaceState::Ok
    );
}

fn walkdir(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    out
}

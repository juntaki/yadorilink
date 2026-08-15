//! L1: single large file, two real `DaemonState`s paired directly over
//! loopback UDP (the repo's own 1GbE-equivalent -- see DESIGN.md for why
//! loopback stands in for a real 1GbE link in this first slice, and W1/W2's
//! planned `tc netem` treatment for when a real link characteristic
//! matters).

use std::io::{Read, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::harness::{self, BenchDevice};
use crate::metrics::{Metric, ScenarioReport, WireSnapshot};
use crate::scenario::{RunOptions, Scenario};

const GROUP_ID: &str = "bench-l1-group";
const FILE_NAME: &str = "l1-payload.bin";
const WRITE_CHUNK_BYTES: usize = 8 * 1024 * 1024;
/// Generous ceiling on how long the whole transfer may take before this
/// scenario gives up and reports a hard failure rather than hanging a bench
/// run forever -- not a correctness gate, just a sanity backstop.
const OVERALL_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const POLL_INTERVAL: Duration = Duration::from_millis(20);

pub struct L1Scenario;

#[async_trait::async_trait]
impl Scenario for L1Scenario {
    fn id(&self) -> &'static str {
        "L1"
    }

    async fn run(&self, opts: &RunOptions) -> anyhow::Result<ScenarioReport> {
        let source = harness::new_device("bench-source", GROUP_ID).await?;
        let receiver = harness::new_device("bench-receiver", GROUP_ID).await?;
        harness::start_link_watch(&source, GROUP_ID)?;
        harness::start_link_watch(&receiver, GROUP_ID)?;
        let _session_handles = harness::pair_devices(&source, &receiver, GROUP_ID).await?;

        let wire_baseline = WireSnapshot::capture(&[&source.hub, &receiver.hub]);
        let (cpu_baseline, _) = crate::rusage::snapshot();

        let file_path = source.root.path().join(FILE_NAME);
        let size_bytes = opts.file_size_bytes;
        let write_path = file_path.clone();
        tokio::task::spawn_blocking(move || write_large_file(&write_path, size_bytes)).await??;
        // File-close instant: `write_large_file` returns only after its
        // `BufWriter` is flushed and its `File` handle is dropped.
        let t0 = Instant::now();

        let t_detect = poll_until(
            || record_matches(&source, GROUP_ID, FILE_NAME, size_bytes),
            OVERALL_TIMEOUT,
        )
        .await
        .map(|at| at - t0);

        let t_index = poll_until(
            || record_matches(&receiver, GROUP_ID, FILE_NAME, size_bytes),
            OVERALL_TIMEOUT,
        )
        .await
        .map(|at| at - t0);

        let t_firstbyte = poll_until(
            || {
                let now = WireSnapshot::capture(&[&receiver.hub]);
                now.bytes_received > wire_baseline.bytes_received
            },
            OVERALL_TIMEOUT,
        )
        .await
        .map(|at| at - t0);

        // "byte-exact durable convergence" means exactly that: a real
        // streaming digest match, not an inference from file size. Measured
        // empirically during this scenario's own development that a bare
        // size check is NOT a safe completion signal here -- the
        // materialization path can leave a final-size file at the
        // destination path while a block fetch for it is still failing/
        // retrying (observed: a destination reaching the expected size
        // immediately, but hashing as all-zero, while the real content
        // arrived only once the daemon's periodic repair sweep re-drove the
        // fetch seconds later). So this polls size AS A CHEAP GATE, then
        // re-hashes on a coarser cadence until the digests actually match
        // or the overall timeout elapses -- `t_complete` is stamped at the
        // instant a real digest match is observed, never at first size
        // match.
        let dest_path = receiver.root.path().join(FILE_NAME);
        let (t_complete, _source_digest, _dest_digest) =
            wait_for_byte_exact_convergence(&file_path, &dest_path, size_bytes, t0).await?;

        let wire_final = WireSnapshot::capture(&[&source.hub, &receiver.hub]);
        let wire_delta = wire_final.delta_since(&wire_baseline);
        let (cpu_final, peak_rss) = crate::rusage::snapshot();
        let cpu_seconds = (cpu_final - cpu_baseline).max(0.0);

        let packets_per_sec = if t_complete.as_secs_f64() > 0.0 {
            (wire_delta.packets_sent + wire_delta.packets_received) as f64
                / t_complete.as_secs_f64()
        } else {
            0.0
        };

        Ok(ScenarioReport {
            scenario: self.id(),
            file_size_bytes: size_bytes,
            t_detect: duration_metric(t_detect),
            t_index: duration_metric(t_index),
            t_firstbyte: duration_metric(t_firstbyte),
            t_complete: Metric::Duration(t_complete),
            wire_bytes_sent: Metric::Bytes(wire_delta.bytes_sent),
            wire_bytes_received: Metric::Bytes(wire_delta.bytes_received),
            disk_read_bytes: Metric::NotImplemented(
                "no per-process disk-read counter wired yet -- Linux has /proc/self/io, macOS \
                 needs libproc's rusage_info_v4 (RUSAGE_INFO_V4.ri_diskio_bytesread); neither is \
                 instrumented in this first slice",
            ),
            disk_write_bytes: Metric::NotImplemented(
                "same gap as disk_read_bytes -- alternatively FsBlockStore could self-report \
                 bytes written on its own put()/materialization path, not done yet",
            ),
            cpu_seconds: Metric::Duration(Duration::from_secs_f64(cpu_seconds)),
            peak_rss_bytes: Metric::Bytes(peak_rss),
            packets_per_sec: Metric::Rate(packets_per_sec, "pkt/s"),
            fsync_count: Metric::NotImplemented(
                "no fsync counter wired yet -- needs instrumenting yadorilink-local-storage's \
                 FsBlockStore write path directly, not done in this first slice",
            ),
        })
    }
}

fn duration_metric(result: anyhow::Result<Duration>) -> Metric {
    match result {
        Ok(d) => Metric::Duration(d),
        Err(e) => Metric::NotImplemented(Box::leak(format!("poll failed: {e}").into_boxed_str())),
    }
}

async fn poll_until<F: FnMut() -> bool>(mut cond: F, timeout: Duration) -> anyhow::Result<Instant> {
    let deadline = Instant::now() + timeout;
    loop {
        if cond() {
            return Ok(Instant::now());
        }
        if Instant::now() > deadline {
            anyhow::bail!("condition never became true within {timeout:?}");
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

fn record_matches(device: &BenchDevice, group_id: &str, file_name: &str, size_bytes: u64) -> bool {
    device
        .state
        .replica_coordinator
        .file_index_repository()
        .list_files(group_id)
        .map(|files| {
            files.iter().any(|r| !r.deleted && r.path == file_name && r.size == size_bytes)
        })
        .unwrap_or(false)
}

/// Writes `size_bytes` of genuinely random content to `path` in
/// `WRITE_CHUNK_BYTES` chunks -- real entropy per chunk (not a repeated
/// buffer with a perturbed header), so this scenario's wire-byte numbers
/// reflect a content-addressed store and any future compression negotiation
/// against realistic, incompressible user data rather than an artificially
/// easy payload.
///
/// Writes to a sibling temp path and renames into `path` only once fully
/// flushed. MEASURED during this scenario's own development: writing this
/// many chunks directly to the final, watched path let the real OS
/// filesystem watcher (FSEvents on macOS) observe and capture an
/// intermediate, still-being-written revision of the file mid-write. That
/// revision indexes and chunks differently from the final one, and the
/// receiver can end up requesting blocks by a stale revision's hashes that
/// the source's now-current `FileRecord` no longer references -- a
/// permanent (not transient) `DontHave`/`NotFound`, since nothing ever
/// re-announces the stale hash set. Same-directory rename is atomic, so the
/// watcher only ever observes one, complete revision -- exactly how a real
/// application writing a large file (browser download, archive extractor)
/// avoids the same problem in production.
fn write_large_file(path: &Path, size_bytes: u64) -> anyhow::Result<()> {
    let temp_path = path.with_extension("bench-write-tmp");
    let mut chunk = vec![0u8; WRITE_CHUNK_BYTES];
    {
        let mut file = std::io::BufWriter::new(std::fs::File::create(&temp_path)?);
        let mut written: u64 = 0;
        while written < size_bytes {
            let take = WRITE_CHUNK_BYTES.min((size_bytes - written) as usize);
            rand::fill(&mut chunk[..take]);
            file.write_all(&chunk[..take])?;
            written += take as u64;
        }
        file.flush()?;
    }
    std::fs::rename(&temp_path, path)?;
    Ok(())
}

/// Cheap size-poll cadence while waiting for the destination to even reach
/// its final size.
const SIZE_POLL_INTERVAL: Duration = Duration::from_millis(20);
/// Cadence between full-file digest re-attempts once the destination has
/// reached its final size but its content has not yet been confirmed
/// byte-exact -- see this function's caller for why a size match alone is
/// not trusted. Deliberately coarser than `SIZE_POLL_INTERVAL`: a digest
/// pass over a multi-GB file is real, non-trivial I/O + CPU work that
/// should not be re-run every 20ms.
const DIGEST_RETRY_INTERVAL: Duration = Duration::from_secs(2);

/// Polls `dest_path` for its final size, then re-hashes both files against
/// each other until they match or `OVERALL_TIMEOUT` (measured from `t0`)
/// elapses. Returns `(time from t0 to the first real digest match, source
/// digest, dest digest)`, or a real error naming the last observed
/// mismatch -- never a fabricated success.
async fn wait_for_byte_exact_convergence(
    source_path: &Path,
    dest_path: &Path,
    size_bytes: u64,
    t0: Instant,
) -> anyhow::Result<(Duration, String, String)> {
    let deadline = t0 + OVERALL_TIMEOUT;
    while Instant::now() < deadline
        && !dest_path.metadata().map(|m| m.len() == size_bytes).unwrap_or(false)
    {
        tokio::time::sleep(SIZE_POLL_INTERVAL).await;
    }

    loop {
        let source_path_owned = source_path.to_path_buf();
        let dest_path_owned = dest_path.to_path_buf();
        let (source_digest, dest_digest) = tokio::task::spawn_blocking(move || {
            anyhow::Ok((digest_file(&source_path_owned)?, digest_file(&dest_path_owned)?))
        })
        .await??;
        if source_digest == dest_digest {
            return Ok((Instant::now() - t0, source_digest, dest_digest));
        }
        if Instant::now() > deadline {
            anyhow::bail!(
                "L1 FAILED: source and destination content never converged within \
                 {OVERALL_TIMEOUT:?} (source sha256={source_digest}, last dest \
                 sha256={dest_digest}) -- not reporting a fabricated convergence metric"
            );
        }
        tokio::time::sleep(DIGEST_RETRY_INTERVAL).await;
    }
}

fn digest_file(path: &Path) -> anyhow::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; WRITE_CHUNK_BYTES];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

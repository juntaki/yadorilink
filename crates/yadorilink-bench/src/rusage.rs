//! Process-wide CPU-seconds and peak-RSS via `getrusage(2)`. Not per-daemon
//! (see `metrics::ScenarioMetrics`'s doc comment): a bench run hosts both
//! `DaemonState`s in this one OS process, so these numbers are the SUM of
//! both sides plus the harness's own bookkeeping, not either device alone.
//! Splitting the two apart would need each device driven from a genuinely
//! separate OS process (the shape W1/W2 and the real Resilio comparison
//! need anyway -- see DESIGN.md) rather than a new measurement trick here.

/// `(cpu_seconds, peak_rss_bytes)` for this process since it started.
/// `peak_rss_bytes` is `ru_maxrss`, itself already a running maximum over
/// the process's whole lifetime (not reset per call) -- normalized to bytes
/// on every platform this builds for, since the kernel reports it in KiB on
/// Linux but bytes on macOS.
pub fn snapshot() -> (f64, u64) {
    // SAFETY: `usage` is a plain-old-data `libc::rusage` the kernel fills in
    // fully on success; `RUSAGE_SELF` is always a valid target.
    let usage: libc::rusage = unsafe {
        let mut usage = std::mem::zeroed();
        libc::getrusage(libc::RUSAGE_SELF, &mut usage);
        usage
    };
    let cpu_seconds = (usage.ru_utime.tv_sec + usage.ru_stime.tv_sec) as f64
        + (usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) as f64 / 1_000_000.0;
    let peak_rss_bytes = if cfg!(target_os = "macos") {
        usage.ru_maxrss as u64
    } else {
        // Linux (and most other getrusage-bearing platforms) report KiB.
        (usage.ru_maxrss as u64).saturating_mul(1024)
    };
    (cpu_seconds, peak_rss_bytes)
}

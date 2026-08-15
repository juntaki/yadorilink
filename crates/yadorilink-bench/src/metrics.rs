//! The metrics a scenario runner reports, and the shared machinery for
//! reading the ones that are realistically captureable today. See
//! `DESIGN.md` for what each metric means and why the rest are stubbed.

use std::sync::Arc;
use std::time::Duration;

use yadorilink_transport::TransportHub;

/// A wire-level snapshot (bytes/packets sent and received) taken from one or
/// more `TransportHub`s at a point in time. Two snapshots' difference is a
/// scenario's real wire cost -- see `TransportHub::wire_bytes_sent` and
/// siblings, added specifically for this harness.
#[derive(Debug, Clone, Copy, Default)]
pub struct WireSnapshot {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
}

impl WireSnapshot {
    pub fn capture(hubs: &[&Arc<TransportHub>]) -> Self {
        let mut snapshot = Self::default();
        for hub in hubs {
            snapshot.bytes_sent += hub.wire_bytes_sent();
            snapshot.bytes_received += hub.wire_bytes_received();
            snapshot.packets_sent += hub.wire_packets_sent();
            snapshot.packets_received += hub.wire_packets_received();
        }
        snapshot
    }

    pub fn delta_since(&self, baseline: &WireSnapshot) -> WireSnapshot {
        WireSnapshot {
            bytes_sent: self.bytes_sent.saturating_sub(baseline.bytes_sent),
            bytes_received: self.bytes_received.saturating_sub(baseline.bytes_received),
            packets_sent: self.packets_sent.saturating_sub(baseline.packets_sent),
            packets_received: self.packets_received.saturating_sub(baseline.packets_received),
        }
    }
}

/// A metric a scenario either measured for real, or could not -- printed
/// distinctly so a "0" is never mistaken for a real zero-cost measurement.
/// See the M6-0 task's own constraint: "if a metric genuinely can't be
/// captured on this platform yet, the harness should say so explicitly in
/// its output, not report a fake zero."
#[derive(Debug, Clone)]
pub enum Metric {
    Duration(Duration),
    Bytes(u64),
    Count(u64),
    Rate(f64, &'static str),
    NotImplemented(&'static str),
}

impl std::fmt::Display for Metric {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Metric::Duration(d) => write!(f, "{:.3}s", d.as_secs_f64()),
            Metric::Bytes(b) => write!(f, "{b} bytes ({:.3} MiB)", *b as f64 / (1024.0 * 1024.0)),
            Metric::Count(c) => write!(f, "{c}"),
            Metric::Rate(v, unit) => write!(f, "{v:.1} {unit}"),
            Metric::NotImplemented(why) => write!(f, "NOT YET IMPLEMENTED -- {why}"),
        }
    }
}

/// A completed scenario run's full metric set, in the fixed order the M6-0
/// task specifies. `cpu_seconds`/`peak_rss_bytes` are process-wide, not
/// per-daemon -- see `rusage.rs`'s doc comment.
pub struct ScenarioReport {
    pub scenario: &'static str,
    pub file_size_bytes: u64,
    pub t_detect: Metric,
    pub t_index: Metric,
    pub t_firstbyte: Metric,
    pub t_complete: Metric,
    pub wire_bytes_sent: Metric,
    pub wire_bytes_received: Metric,
    pub disk_read_bytes: Metric,
    pub disk_write_bytes: Metric,
    pub cpu_seconds: Metric,
    pub peak_rss_bytes: Metric,
    pub packets_per_sec: Metric,
    pub fsync_count: Metric,
}

impl ScenarioReport {
    pub fn print(&self) {
        println!("=== {} ({} bytes) ===", self.scenario, self.file_size_bytes);
        println!("T_detect             {}", self.t_detect);
        println!("T_index              {}", self.t_index);
        println!("T_firstbyte          {}", self.t_firstbyte);
        println!("T_complete           {}", self.t_complete);
        println!("wire bytes sent      {}", self.wire_bytes_sent);
        println!("wire bytes received  {}", self.wire_bytes_received);
        println!("disk read bytes      {}", self.disk_read_bytes);
        println!("disk write bytes     {}", self.disk_write_bytes);
        println!("CPU seconds          {}", self.cpu_seconds);
        println!("peak RSS             {}", self.peak_rss_bytes);
        println!("packets/sec          {}", self.packets_per_sec);
        println!("fsync count          {}", self.fsync_count);
    }
}

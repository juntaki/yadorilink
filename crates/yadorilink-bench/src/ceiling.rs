//! The machine's own raw network/disk ceiling, via `iperf3`/`fio`, so a
//! scenario's numbers can later be expressed as a percentage of the
//! ceiling rather than a bare absolute. Neither tool is installed on this
//! development machine (checked via `which`), so this module currently only
//! detects and reports that honestly; actually driving them (spin up an
//! `iperf3 -s` / loopback client pair, run a representative `fio` job
//! against the block-store disk) is follow-up work -- see DESIGN.md.

use std::process::Command;

pub struct CeilingTools {
    pub iperf3_path: Option<String>,
    pub fio_path: Option<String>,
}

impl CeilingTools {
    pub fn detect() -> Self {
        Self { iperf3_path: which("iperf3"), fio_path: which("fio") }
    }

    pub fn describe(&self) -> Vec<String> {
        vec![
            describe_one("iperf3", &self.iperf3_path, "network ceiling"),
            describe_one("fio", &self.fio_path, "disk ceiling"),
        ]
    }
}

fn describe_one(tool: &str, path: &Option<String>, purpose: &str) -> String {
    match path {
        Some(p) => format!(
            "{tool} found at {p} -- {purpose} measurement not wired into this scenario yet (TODO)"
        ),
        None => format!("{tool} not installed on this machine -- {purpose} measurement skipped"),
    }
}

fn which(name: &str) -> Option<String> {
    let output = Command::new("which").arg(name).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        None
    } else {
        Some(path)
    }
}

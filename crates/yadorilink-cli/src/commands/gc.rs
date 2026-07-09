//! `yadorilink gc [--dry-run]`: triggers an immediate block-store
//! mark-and-sweep over the daemon control socket — the same round-trip
//! shape `limits.rs`/`materialization.rs` already establish for a simple
//! single-request-response daemon command.

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::GcRequest;

use crate::control_client;
use crate::error::CliError;

/// prints blocks/bytes actually deleted under a real sweep, or
/// blocks/bytes that *would* be deleted under `--dry-run` — see
/// `GcResponse`'s doc comment for why both share the same two fields.
pub async fn run(dry_run: bool) -> Result<(), CliError> {
    let resp = control_client::send(ReqPayload::Gc(GcRequest { dry_run })).await?;
    let Some(RespPayload::Gc(report)) = resp.payload else {
        return Err(CliError::Other("unexpected daemon response".into()));
    };
    println!("{}", format_gc_report(&report, dry_run));
    Ok(())
}

fn format_gc_report(report: &yadorilink_ipc_proto::daemonctl::GcResponse, dry_run: bool) -> String {
    if dry_run {
        format!(
            "Dry run: would delete {} block(s), reclaiming {} bytes",
            report.blocks_deleted, report.bytes_reclaimed
        )
    } else {
        format!(
            "Deleted {} block(s), reclaimed {} bytes",
            report.blocks_deleted, report.bytes_reclaimed
        )
    }
}

#[cfg(test)]
mod tests {
    use yadorilink_ipc_proto::daemonctl::GcResponse;

    use super::*;

    #[test]
    fn dry_run_report_says_would_delete() {
        let report = GcResponse { blocks_deleted: 3, bytes_reclaimed: 1024 };
        let line = format_gc_report(&report, true);
        assert!(line.contains("Dry run"));
        assert!(line.contains("would delete 3 block(s)"));
        assert!(line.contains("1024 bytes"));
    }

    #[test]
    fn real_run_report_says_deleted() {
        let report = GcResponse { blocks_deleted: 3, bytes_reclaimed: 1024 };
        let line = format_gc_report(&report, false);
        assert!(!line.contains("Dry run"));
        assert!(line.contains("Deleted 3 block(s)"));
        assert!(line.contains("1024 bytes"));
    }

    #[test]
    fn zero_blocks_reports_zero_cleanly() {
        let report = GcResponse { blocks_deleted: 0, bytes_reclaimed: 0 };
        let line = format_gc_report(&report, false);
        assert!(line.contains("Deleted 0 block(s), reclaimed 0 bytes"));
    }
}

//! add-resource-governance task 5.3: `yadorilink limits set --up <RATE>
//! --down <RATE>` / `yadorilink limits show` — global transfer rate limit
//! management over the daemon control socket. Rate arguments are typed as
//! `u64` in `main.rs`'s `clap` definition, so a negative or unparseable
//! value is already rejected by clap itself, with a clear error and a
//! non-zero exit, before this module's code ever runs (task 5.5's "invalid
//! rate arguments are rejected with a clear CLI error").

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{LimitsSetRequest, LimitsShowRequest};

use crate::control_client;
use crate::error::CliError;

/// `0` reads as "unlimited" — mirrors `commands::status::format_rate_bytes_per_sec`'s
/// convention, but plain (no unit scaling): `limits set`/`limits show`
/// report the exact configured byte count, not a human-scaled
/// approximation, since a user setting `--up 1048576` wants to see that
/// value confirmed exactly.
fn format_limit(bytes_per_sec: u64) -> String {
    if bytes_per_sec == 0 {
        "unlimited".to_string()
    } else {
        format!("{bytes_per_sec} bytes/sec")
    }
}

pub async fn set(up: u64, down: u64) -> Result<(), CliError> {
    let resp = control_client::send(ReqPayload::LimitsSet(LimitsSetRequest {
        upload_bytes_per_sec: up,
        download_bytes_per_sec: down,
    }))
    .await?;
    let Some(RespPayload::LimitsSet(applied)) = resp.payload else {
        return Err(CliError::Other("unexpected daemon response".into()));
    };
    println!(
        "Limits updated: up={}  down={}",
        format_limit(applied.upload_bytes_per_sec),
        format_limit(applied.download_bytes_per_sec)
    );
    Ok(())
}

pub async fn show() -> Result<(), CliError> {
    let resp = control_client::send(ReqPayload::LimitsShow(LimitsShowRequest {})).await?;
    let Some(RespPayload::LimitsShow(current)) = resp.payload else {
        return Err(CliError::Other("unexpected daemon response".into()));
    };
    println!(
        "up={}  down={}",
        format_limit(current.upload_bytes_per_sec),
        format_limit(current.download_bytes_per_sec)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_limit_zero_is_unlimited() {
        assert_eq!(format_limit(0), "unlimited");
    }

    #[test]
    fn format_limit_nonzero_reports_exact_bytes() {
        assert_eq!(format_limit(1_048_576), "1048576 bytes/sec");
    }
}

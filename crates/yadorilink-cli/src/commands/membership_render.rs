//! Shared stdout/stderr rendering for `ReplicaMembershipCommandOutcome`
//! (`device remove`, `share revoke`, `share revoke <edge-id>`) — every call
//! site used to discard this outcome entirely (`Outcome(_) => {}`), so a
//! `--force` removal's data-loss warning and an unknown-scope operation's
//! "the affected scope could not be determined" warning never reached the
//! user, even though the daemon side already computed them.

use std::io::Write;

use yadorilink_ipc_proto::daemonctl::ReplicaMembershipCommandOutcome;

pub(crate) fn render_membership_outcome(action: &str, outcome: &ReplicaMembershipCommandOutcome) {
    render_membership_outcome_to(action, outcome, &mut std::io::stdout(), &mut std::io::stderr());
}

/// Testable core: writes to the given sinks instead of the real
/// stdout/stderr so tests can pin the exact rendered text.
fn render_membership_outcome_to(
    action: &str,
    outcome: &ReplicaMembershipCommandOutcome,
    out: &mut impl Write,
    err: &mut impl Write,
) {
    for handoff in &outcome.handoffs {
        let _ = writeln!(
            out,
            "handoff completed: group={} target={} generation={} lease={}",
            handoff.group_id,
            handoff.target_device_id,
            handoff.membership_generation,
            handoff.lease_id,
        );
    }
    if !outcome.forced_group_ids.is_empty() {
        let _ = writeln!(
            err,
            "warning: forced {action} without confirmed durability for: {}. This may \
             permanently lose data.",
            outcome.forced_group_ids.join(", ")
        );
    }
    if !outcome.unknown_scope_operation_id.is_empty() {
        let _ = writeln!(
            err,
            "warning: {action} was forced before the affected folder groups could be \
             determined. The possible data-loss scope is unknown.\n\
             Recovery operation: {}\n\
             Sync status will remain degraded until reconciliation completes.",
            outcome.unknown_scope_operation_id
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(
        forced_group_ids: Vec<String>,
        unknown_scope_operation_id: &str,
    ) -> ReplicaMembershipCommandOutcome {
        ReplicaMembershipCommandOutcome {
            handoffs: Vec::new(),
            forced_group_ids,
            unknown_scope_operation_id: unknown_scope_operation_id.to_string(),
        }
    }

    #[test]
    fn forced_group_ids_render_the_data_loss_warning_with_the_exact_group_list() {
        let out_data = outcome(vec!["group-1".to_string(), "group-2".to_string()], "");
        let mut out = Vec::new();
        let mut err = Vec::new();
        render_membership_outcome_to("remove", &out_data, &mut out, &mut err);

        assert!(out.is_empty());
        assert_eq!(
            String::from_utf8(err).unwrap(),
            "warning: forced remove without confirmed durability for: group-1, group-2. This may \
             permanently lose data.\n"
        );
    }

    #[test]
    fn unknown_scope_operation_id_renders_the_scope_unknown_warning_verbatim() {
        let out_data = outcome(Vec::new(), "op-123");
        let mut out = Vec::new();
        let mut err = Vec::new();
        render_membership_outcome_to("remove", &out_data, &mut out, &mut err);

        assert!(out.is_empty());
        assert_eq!(
            String::from_utf8(err).unwrap(),
            "warning: remove was forced before the affected folder groups could be determined. \
             The possible data-loss scope is unknown.\n\
             Recovery operation: op-123\n\
             Sync status will remain degraded until reconciliation completes.\n"
        );
    }

    #[test]
    fn a_plain_committed_outcome_renders_no_warnings() {
        let out_data = outcome(Vec::new(), "");
        let mut out = Vec::new();
        let mut err = Vec::new();
        render_membership_outcome_to("remove", &out_data, &mut out, &mut err);

        assert!(out.is_empty());
        assert!(err.is_empty());
    }

    #[test]
    fn a_handoff_renders_to_stdout_not_stderr() {
        let out_data = ReplicaMembershipCommandOutcome {
            handoffs: vec![yadorilink_ipc_proto::daemonctl::MembershipHandoffResult {
                group_id: "group-1".to_string(),
                target_device_id: "device-c".to_string(),
                lease_id: "lease-1".to_string(),
                membership_generation: 7,
            }],
            forced_group_ids: Vec::new(),
            unknown_scope_operation_id: String::new(),
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        render_membership_outcome_to("revoke", &out_data, &mut out, &mut err);

        assert_eq!(
            String::from_utf8(out).unwrap(),
            "handoff completed: group=group-1 target=device-c generation=7 lease=lease-1\n"
        );
        assert!(err.is_empty());
    }
}

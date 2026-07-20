//! Shared client-side durability-readiness gate for `yadorilink share
//! revoke` and `yadorilink device remove` -- the two role-loss paths where
//! some OTHER device is losing access, so the acting device's own daemon
//! must be asked to evaluate readiness on that device's behalf, excluding it
//! from counting as its own handoff target.
//!
//! `unlink`'s equivalent gate lives daemon-side instead (see
//! `yadorilink_daemon::control_socket`'s `ensure_unlink_keeps_a_full_replica`),
//! since there the device unlinking is the one giving up its own role and
//! the existing [`DaemonState::another_full_replica_is_ready`] check already
//! excludes it naturally (it only ever checks OTHER connected peers).
//!
//! This gate is layered on top of -- not a replacement for -- the
//! coordination Worker's own authoritative access-count guard
//! (`revokeAccessGuarded`/`removeDevice`), which every revoke/remove request
//! still goes through unchanged.
//!
//! It FAILS CLOSED: unless the daemon positively confirms a ready handoff, the
//! command is refused unless `--force`. An unreachable daemon, an older daemon
//! that doesn't understand the request, or any unexpected response is treated
//! the same as "not ready" -- otherwise the readiness gate could be trivially
//! bypassed by stopping or avoiding the local daemon.
//!
//! The acting daemon can only evaluate readiness for folder groups it itself
//! links, so for an account-wide `device remove` (no group scope) this gate
//! also asks the coordination Worker (`GET /devices/:deviceId/eager-groups`)
//! for the removed device's complete eager-replica set -- authoritative
//! regardless of what the acting daemon happens to link -- and treats any
//! group outside the acting daemon's own local view as unconfirmed (not
//! ready), same as an unreachable daemon. That closes the blind spot where a
//! group the removed device fully replicates, but the acting device does not
//! itself link, would otherwise fall through to only the Worker's per-group
//! count guard.
//!
//! Group-level coverage is only half the picture, though: the readiness
//! answer itself ([`daemon_group_ready`]) is computed from THIS daemon's own
//! local root index (`SyncState::enumerate_group_durability_roots`), not the
//! target device's. That is sound when the target IS this operating device --
//! removing/revoking yourself, the local index legitimately *is* the thing
//! being removed. It is NOT sound when the target is a different device: this
//! daemon cannot enumerate or attest what that other device uniquely retains
//! (for example, versions still in its own trash that nothing else ever
//! replicated), so a locally-computed "ready" can green-light quietly losing
//! history only that other device held. [`classify_removal_target`] draws
//! that line, and a cross-device target never consults the (unsound, for
//! that case) local readiness answer -- instead
//! [`guard_cross_device_removal`] first tries the ONLINE removed-device-
//! ticket path: it asks the acting daemon to ask the removed device (B)
//! itself, over the authenticated peer channel, to attest and hand off ITS
//! OWN roots for every at-risk group (`ObtainHandoffTicketRequest`,
//! `DaemonState::obtain_handoff_ticket_from_device`). Every ticket -- the
//! confirming peer (C) B pinned its roots at, plus the live lease id C
//! obtained -- is then PRESENTED to a lease-guarded coordination-plane
//! commit ([`present_tickets_to_lease_guarded_commit`]) that atomically
//! re-verifies the lease is still live and its target still eligible at the
//! moment the removal actually happens, not merely at the moment the ticket
//! was obtained -- closing the time-of-check/time-of-use gap an earlier
//! version of this gate left open (a ticket collapsed to a bare bool, with
//! the actual revoke/delete performed unconditionally and separately). Only
//! once every group's commit succeeds does the removal proceed WITHOUT
//! `--force` -- the decision is sound because it was B, not this device,
//! that attested B's roots, AND that attestation is still true right now. If
//! B is offline, times out, any ticket isn't granted, or a lease-guarded
//! commit itself fails (an expired/released lease, or a target that fell out
//! of eligibility in between), this falls back to the pre-existing interim:
//! fail closed unconditionally unless `--force` ([`cross_device_gate`]),
//! which warns, latches every affected group to `DurabilityUnknown` (reusing
//! [`DaemonState::latch_group_durability_unknown`]), and audits the override
//! as cross-device. A commit failure is NEVER treated as a reason to fall
//! back to a plain, unconditional revoke/delete instead.

use serde::{Deserialize, Serialize};
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    CheckFullReplicaHandoffReadyExcludingRequest, HandoffResult,
    LatchGroupDurabilityUnknownRequest, ListLinksRequest, ObtainHandoffTicketRequest,
    ReleaseHandoffTicketRequest,
};

use crate::control_client;
use crate::error::CliError;
use crate::http_client::{get_json, post_json_no_content, require_access_token};

/// Prints the outcome of a completed full-replica-handoff role-loss commit
/// (`HandoffResult` -- see its own proto doc comment) in a short, stable,
/// human-readable form. Shared by every CLI command that can surface one --
/// currently only `link unlink`, whose durability gate
/// (`ensure_unlink_keeps_a_full_replica`) is the one call site that already
/// runs the coordination-plane handoff-commit endpoint end to end.
pub fn print_handoff_result(result: &HandoffResult) {
    println!(
        "  handoff completed: target={} membership_generation={}{}",
        result.target_device_id,
        result.membership_generation,
        if result.lease_id.is_empty() {
            String::new()
        } else {
            format!(" lease={}", result.lease_id)
        }
    );
}

/// Whether a removal/revoke target is this operating device itself, or some
/// other device -- the fork the module doc comment's cross-device rule turns
/// on. Deliberately pure (no I/O), so the decision itself is directly unit
/// testable without a daemon connection or coordination-plane access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemovalTarget {
    /// `target_device_id` is this same operating device -- its local root
    /// index legitimately IS the thing being removed, so the existing
    /// local-root readiness judgment is sound.
    SelfDevice,
    /// `target_device_id` is a different device. This daemon cannot
    /// enumerate or attest that device's retained/trashed roots, so a
    /// locally-computed readiness answer would be unsound here.
    OtherDevice,
}

/// A device this local daemon cannot positively identify as itself is
/// treated as `OtherDevice` too (fail closed on an unknown local identity),
/// not just an unequal id.
fn classify_removal_target(local_device_id: Option<&str>, target_device_id: &str) -> RemovalTarget {
    match local_device_id {
        Some(id) if id == target_device_id => RemovalTarget::SelfDevice,
        _ => RemovalTarget::OtherDevice,
    }
}

/// The pure outcome of the cross-device fail-closed gate (see the module
/// doc comment) -- kept independent of any I/O so this exact judgment is
/// unit testable without a daemon connection or coordination-plane access.
enum CrossDeviceGate {
    /// No `--force`: the caller must refuse with this message.
    Refuse(String),
    /// `--force`: the caller proceeds, but must print this warning, latch
    /// every group in `groups_at_risk` to `DurabilityUnknown`, and audit the
    /// override as cross-device.
    ForceOverride { warning: String },
}

/// Decides the cross-device branch of [`guard_against_forced_replica_loss`]:
/// reached whenever [`classify_removal_target`] returns `OtherDevice`. Never
/// consults a readiness answer at all -- there isn't a sound one to consult
/// for another device's roots -- so this fails closed unconditionally unless
/// `force` is set.
fn cross_device_gate(
    action: &str,
    target_device_id: &str,
    groups_at_risk: &[String],
    unverified: bool,
    force: bool,
) -> CrossDeviceGate {
    let groups_desc = if !groups_at_risk.is_empty() {
        format!("folder group(s) {}", groups_at_risk.join(", "))
    } else {
        "this account's folder groups".to_string()
    };
    let verify_note = if unverified {
        " (this device could not even confirm the complete set of groups at risk, so the real \
         blast radius may be larger than shown)"
    } else {
        ""
    };
    if !force {
        return CrossDeviceGate::Refuse(format!(
            "refusing to {action}: {target_device_id} is a different device from this one, and \
             this device has no way to verify which versions {target_device_id} retains in \
             {groups_desc}{verify_note} that no other replica holds. A durability judgment is \
             only sound when computed from the removed device's own index, and {target_device_id} \
             may hold history unique to it -- for example, versions still in its own trash that \
             nothing else ever replicated -- that a normal removal would permanently discard \
             without warning. A future online handoff would let {target_device_id} attest and \
             hand off its own roots before it is removed; until that exists, re-run with --force \
             to proceed anyway, accepting the risk of permanently losing any such device-unique \
             history."
        ));
    }
    CrossDeviceGate::ForceOverride {
        warning: format!(
            "warning: forcing {action} for {target_device_id} (a different device from this one) \
             without being able to verify its retained versions in {groups_desc}{verify_note} -- \
             this may permanently lose device-unique history no other replica holds"
        ),
    }
}

/// The pure outcome of the self-case readiness gate, once the daemon's
/// per-group readiness answers are already resolved -- exactly the decision
/// [`guard_against_forced_replica_loss`]'s original (pre-cross-device-fix)
/// logic made inline. Split out so it stays unit testable without a daemon
/// connection, and so the self case can be shown, directly, to behave
/// exactly as it did before this change.
enum ReadinessGateOutcome {
    /// Every at-risk group has a positively confirmed ready handoff. Proceed.
    Proceed,
    /// No `--force`: the caller must refuse with this message.
    Refuse(String),
    /// `--force`: the caller proceeds, but must print this warning, latch
    /// the not-ready groups to `DurabilityUnknown`, and audit the override.
    ForceOverride { warning: String },
}

fn readiness_gate_outcome(
    action: &str,
    not_ready_group_ids: &[String],
    scoped_group_id: &Option<String>,
    unverified: bool,
    force: bool,
) -> ReadinessGateOutcome {
    if not_ready_group_ids.is_empty() && !unverified {
        // Every at-risk group has a positively confirmed ready handoff to a
        // full replica other than the one being removed. Gate passed.
        return ReadinessGateOutcome::Proceed;
    }

    let groups_desc = if !not_ready_group_ids.is_empty() {
        format!("folder group(s) {}", not_ready_group_ids.join(", "))
    } else if let Some(g) = scoped_group_id {
        format!("folder group {g}")
    } else {
        "this account's folder groups".to_string()
    };
    let verify_note = if unverified {
        " (the local daemon could not confirm a ready handoff -- an unconfirmed handoff is \
         treated as not ready)"
    } else {
        ""
    };

    if !force {
        return ReadinessGateOutcome::Refuse(format!(
            "refusing to {action}: no other full replica is confirmed ready to durably hold \
             every file in {groups_desc} yet{verify_note}, so this may permanently lose the only \
             copy of that data. Wait for another full replica to finish syncing, or re-run with \
             --force to proceed anyway (data-loss risk)."
        ));
    }
    ReadinessGateOutcome::ForceOverride {
        warning: format!(
            "warning: forcing {action} without a confirmed durable-replica handoff for {groups_desc} \
             -- this may permanently lose the only copy of that data"
        ),
    }
}

/// Asks the local daemon whether every folder group put at risk by taking
/// away `excluded_device_id`'s access has another confirmed-ready full
/// replica, then enforces the shared `--force` data-loss-acknowledgement
/// contract: refuses with a clear error unless `force` is set, in which case
/// it prints a data-loss warning and logs a `tracing::warn!` audit line
/// naming the affected group(s) before letting the caller proceed.
///
/// `group_id`: `Some` scopes the check to one already-resolved folder group
/// (`share revoke`); `None` asks the daemon to check every group it locally
/// knows `excluded_device_id` as a full replica for (`device remove`, which
/// can affect any number of groups at once).
///
/// This is where [`classify_removal_target`] forks the whole gate: a
/// self-target keeps running the local-root readiness judgment below,
/// unchanged; a different-device target is refused unconditionally (short of
/// `--force`) by [`cross_device_gate`] instead, without ever asking the
/// daemon for a readiness answer that would not be sound for another
/// device's roots. See the module doc comment for why.
///
/// Returns a [`RemovalOutcome`] rather than a bare `()`: a cross-device
/// removal that went through the online removed-device-ticket path has
/// ALREADY performed the actual coordination-plane removal itself, atomically
/// bound to the live lease it presented (see [`RemovalOutcome`]'s own doc
/// comment for why this distinction exists and why the caller must not just
/// always issue its own plain removal call afterward).
pub async fn guard_against_forced_replica_loss(
    action: &str,
    group_id: Option<String>,
    excluded_device_id: &str,
    force: bool,
) -> Result<RemovalOutcome, CliError> {
    let scoped = group_id.clone();

    // The folder groups this action puts at durability risk: for a scoped
    // `share revoke` just that group; for an account-wide `device remove` the
    // removed device's COMPLETE eager-replica set as the Worker authoritatively
    // records it -- not merely what the acting daemon happens to link. Failing
    // to enumerate that set is fail-closed (unverified).
    let (groups_at_risk, mut unverified): (Vec<String>, bool) = match &group_id {
        Some(g) => (vec![g.clone()], false),
        None => match fetch_device_eager_groups(excluded_device_id).await {
            Ok(ids) => (ids, false),
            Err(_) => (Vec::new(), true),
        },
    };

    // THE self-vs-other fork: this daemon's own local root index can only
    // stand in for `excluded_device_id`'s index when they are the same
    // device. A different device's retained/trashed roots are unattestable
    // from here, so that case never reaches the local readiness judgment at
    // all -- see the module doc comment and `cross_device_gate`.
    // Fail closed on a config *error*, as distinct from genuine absence.
    // `classify_removal_target(None, ..)` treats an unknown identity as
    // `OtherDevice`, which is the correct fail-safe when the device is simply
    // not registered yet. But an IO error or corrupt `device.json` must not be
    // silently flattened into that same `None`: we genuinely cannot tell
    // whether this is the target device, so acting on a guessed classification
    // for a data-destructive command is unsafe. Abort instead, so the operator
    // fixes the config rather than proceeding on an unverifiable identity.
    let local_device_id = match crate::device_config::load() {
        Ok(cfg) => Some(cfg.device_id),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            return Err(CliError::Other(format!(
                "refusing to {action}: could not read this device's local identity from \
                 device.json ({e}). This is a data-destructive command and its cross-device \
                 safety guard depends on knowing which device this is; fix or remove device.json, \
                 or re-run `yadorilink device register`, then try again."
            )));
        }
    };
    if classify_removal_target(local_device_id.as_deref(), excluded_device_id)
        == RemovalTarget::OtherDevice
    {
        return guard_cross_device_removal(
            action,
            &scoped,
            &groups_at_risk,
            unverified,
            excluded_device_id,
            force,
        )
        .await;
    }

    // Self case from here down: unchanged from before this fix. The acting
    // daemon can only attest readiness for a group it itself links, so a
    // group it does not link is unattestable and fail-closed. Even for a
    // linked group, only a POSITIVE `ready` answer counts: inferring "ready"
    // from "linked and not flagged not-ready" would miss a group the daemon
    // skipped because its own (possibly stale) membership view doesn't yet
    // record the removed device as an eager replica of it. So each at-risk
    // group is checked individually and must come back positively ready.
    let linked = fetch_locally_linked_group_ids().await;
    let mut not_ready_group_ids: Vec<String> = Vec::new();
    for g in &groups_at_risk {
        let linked_here = linked.as_ref().is_some_and(|l| l.contains(g));
        if !linked_here {
            not_ready_group_ids.push(g.clone());
            continue;
        }
        match daemon_group_ready(g, excluded_device_id).await {
            Some(true) => {} // a peer holds the whole group excluding the target
            Some(false) => not_ready_group_ids.push(g.clone()),
            None => {
                // Couldn't get an answer for a group the daemon does link
                // (older daemon / unexpected payload / unreachable): fail closed.
                unverified = true;
                not_ready_group_ids.push(g.clone());
            }
        }
    }

    match readiness_gate_outcome(action, &not_ready_group_ids, &scoped, unverified, force) {
        ReadinessGateOutcome::Proceed => Ok(RemovalOutcome::ProceedWithPlainCall),
        ReadinessGateOutcome::Refuse(message) => Err(CliError::Other(message)),
        ReadinessGateOutcome::ForceOverride { warning } => {
            eprintln!("{warning}");
            tracing::warn!(
                action,
                groups = ?not_ready_group_ids,
                unverified,
                excluded_device_id,
                "durability readiness gate forced past by --force -- proceeding without a confirmed \
                 ready full-replica handoff"
            );
            // The groups actually forced past the gate above: the same
            // resolution `record_force_override_audit` below uses for its own
            // group_ids field (not_ready_group_ids when known, else the
            // single scoped group, else none for an unresolvable
            // account-wide check). Each is latched to `DurabilityUnknown` on
            // this daemon so `status` stops reporting it Healthy/"synced"
            // until a real whole-group handoff re-check confirms coverage
            // again -- the CLI-orchestrated counterpart to the daemon-side
            // forced-unlink path's own call to `latch_group_durability_unknown`
            // (`control_socket.rs`'s `ensure_unlink_keeps_a_full_replica`).
            let forced_group_ids: Vec<String> = if !not_ready_group_ids.is_empty() {
                not_ready_group_ids.clone()
            } else if let Some(g) = &scoped {
                vec![g.clone()]
            } else {
                Vec::new()
            };
            latch_groups_durability_unknown(&forced_group_ids).await;
            // The `tracing::warn!` line above is this machine's only record
            // of a data-loss-risking override, and it rotates away with the
            // local log like any other -- there is no durable trace of it
            // anywhere once that happens. Report the same facts to the
            // coordination plane's append-only audit table as a second,
            // durable record. Best-effort: a failure here is surfaced to the
            // operator but never blocks the override itself, since the
            // decision to proceed with `--force` was already made above.
            record_force_override_audit(
                action,
                &not_ready_group_ids,
                &scoped,
                excluded_device_id,
                unverified,
                false, // this is the self-target branch, not a cross-device override
            )
            .await;
            Ok(RemovalOutcome::ProceedWithPlainCall)
        }
    }
}

/// What the caller (`commands::share`/`commands::device`) must do once
/// [`guard_against_forced_replica_loss`] returns `Ok`. Before the atomic
/// ticket-consumption fix, the guard only ever decided yes/no and every
/// caller unconditionally followed up with its own plain removal call
/// (`POST .../revoke` or `DELETE /devices/:id`) -- which is exactly the
/// time-of-check/time-of-use gap the fix closes for the cross-device ticket
/// path: a ticket's lease could still be live when the guard granted it, but
/// nothing re-checked that at the moment the plain call actually ran, so an
/// expired-in-between lease left the removal proceeding with no live pin
/// anywhere. Now, whenever a ticket is actually used, the guard itself
/// performs the removal -- atomically bound to the lease, via the
/// coordination plane's lease-guarded commit -- and reports
/// [`RemovalOutcome::AlreadyCompleted`] so the caller does NOT also issue the
/// plain call. Every other path (self-target, verified-empty at-risk set,
/// or a `--force` override with no ticket at all) is unaffected by any of
/// this and still reports [`RemovalOutcome::ProceedWithPlainCall`], exactly
/// as before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemovalOutcome {
    /// The caller must still perform its own plain removal call.
    ProceedWithPlainCall,
    /// The removal already happened, atomically bound to a live lease, as
    /// part of the guard itself -- the caller must NOT also call the plain
    /// removal endpoint.
    AlreadyCompleted,
}

/// A removed-device handoff ticket that is actually usable to bind a removal
/// to a lease-guarded commit: the confirming peer (C) the removed device (B)
/// pinned its roots at, and the live lease id C obtained for that pin. A
/// vacuously-granted ticket for an empty root set (see
/// `DaemonState::obtain_own_handoff_ticket`'s doc comment) carries neither
/// and is deliberately NOT represented here -- see
/// [`obtain_handoff_ticket_for_group`]'s doc comment.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HandoffTicket {
    target_device_id: String,
    lease_id: String,
}

/// One at-risk group paired with the ticket obtained for it -- what
/// [`present_tickets_to_lease_guarded_commit`] needs to actually perform the
/// removal.
#[derive(Debug, Clone, PartialEq, Eq)]
struct GroupTicket {
    group_id: String,
    target_device_id: String,
    lease_id: String,
}

/// The pure fold behind the removed-device-ticket path: every at-risk group
/// must have come back with a genuinely usable ticket (a real target +
/// lease, not merely `granted = true`) for the cross-device removal to
/// proceed without `--force` -- a single ungranted (or vacuous/unusable)
/// group among several falls the WHOLE removal back to the pre-existing
/// interim, never a partial pass. An empty `results` (nothing to lift the
/// gate with -- e.g. the at-risk set itself couldn't be enumerated) is "not
/// all granted" too: there is no ticket to point to. Kept pure and separate
/// from the async per-group fetch loop so this exact judgment is unit
/// testable without a daemon connection.
fn zip_granted_tickets(
    groups_at_risk: &[String],
    results: Vec<Option<HandoffTicket>>,
) -> Option<Vec<GroupTicket>> {
    if results.is_empty() || results.iter().any(Option::is_none) {
        return None;
    }
    Some(
        groups_at_risk
            .iter()
            .cloned()
            .zip(results.into_iter().map(|t| t.expect("checked above: no None remains")))
            .map(|(group_id, t)| GroupTicket {
                group_id,
                target_device_id: t.target_device_id,
                lease_id: t.lease_id,
            })
            .collect(),
    )
}

/// Asks the local daemon to obtain a removed-device handoff ticket for one
/// folder group from `device_id` (the device being removed/revoked) --
/// `ObtainHandoffTicketRequest`'s CLI-side call, one request per group since
/// the request is scoped to a single group (mirrors `latch_groups_
/// durability_unknown`'s per-group shape). Returns `None` uniformly for
/// every non-success case (daemon unreachable, an older daemon that doesn't
/// understand the request, or the daemon's own answer reporting `granted =
/// false`) -- there is no partial-credit outcome here, matching
/// `DaemonState::obtain_handoff_ticket_from_device`'s own fail-closed
/// collapse.
///
/// Also returns `None` for a `granted = true` answer whose `lease_id`/
/// `target_device_id` are empty -- the vacuously-ready empty-root-set case
/// (nothing for the removed device to hand off). Such a ticket carries no
/// target to atomically bind a lease-guarded commit to, so this atomic
/// wiring cannot use it; a group in that state instead falls back to the
/// pre-existing interim (refuse unless `--force`) alongside any genuinely
/// ungranted group. This is a deliberate, disclosed simplification -- see
/// this module's test coverage and the top-level report for this change.
async fn obtain_handoff_ticket_for_group(group_id: &str, device_id: &str) -> Option<HandoffTicket> {
    let request = ObtainHandoffTicketRequest {
        group_id: group_id.to_string(),
        device_id: device_id.to_string(),
    };
    match control_client::send(ReqPayload::ObtainHandoffTicket(request)).await {
        Ok(resp) => match resp.payload {
            Some(RespPayload::ObtainHandoffTicket(r))
                if r.granted && !r.lease_id.is_empty() && !r.target_device_id.is_empty() =>
            {
                Some(HandoffTicket { target_device_id: r.target_device_id, lease_id: r.lease_id })
            }
            _ => None,
        },
        Err(_) => None,
    }
}

async fn release_handoff_ticket_for_group(group_id: &str, device_id: &str, ticket: &HandoffTicket) {
    let request = ReleaseHandoffTicketRequest {
        group_id: group_id.to_string(),
        device_id: device_id.to_string(),
        target_device_id: ticket.target_device_id.clone(),
        lease_id: ticket.lease_id.clone(),
    };
    let _ = control_client::send(ReqPayload::ReleaseHandoffTicket(request)).await;
}

async fn release_obtained_tickets(
    groups_at_risk: &[String],
    device_id: &str,
    results: &[Option<HandoffTicket>],
) {
    for (group_id, ticket) in groups_at_risk.iter().zip(results) {
        if let Some(ticket) = ticket {
            release_handoff_ticket_for_group(group_id, device_id, ticket).await;
        }
    }
}

/// Presents every ticket in `tickets` to a lease-guarded coordination-plane
/// commit, atomically binding the removal to each lease at the moment it
/// actually happens -- closing the time-of-check/time-of-use gap a bare
/// ticket-then-later-plain-delete would leave open. Forks on whether this is
/// a single scoped group (`share revoke`/`share revoke-edge`, `scoped_group_id
/// = Some`) or an account-wide removal (`device remove`, `scoped_group_id =
/// None`): the former presents its one ticket to the existing single-group
/// `POST .../handoff/commit` endpoint (unchanged, already atomic and
/// lease-guarded); the latter presents every ticket at once to the NEW
/// multi-group `POST /devices/:deviceId/handoff-remove` endpoint, which
/// commits every group's role loss AND deletes the device row in one
/// all-or-nothing transaction -- see that endpoint's own doc comment
/// (`coordination-worker/src/devices/service.ts`) for the shared-gate SQL
/// that makes a single invalid lease void the entire batch.
///
/// `Ok(())` means the removal is DONE -- the caller must not also issue a
/// plain removal call. `Err` means the commit was refused or unreachable
/// (e.g. a lease that was live when the ticket was obtained has since
/// expired or been released) -- the caller must treat this exactly like a
/// ticket that was never granted at all and fall through to the pre-existing
/// interim, NEVER fall back to a plain, unconditional removal call.
async fn present_tickets_to_lease_guarded_commit(
    scoped_group_id: &Option<String>,
    excluded_device_id: &str,
    tickets: &[GroupTicket],
) -> Result<(), String> {
    let access_token = require_access_token()
        .map_err(|e| format!("not logged in for the lease-guarded commit: {e}"))?;
    match scoped_group_id {
        Some(group_id) => {
            let ticket = tickets.iter().find(|t| &t.group_id == group_id).ok_or_else(|| {
                "internal error: no ticket obtained for the scoped group".to_string()
            })?;
            let outcome = yadorilink_daemon::coordination_client::commit_handoff_role_loss(
                &crate::http_client::coordination_http_addr(),
                &access_token,
                group_id,
                excluded_device_id,
                &ticket.target_device_id,
                Some(ticket.lease_id.as_str()),
                "revoke",
            )
            .await;
            match outcome {
                yadorilink_daemon::coordination_client::RoleLossCommitOutcome::Committed(result) => {
                    println!(
                        "  handoff completed: target={} membership_generation={} lease={}",
                        result.target_device_id, result.membership_generation, ticket.lease_id
                    );
                    Ok(())
                }
                yadorilink_daemon::coordination_client::RoleLossCommitOutcome::DefinitelyRejected(
                    detail,
                ) => Err(format!("lease-guarded revoke was rejected: {detail}")),
                yadorilink_daemon::coordination_client::RoleLossCommitOutcome::Ambiguous(detail) => {
                    Err(format!(
                        "lease-guarded revoke outcome is ambiguous; refusing an unconditional retry: {detail}"
                    ))
                }
            }
        }
        None => {
            commit_multi_group_handoff_removal(&access_token, excluded_device_id, tickets).await
        }
    }
}

/// The request body for the new atomic multi-group removal endpoint
/// (`POST /devices/:deviceId/handoff-remove`) -- one entry per at-risk group,
/// each carrying exactly the `(groupId, targetDeviceId, leaseId)` triple the
/// Worker's shared gate needs to re-verify that specific lease is still live
/// at commit time. Carries no digest, path, or version -- ids only, matching
/// every other coordination-plane call in this crate (INV-4).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HandoffRemoveGroupEntry<'a> {
    group_id: &'a str,
    target_device_id: &'a str,
    lease_id: &'a str,
}
#[derive(Serialize)]
struct HandoffRemoveBody<'a> {
    groups: Vec<HandoffRemoveGroupEntry<'a>>,
}

/// Presents every group's ticket to the new atomic multi-group endpoint --
/// see [`present_tickets_to_lease_guarded_commit`]'s doc comment for why this
/// is a single request rather than one commit per group. A non-2xx response
/// (any group's lease no longer live/eligible, or any other failure) is
/// reported as `Err`, which the caller treats exactly like no ticket having
/// been granted at all.
async fn commit_multi_group_handoff_removal(
    access_token: &str,
    device_id: &str,
    tickets: &[GroupTicket],
) -> Result<(), String> {
    let body = HandoffRemoveBody {
        groups: tickets
            .iter()
            .map(|t| HandoffRemoveGroupEntry {
                group_id: &t.group_id,
                target_device_id: &t.target_device_id,
                lease_id: &t.lease_id,
            })
            .collect(),
    };
    crate::http_client::post_json_no_content(
        &format!("/devices/{device_id}/handoff-remove"),
        &body,
        Some(access_token),
    )
    .await
    .map_err(|e| e.to_string())
}

/// The cross-device branch of [`guard_against_forced_replica_loss`]: reached
/// whenever `excluded_device_id` is a different device than this operating
/// one. Never consults a readiness answer computed from THIS device's own
/// root index -- see the module doc comment for why that would not be sound
/// for another device's roots -- but first tries the ONLINE removed-device-
/// ticket path: asks `excluded_device_id` itself, over the peer channel, to
/// attest and hand off its own roots for every group in `groups_at_risk`
/// ([`obtain_handoff_ticket_for_group`]). If [`zip_granted_tickets`] finds
/// every group came back with a genuinely usable ticket, THIS function
/// itself performs the removal by presenting all of them to a lease-guarded
/// coordination-plane commit ([`present_tickets_to_lease_guarded_commit`]),
/// atomically re-verifying every lease is still live at the moment the
/// removal actually happens -- not merely at the moment the ticket was
/// obtained. A commit failure (a lease that expired or was released in
/// between) is treated exactly like an ungranted ticket, never as a reason
/// to fall back to a plain, unconditional delete. Otherwise (any group not
/// granted/usable, the at-risk set itself was unverified, or the guarded
/// commit itself failed) this falls back to the pre-existing interim exactly
/// as before: refuses unconditionally unless `force` is set, in which case
/// `--force` prints a history-loss warning, latches every group in
/// `groups_at_risk` to `DurabilityUnknown` (the same mechanism the self-case
/// force path above uses), and audits the override as cross-device.
///
/// `scoped_group_id` mirrors [`guard_against_forced_replica_loss`]'s own
/// `group_id` parameter: `Some` for a single-group removal (`share revoke`),
/// which presents its one ticket to the existing single-group
/// `.../handoff/commit` endpoint; `None` for an account-wide removal
/// (`device remove`), which presents every ticket at once to the new
/// multi-group `POST /devices/:deviceId/handoff-remove` endpoint so the
/// whole removal -- every group's role loss plus the device row itself --
/// is one all-or-nothing transaction. See
/// [`present_tickets_to_lease_guarded_commit`]'s doc comment.
async fn guard_cross_device_removal(
    action: &str,
    scoped_group_id: &Option<String>,
    groups_at_risk: &[String],
    unverified: bool,
    excluded_device_id: &str,
    force: bool,
) -> Result<RemovalOutcome, CliError> {
    // A verified-empty at-risk set means the removed device is an eager
    // full replica of zero groups: nothing this gate protects is at risk,
    // so the removal is trivially safe -- allow it without --force. (Only
    // when the enumeration itself SUCCEEDED: an `unverified` empty set is a
    // failure to enumerate and must still fail closed below.) Any
    // retained/trashed data in groups where the device is NOT eager is not
    // relied-upon full-replica durability, so this gate does not count it.
    if !unverified && groups_at_risk.is_empty() {
        return Ok(RemovalOutcome::ProceedWithPlainCall);
    }
    // The at-risk set must itself be positively known (an `unverified`
    // account-wide enumeration failure never even attempts a ticket for a
    // group it can't name) -- both fold to "nothing granted" via
    // `zip_granted_tickets`'s own empty-input handling, so this early return
    // is purely to avoid the (pointless, since `groups_at_risk` is empty in
    // that case anyway) loop below.
    if !unverified && !groups_at_risk.is_empty() {
        let mut ticket_per_group = Vec::with_capacity(groups_at_risk.len());
        for group_id in groups_at_risk {
            ticket_per_group
                .push(obtain_handoff_ticket_for_group(group_id, excluded_device_id).await);
        }
        if let Some(tickets) = zip_granted_tickets(groups_at_risk, ticket_per_group.clone()) {
            match present_tickets_to_lease_guarded_commit(
                scoped_group_id,
                excluded_device_id,
                &tickets,
            )
            .await
            {
                Ok(()) => {
                    tracing::info!(
                        action,
                        groups = ?groups_at_risk,
                        excluded_device_id,
                        "cross-device removal proceeding without --force: the removed device attested \
                         and handed off its own roots for every at-risk group, atomically bound to a \
                         live lease at commit time"
                    );
                    return Ok(RemovalOutcome::AlreadyCompleted);
                }
                Err(e) => {
                    release_obtained_tickets(groups_at_risk, excluded_device_id, &ticket_per_group)
                        .await;
                    // A ticket that was granted a moment ago no longer binds a
                    // live lease at commit time (expired, released, or the
                    // target fell out of eligibility in between) -- or the
                    // commit endpoint itself was unreachable. Either way this
                    // is NOT a reason to fall back to a plain, unconditional
                    // delete: treat it exactly like the ticket was never
                    // granted at all and fall through to the interim below.
                    tracing::warn!(
                        action,
                        groups = ?groups_at_risk,
                        excluded_device_id,
                        error = %e,
                        "lease-guarded commit for the removed-device ticket path failed -- treating \
                         as not granted; falling back to the fail-closed interim rather than a plain \
                         unconditional removal"
                    );
                }
            }
        } else {
            release_obtained_tickets(groups_at_risk, excluded_device_id, &ticket_per_group).await;
        }
    }
    match cross_device_gate(action, excluded_device_id, groups_at_risk, unverified, force) {
        CrossDeviceGate::Refuse(message) => Err(CliError::Other(message)),
        CrossDeviceGate::ForceOverride { warning } => {
            eprintln!("{warning}");
            tracing::warn!(
                action,
                groups = ?groups_at_risk,
                excluded_device_id,
                unverified,
                "cross-device durability gate forced past by --force -- this device cannot \
                 attest another device's retained versions, proceeding anyway"
            );
            latch_groups_durability_unknown(groups_at_risk).await;
            record_force_override_audit(
                action,
                groups_at_risk,
                &None,
                excluded_device_id,
                unverified,
                true, // cross-device forced override
            )
            .await;
            Ok(RemovalOutcome::ProceedWithPlainCall)
        }
    }
}

/// Asks the local daemon whether one folder group has another full replica --
/// other than `excluded_device_id` -- confirmed to durably hold every one of
/// its current files. `Some(true)`/`Some(false)` is a positive answer;
/// `None` means no answer could be obtained (daemon unreachable, an older
/// daemon that doesn't understand the request, or an unexpected payload),
/// which the caller treats as fail-closed. Only meaningful for a group the
/// acting daemon actually links -- the caller verifies that separately, since
/// the daemon vacuously reports a group it has no local index for as "ready".
async fn daemon_group_ready(group_id: &str, excluded_device_id: &str) -> Option<bool> {
    let request = CheckFullReplicaHandoffReadyExcludingRequest {
        group_id: group_id.to_string(),
        excluded_device_id: excluded_device_id.to_string(),
    };
    match control_client::send(ReqPayload::CheckFullReplicaHandoffReadyExcluding(request)).await {
        Ok(resp) => match resp.payload {
            Some(RespPayload::CheckFullReplicaHandoffReadyExcluding(r)) => Some(r.ready),
            _ => None,
        },
        Err(_) => None,
    }
}

/// Best-effort: sends `LatchGroupDurabilityUnknown` to the local daemon for
/// each of `group_ids` -- one control-socket request per group, since the
/// request is scoped to a single group. A failure (unreachable daemon, older
/// daemon that doesn't understand the request, or any other error) is
/// silently ignored: this call must never block or unwind the override
/// itself, which the caller has already committed to proceeding with by the
/// time this runs. The only consequence of a failed latch is that `status`
/// won't show `DurabilityUnknown` for that group until a later request
/// succeeds or a real handoff re-check derives/clears it on its own.
async fn latch_groups_durability_unknown(group_ids: &[String]) {
    for group_id in group_ids {
        let request = LatchGroupDurabilityUnknownRequest { group_id: group_id.clone() };
        let _ = control_client::send(ReqPayload::LatchGroupDurabilityUnknown(request)).await;
    }
}

/// `GET /devices/:deviceId/eager-groups` -- every folder group `device_id`
/// is an eager (full-replica) member of, per the coordination Worker's
/// authoritative ACL records (mirrors coordination-worker's
/// `listEagerGroupsForDevice`, which scopes this to the caller's own
/// devices). Independent of, and a superset check on, whatever the acting
/// daemon happens to locally know.
async fn fetch_device_eager_groups(device_id: &str) -> Result<Vec<String>, CliError> {
    #[derive(Deserialize)]
    struct EagerGroupsResponse {
        #[serde(rename = "groupIds")]
        group_ids: Vec<String>,
    }
    let access_token = require_access_token()?;
    let resp: EagerGroupsResponse =
        get_json(&format!("/devices/{device_id}/eager-groups"), Some(&access_token)).await?;
    Ok(resp.group_ids)
}

/// The folder groups the acting daemon itself locally links, or `None` if
/// that can't be determined (daemon unreachable, older daemon, or any
/// unexpected response) -- the same fail-closed-on-unknown treatment already
/// used for `CheckFullReplicaHandoffReadyExcluding` above.
async fn fetch_locally_linked_group_ids() -> Option<Vec<String>> {
    match control_client::send(ReqPayload::ListLinks(ListLinksRequest {})).await {
        Ok(resp) => match resp.payload {
            Some(RespPayload::ListLinks(list)) => {
                Some(list.links.into_iter().map(|l| l.group_id).collect())
            }
            _ => None,
        },
        Err(_) => None,
    }
}

/// The request body for `POST /audit/force-override` — see that route's doc
/// comment in the coordination Worker (`src/routes/audit.ts`) for the durable
/// table this lands in.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ForceOverrideAuditBody<'a> {
    device_id: &'a str,
    action: &'a str,
    group_ids: &'a [String],
}

/// Builds the `force_override_audit.action` text for a `--force` override.
/// `excluded_device_id`/`unverified`/`cross_device` have no dedicated column
/// on the audit table (see `migrations/0015_force_override_audit.sql`) --
/// folded into the action text instead, matching the same facts the local
/// `tracing::warn!` line at each call site already carries. `cross_device`
/// records whether this was a cross-device forced removal (this device
/// overriding the fail-closed gate for a DIFFERENT device's roots, which it
/// could not attest) versus a self-target force override (this device
/// forcing past its own local-root readiness judgment). Pure and therefore
/// directly unit testable without a coordination-plane connection.
fn force_override_action_desc(
    action: &str,
    excluded_device_id: &str,
    unverified: bool,
    cross_device: bool,
) -> String {
    format!(
        "{action} (excluded_device_id={excluded_device_id}, unverified={unverified}, \
         cross_device={cross_device})"
    )
}

/// Best-effort durable audit record for a `--force` override: posts the same
/// facts already logged locally via `tracing::warn!` to the coordination
/// plane, so the override survives past this machine's own log rotation.
/// Never returns an error -- a missing local device registration, a missing
/// access token, or a failed request all just print a note explaining that
/// the durable record could not be written, since the override itself has
/// already been decided and must not be blocked by this.
async fn record_force_override_audit(
    action: &str,
    not_ready_group_ids: &[String],
    scoped_group_id: &Option<String>,
    excluded_device_id: &str,
    unverified: bool,
    cross_device: bool,
) {
    let note = "note: could not record a durable audit entry for this --force override";
    let device_id = match crate::device_config::load() {
        Ok(cfg) => cfg.device_id,
        Err(_) => {
            eprintln!(
                "{note} -- no local device registered; the warning above is the only record of it"
            );
            return;
        }
    };
    let access_token = match require_access_token() {
        Ok(t) => t,
        Err(_) => {
            eprintln!("{note} -- not logged in; the warning above is the only record of it");
            return;
        }
    };
    // The specific folder group(s) put at risk, when known; otherwise this
    // was an account-wide check (`device remove` with no single group in
    // view) and the audit row simply carries no group ids.
    let group_ids: Vec<String> = if !not_ready_group_ids.is_empty() {
        not_ready_group_ids.to_vec()
    } else if let Some(g) = scoped_group_id {
        vec![g.clone()]
    } else {
        Vec::new()
    };
    let action_desc =
        force_override_action_desc(action, excluded_device_id, unverified, cross_device);
    let body = ForceOverrideAuditBody {
        device_id: &device_id,
        action: &action_desc,
        group_ids: &group_ids,
    };
    // Bound the POST: this is best-effort and must never block the override the
    // caller already committed to. The shared HTTP client has no request
    // timeout, so a stalled connection would otherwise hang here indefinitely
    // before the revoke/remove proceeds.
    let post = post_json_no_content("/audit/force-override", &body, Some(&access_token));
    match tokio::time::timeout(std::time::Duration::from_secs(5), post).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            eprintln!("{note} on the coordination plane ({e}) -- the warning above is the only record of it");
        }
        Err(_) => {
            eprintln!("{note} on the coordination plane (timed out) -- the warning above is the only record of it");
        }
    }
}

#[cfg(test)]
mod tests {
    //! Covers the P0 durability fix's core judgment: `share revoke`/`device
    //! remove` against a DIFFERENT device must fail closed unconditionally
    //! (never consulting a locally-computed readiness answer, which would be
    //! unsound for another device's roots), while the same commands against
    //! this operating device itself keep behaving exactly as before.
    //!
    //! `guard_against_forced_replica_loss` itself needs a live daemon
    //! connection and (for `device remove`) a coordination-plane access
    //! token, neither of which this unit-test binary has, so it is not
    //! exercised end to end here. Instead these tests target the pure
    //! decision points it delegates to (`classify_removal_target`,
    //! `cross_device_gate`, `readiness_gate_outcome`,
    //! `force_override_action_desc`), which carry the entire self-vs-other
    //! and fail-closed logic, plus the real daemon-side latch primitive
    //! those decisions drive.

    use super::*;

    fn group_ids(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    // --- classify_removal_target -------------------------------------

    #[test]
    fn classify_removal_target_is_self_only_when_ids_match() {
        assert_eq!(
            classify_removal_target(Some("device-x"), "device-x"),
            RemovalTarget::SelfDevice
        );
        assert_eq!(
            classify_removal_target(Some("device-x"), "device-a"),
            RemovalTarget::OtherDevice
        );
    }

    #[test]
    fn classify_removal_target_fails_closed_when_local_identity_is_unknown() {
        // If this device can't even determine its own id, it certainly
        // can't confirm the target IS itself -- treat that as "other" too,
        // not as a free pass.
        assert_eq!(classify_removal_target(None, "device-a"), RemovalTarget::OtherDevice);
    }

    // --- cross-device fail-closed gate --------------------------------

    /// `share revoke <group> <other-device>` without `--force`: refused
    /// outright. This is the load-bearing assertion that the cross-device
    /// path never consults a readiness answer at all -- there is no `ready`
    /// input to this function for it to have been swayed by; the refusal
    /// is unconditional on the target being a different device.
    #[test]
    fn cross_device_revoke_is_fail_closed_without_force() {
        let groups = group_ids(&["group-1"]);
        match cross_device_gate("revoke this device's access", "device-a", &groups, false, false) {
            CrossDeviceGate::Refuse(message) => {
                assert!(message.contains("device-a"), "must name the target device: {message}");
                assert!(message.contains("--force"), "must point at the escape hatch: {message}");
                assert!(message.contains("group-1"), "must name the at-risk group: {message}");
            }
            CrossDeviceGate::ForceOverride { .. } => {
                panic!("a cross-device removal without --force must be refused, not proceed")
            }
        }
    }

    /// `device remove <other-device>` without `--force`: refused outright,
    /// even for the account-wide (multi-group, no single scoped group) shape
    /// `device remove` uses. Also covers the eager-groups-fetch-failed
    /// (`unverified`) case: refusal must not depend on having successfully
    /// enumerated every at-risk group first.
    #[test]
    fn cross_device_device_remove_is_fail_closed_without_force() {
        let groups = group_ids(&["group-1", "group-2"]);
        match cross_device_gate("remove this device", "device-a", &groups, false, false) {
            CrossDeviceGate::Refuse(message) => {
                assert!(message.contains("device-a"));
                assert!(message.contains("--force"));
            }
            CrossDeviceGate::ForceOverride { .. } => panic!("must refuse without --force"),
        }
        // Even when the eager-group enumeration itself failed (unverified),
        // the account-wide check still refuses outright.
        match cross_device_gate("remove this device", "device-a", &[], true, false) {
            CrossDeviceGate::Refuse(message) => assert!(message.contains("--force")),
            CrossDeviceGate::ForceOverride { .. } => panic!("must refuse without --force"),
        }
    }

    /// The self-case tail (`readiness_gate_outcome`) is exactly the
    /// pre-existing inline logic, unchanged: a positively-confirmed-ready
    /// answer permits the removal WITHOUT `--force`, and a not-ready answer
    /// is refused without `--force` -- the same behavior this code had
    /// before the cross-device fix, now just reachable only via the
    /// `SelfDevice` fork.
    #[test]
    fn self_removal_still_uses_local_root_handoff_judgment() {
        assert_eq!(
            classify_removal_target(Some("device-x"), "device-x"),
            RemovalTarget::SelfDevice
        );

        // Ready: no not-ready groups, not unverified -> proceed without --force.
        match readiness_gate_outcome(
            "revoke this device's access",
            &[],
            &Some("group-1".into()),
            false,
            false,
        ) {
            ReadinessGateOutcome::Proceed => {}
            _ => panic!("a confirmed-ready self removal must proceed without --force"),
        }

        // Not ready, no --force -> refused.
        let not_ready = group_ids(&["group-1"]);
        match readiness_gate_outcome(
            "revoke this device's access",
            &not_ready,
            &Some("group-1".into()),
            false,
            false,
        ) {
            ReadinessGateOutcome::Refuse(message) => {
                assert!(message.contains("group-1"));
                assert!(message.contains("--force"));
            }
            _ => panic!("a not-ready self removal without --force must be refused"),
        }
    }

    /// Removing a device that is an eager full replica of several groups
    /// must show the user every one of those groups, not just the first or
    /// a generic "some groups" message -- the concrete blast radius has to
    /// be visible before the user decides whether to `--force`.
    #[test]
    fn multi_group_device_remove_enumerates_at_risk_groups() {
        let groups = group_ids(&["group-1", "group-2", "group-3"]);
        match cross_device_gate("remove this device", "device-a", &groups, false, false) {
            CrossDeviceGate::Refuse(message) => {
                for g in &groups {
                    assert!(message.contains(g), "refusal must list {g}: {message}");
                }
            }
            CrossDeviceGate::ForceOverride { .. } => panic!("must refuse without --force"),
        }
        // The forced-override warning must enumerate them too.
        match cross_device_gate("remove this device", "device-a", &groups, false, true) {
            CrossDeviceGate::ForceOverride { warning } => {
                for g in &groups {
                    assert!(warning.contains(g), "warning must list {g}: {warning}");
                }
            }
            CrossDeviceGate::Refuse(_) => panic!("--force must proceed, not refuse"),
        }
    }

    /// `--force` on a cross-device removal must (a) emit a history-loss
    /// warning naming the target device, (b) latch every affected group to
    /// `DurabilityUnknown` on the real daemon state (reusing the exact same
    /// `DaemonState::latch_group_durability_unknown` primitive the
    /// forced-unlink path already uses -- not a new mechanism), and (c)
    /// produce an audit action string that records this was a cross-device
    /// forced override, not a self-target one. The actual coordination-plane
    /// POST and the actual daemon control-socket round trip both need live
    /// processes this unit-test binary doesn't have, so those two hops are
    /// exercised at their real, non-networked cores instead: the same
    /// `DaemonState` the daemon process holds, and the same `String` that
    /// would become the audit row's `action` column.
    #[tokio::test]
    async fn forced_cross_device_removal_warns_latches_unknown_and_audits() {
        let groups = group_ids(&["group-1", "group-2"]);

        // (a) warning.
        let warning =
            match cross_device_gate("remove this device", "device-a", &groups, false, true) {
                CrossDeviceGate::ForceOverride { warning } => warning,
                CrossDeviceGate::Refuse(_) => panic!("--force must proceed"),
            };
        assert!(warning.contains("device-a"), "warning must name the target device: {warning}");
        assert!(
            warning.to_lowercase().contains("history") || warning.to_lowercase().contains("lose"),
            "warning must convey the history-loss risk: {warning}"
        );

        // (b) the real latch primitive, against a real (in-memory) DaemonState
        // -- the same one `control_socket.rs`'s `LatchGroupDurabilityUnknown`
        // handler calls, and the same one the pre-existing forced-unlink path
        // already relies on.
        let state = test_daemon_state();
        for g in &groups {
            assert_ne!(
                state.group_durability_status(g),
                yadorilink_daemon::daemon_state::GroupDurabilityStatus::DurabilityUnknown,
                "group must not start out latched"
            );
        }
        for g in &groups {
            state.latch_group_durability_unknown(g).unwrap();
        }
        for g in &groups {
            assert_eq!(
                state.group_durability_status(g),
                yadorilink_daemon::daemon_state::GroupDurabilityStatus::DurabilityUnknown,
                "a forced cross-device override must latch every affected group"
            );
        }

        // (c) the audit action text records the cross-device fact -- this is
        // the exact string `record_force_override_audit` posts as the
        // existing `force_override_audit.action` column (see
        // `migrations/0015_force_override_audit.sql`); no new column, no new
        // table, same shape as the pre-existing self-target/unlink override
        // audit record.
        let self_desc = force_override_action_desc("remove this device", "device-a", false, false);
        let cross_desc = force_override_action_desc("remove this device", "device-a", false, true);
        assert!(cross_desc.contains("cross_device=true"), "got: {cross_desc}");
        assert!(self_desc.contains("cross_device=false"), "got: {self_desc}");
        assert_ne!(self_desc, cross_desc, "the audit text must distinguish the two cases");
    }

    // --- Removed-device-ticket decision (Stage C atomic-consumption fix) --

    fn ticket(target: &str, lease: &str) -> Option<HandoffTicket> {
        Some(HandoffTicket { target_device_id: target.to_string(), lease_id: lease.to_string() })
    }

    /// Every at-risk group came back with a genuinely usable ticket -> zipped
    /// into one `GroupTicket` per group, in order, ready to present to a
    /// lease-guarded commit.
    #[test]
    fn zip_granted_tickets_zips_every_group_when_all_granted() {
        let groups = group_ids(&["group-1", "group-2"]);
        let results = vec![ticket("device-c1", "lease-1"), ticket("device-c2", "lease-2")];
        let tickets = zip_granted_tickets(&groups, results).expect("every group granted a ticket");
        assert_eq!(
            tickets,
            vec![
                GroupTicket {
                    group_id: "group-1".to_string(),
                    target_device_id: "device-c1".to_string(),
                    lease_id: "lease-1".to_string(),
                },
                GroupTicket {
                    group_id: "group-2".to_string(),
                    target_device_id: "device-c2".to_string(),
                    lease_id: "lease-2".to_string(),
                },
            ]
        );
    }

    /// A single ungranted (or vacuous/unusable) group among several at-risk
    /// groups must fall the WHOLE removal back to the interim -- no partial
    /// credit for a multi-group `device remove` where only some groups'
    /// tickets came back granted. This is exactly the all-or-nothing
    /// property the shared gate on the Worker's multi-group endpoint also
    /// enforces server-side (see that endpoint's own tests) -- this is the
    /// CLI-side half of the same guarantee: it must never even ATTEMPT a
    /// partial commit.
    #[test]
    fn zip_granted_tickets_is_none_when_any_group_is_not_granted() {
        let groups = group_ids(&["group-1", "group-2", "group-3"]);
        let results = vec![ticket("device-c1", "lease-1"), None, ticket("device-c3", "lease-3")];
        assert!(
            zip_granted_tickets(&groups, results).is_none(),
            "one ungranted group among several must void the whole batch"
        );
    }

    /// No at-risk groups to point a ticket at (e.g. the eager-groups
    /// enumeration itself failed) is "not all granted" too -- there is
    /// nothing here to lift the fail-closed gate with.
    #[test]
    fn zip_granted_tickets_is_none_for_an_empty_result_set() {
        assert!(zip_granted_tickets(&[], Vec::new()).is_none());
    }

    /// `device remove B` where B is a VERIFIED eager full replica of ZERO
    /// groups: nothing this gate protects is at risk, so the removal is
    /// trivially safe and must proceed WITHOUT `--force`, via the caller's
    /// own plain removal call (there is nothing to bind a lease-guarded
    /// commit to). This exercises the real `guard_cross_device_removal` --
    /// its verified-empty early return runs entirely before any daemon/
    /// coordination-plane I/O, so it is reachable from this unit-test binary
    /// (which has neither a live daemon nor an access token). Reaching
    /// `cross_device_gate` at all would refuse without `--force`, so a
    /// `ProceedWithPlainCall` here proves the early return fired and no
    /// `DurabilityUnknown` latch or force-override audit was written (both
    /// live only past the gate, which was never reached).
    #[tokio::test]
    async fn verified_empty_at_risk_set_proceeds_without_force() {
        let result =
            guard_cross_device_removal("remove this device", &None, &[], false, "device-a", false)
                .await;
        match result {
            Ok(RemovalOutcome::ProceedWithPlainCall) => {}
            other => panic!(
                "a device that is an eager full replica of zero groups has nothing at risk and \
                 must proceed without --force via a plain call, got {other:?}"
            ),
        }
    }

    /// The mirror guard on that early return: an UNVERIFIED empty at-risk
    /// set is a FAILURE to enumerate the removed device's eager groups, not
    /// a positive "zero groups" fact, so it must STILL fail closed --
    /// refused without `--force`, exactly as before this fix. Also reaches
    /// no I/O: the refuse arm of `cross_device_gate` returns immediately.
    #[tokio::test]
    async fn unverified_empty_at_risk_set_still_fails_closed_without_force() {
        let result =
            guard_cross_device_removal("remove this device", &None, &[], true, "device-a", false)
                .await;
        match result {
            Err(CliError::Other(message)) => {
                assert!(message.contains("--force"), "must point at the escape hatch: {message}");
            }
            other => {
                panic!("an enumeration failure must still refuse without --force, got {other:?}")
            }
        }
    }

    /// A non-empty, verified at-risk set with NO daemon/control-socket
    /// available (this unit-test binary has none) must fail exactly the same
    /// way an offline removed device does: every per-group ticket attempt
    /// comes back `None` (unreachable), `zip_granted_tickets` folds that to
    /// "not all granted", and the whole removal falls through to the
    /// fail-closed interim -- refused without `--force`. This is the
    /// structural proof, reachable from this binary, that a ticket failure
    /// NEVER falls back to a plain unconditional removal: the only two
    /// exits from `guard_cross_device_removal` past this point are
    /// `cross_device_gate`'s `Refuse` or its `--force` override, never a
    /// bare `Ok` that bypasses them.
    #[tokio::test]
    async fn cross_device_removal_with_no_ticket_available_falls_back_to_interim_refusal() {
        let groups = group_ids(&["group-1"]);
        let result = guard_cross_device_removal(
            "revoke this device's access",
            &Some("group-1".to_string()),
            &groups,
            false,
            "device-a",
            false,
        )
        .await;
        match result {
            Err(CliError::Other(message)) => {
                assert!(message.contains("--force"), "must point at the escape hatch: {message}");
                assert!(message.contains("device-a"));
            }
            other => panic!(
                "no daemon/ticket available must fail closed to the interim, never a plain removal, \
                 got {other:?}"
            ),
        }
    }

    /// Minimal in-memory `DaemonState` for exercising the real
    /// latch/durability-status primitives without a running daemon process
    /// -- same construction `yadorilink-daemon`'s own `daemon_state` tests
    /// use for `test_state()`.
    fn test_daemon_state() -> std::sync::Arc<yadorilink_daemon::daemon_state::DaemonState> {
        let store_dir = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(
            yadorilink_local_storage::FsBlockStore::new(store_dir.path()).unwrap(),
        );
        let sync_state =
            std::sync::Arc::new(yadorilink_sync_core::index::SyncState::open_in_memory().unwrap());
        yadorilink_daemon::daemon_state::DaemonState::new(
            "device-under-test".into(),
            sync_state,
            store,
        )
    }
}

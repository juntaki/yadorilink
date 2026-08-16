//! M5-A Pass 3, review follow-up: `topology_n_m_w.rs`'s happy-path test
//! never actually proves `Protected` or a confirmed-remote-holder
//! `AvailableNow` -- its topology has only ONE full replica (structurally
//! `AtRisk` by design), and its `AvailableNow` assertion runs AFTER W has
//! already hydrated the file locally, so `fully_hydrated_locally` alone
//! (not a confirmed remote peer) could be what made it pass.
//!
//! This test closes both gaps with a real N(FullReplica)/M(FullReplica)/
//! W(OnDemand) topology, built via the SAME production storage-mode path
//! `stand_up_canonical_topology` already uses for N (`link_eager` plus a
//! matching coordination-plane declaration for M too -- not a
//! `FakeCoordination`-only role mismatched against M's actual local
//! storage mode):
//!
//! - N authors real content through the real watcher/DAG path.
//! - M (Eager) auto-hydrates it -- a real second full-replica holder.
//! - A real custody-confirmation sweep (`DaemonState::refresh_custody_
//!   confirmation`, the same call `DurabilityConfirmationJob` makes
//!   periodically in production) lets N positively confirm M's custody,
//!   reaching `Protected`.
//! - W sees the DAG record but is DELIBERATELY NEVER hydrated in this
//!   test -- proving `AvailableNow` (asserted through W's own REAL
//!   control socket, not `DaemonState` internals) reflects a confirmed
//!   reachable remote holder, never local materialization. W's own
//!   `refresh_custody_confirmation` sweep is what supplies that
//!   evidence, exactly as `fetch_available_via_confirmed_peer` requires.
//! - The wire model's `full_replica_device_ids` is also checked, closing
//!   the "current-version holder reflected on the wire" requirement.

mod support;

use std::time::Duration;

use support::fake_coordination::FakeCoordination;
use support::topology::stand_up_topology_two_full_replicas_one_on_demand;
use support::wait_until_with_context;
use yadorilink_daemon::durability_service::GroupDurabilityStatus;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn protected_and_available_now_reflect_a_confirmed_remote_holder_not_local_hydration() {
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "topology-pass3-protected-group";

    let (n, m, w, handles) =
        stand_up_topology_two_full_replicas_one_on_demand(&fake, group_id).await;

    // N authors real content through the real watcher/debounce/executor
    // path -- a genuine current version, not a raw DB upsert.
    let path = n.root.path().join("shared.bin");
    std::fs::write(&path, b"protected content").unwrap();

    // M is Eager: waits for it to auto-hydrate with no explicit
    // `hydration::hydrate` call, unlike W below -- proving M is a real,
    // independently-materialized second full-replica holder, not a
    // declaration-only stand-in.
    wait_until_with_context(
        || {
            std::fs::read(m.root.path().join("shared.bin")).ok().as_deref()
                == Some(b"protected content".as_slice())
        },
        Duration::from_secs(30),
        || "M never auto-hydrated N's content".to_string(),
    )
    .await;

    // W sees the DAG record but is deliberately NEVER hydrated anywhere
    // in this test -- the whole point is to prove `AvailableNow` does not
    // depend on W's own local materialization.
    wait_until_with_context(
        || {
            w.state
                .replica_coordinator
                .file_index_repository()
                .list_files(group_id)
                .map(|files| files.iter().any(|f| f.path == "shared.bin" && !f.deleted))
                .unwrap_or(false)
        },
        Duration::from_secs(30),
        || "W never saw shared.bin's DAG record".to_string(),
    )
    .await;
    // A `Placeholder` row is a real on-disk artifact too (a placeholder
    // marker file under this path's exact name, in this non-OS-native
    // test environment) -- `std::fs::exists` alone can never distinguish
    // "placeholder" from "hydrated"; only `materialization_state` can.
    assert_eq!(
        w.state
            .replica_coordinator
            .materialization_state_repository()
            .get_materialization_state(group_id, "shared.bin")
            .unwrap(),
        Some(yadorilink_replica_domain::session_state::MaterializationState::Placeholder),
        "W must not have materialized this file locally before durability/availability are even \
         checked -- a pre-existing local copy would make this test unable to distinguish \
         confirmed-remote-holder evidence from mere local presence"
    );

    // Real custody-confirmation sweeps -- the same call
    // `DurabilityConfirmationJob` makes periodically in production. From
    // N's side: confirms M's custody, closing the `Protected` gap. From
    // W's side: confirms a reachable full-replica peer holds this
    // group's current content, the evidence `fetch_available_via_
    // confirmed_peer` requires for `AvailableNow` on a device with
    // nothing hydrated locally.
    n.state.refresh_custody_confirmation(group_id).await;
    w.state.refresh_custody_confirmation(group_id).await;

    assert_eq!(
        n.state.group_durability_status(group_id),
        GroupDurabilityStatus::Protected,
        "two confirmed full-replica peers (N holding locally, M's custody freshly confirmed) \
         must read Protected, not AtRisk/Protecting"
    );

    // Read-model truthfulness through the REAL wire boundary, from W's
    // own control socket -- not `DaemonState` internals -- while W's
    // record is STILL a `Placeholder`, not `Hydrated`.
    assert_eq!(
        w.state
            .replica_coordinator
            .materialization_state_repository()
            .get_materialization_state(group_id, "shared.bin")
            .unwrap(),
        Some(yadorilink_replica_domain::session_state::MaterializationState::Placeholder),
        "W must still be unhydrated at the moment fetch_availability is asserted"
    );
    let w_link = support::control_socket_client::query_link_status(w.state.clone(), group_id).await;

    assert_eq!(
        w_link.local_storage_state(),
        yadorilink_ipc_proto::daemonctl::LocalStorageState::OnDemand,
        "W's wire-reported local storage state must truthfully be OnDemand"
    );
    assert_eq!(
        w_link.fetch_availability(),
        yadorilink_ipc_proto::daemonctl::FetchAvailability::AvailableNow,
        "AvailableNow must be reported through the wire model purely from a confirmed reachable \
         remote holder (N/M), even though W itself has never hydrated this file"
    );
    assert!(
        w_link.full_replica_device_ids.contains(&n.device_id)
            || w_link.full_replica_device_ids.contains(&m.device_id),
        "the wire model's current-version-holder list must name at least one of the two real \
         full-replica devices; got {:?}",
        w_link.full_replica_device_ids
    );

    handles.shutdown();
}

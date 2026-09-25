//! The coordination-plane half of the product view's device derivations.
//!
//! `yadorilink_product_view::device` is pure: it names the folder groups to
//! fetch (`distinct_group_ids`) and derives `DeviceSummary` rows and peer
//! counts from member lists it is handed. The fetching lives here, over
//! the client layer's already-tested `list_members_resolved`/`own_device_id`
//! -- the same coordination-plane client every other sharing surface in this
//! crate uses -- rather than a second, independent HTTP path, and rather
//! than pulling that client down into the view crate.

use std::collections::HashMap;

use yadorilink_client_core::ops::shares::{list_members_resolved, own_device_id, GroupMemberInfo};
use yadorilink_client_core::CoreError;
use yadorilink_ipc_proto::daemonctl::LinkStatus;
use yadorilink_product_view::DeviceSummary;

/// Projects one coordination-plane member row onto the product view's
/// device shape.
fn device_summary(member: &GroupMemberInfo) -> DeviceSummary {
    DeviceSummary {
        device_id: member.device_id.clone(),
        display_name: member.device_name.clone(),
        online: member.online,
        last_seen_unix: member.last_seen_unix,
    }
}

/// One folder group's member list, projected.
async fn group_members(group_id: &str) -> Result<Vec<DeviceSummary>, CoreError> {
    Ok(list_members_resolved(group_id).await?.iter().map(device_summary).collect())
}

/// One distinct folder group's own member list per `group_id` in `links`,
/// fetched exactly once each, in link order -- the shared fan-out
/// `device_summaries`/`peer_counts` below both build on. Returns as soon as
/// any one call fails; a best-effort partial listing under a transient
/// per-group failure is a UI concern for the caller.
async fn group_memberships(
    links: &[LinkStatus],
) -> Result<Vec<(String, Vec<DeviceSummary>)>, CoreError> {
    let mut out = Vec::new();
    for group_id in yadorilink_product_view::distinct_group_ids(links) {
        let members = group_members(&group_id).await?;
        out.push((group_id, members));
    }
    Ok(out)
}

/// Every device with access to any of `links`' folder groups, merged across
/// groups (see `yadorilink_product_view::device_summaries`).
pub async fn device_summaries(links: &[LinkStatus]) -> Result<Vec<DeviceSummary>, CoreError> {
    let memberships = group_memberships(links).await?;
    Ok(yadorilink_product_view::device_summaries(
        memberships.iter().map(|(_group_id, members)| members.as_slice()),
    ))
}

/// How many OTHER devices have access to the folder group `group_id` --
/// its coordination-plane member count minus this device itself, identified
/// by the same local `device_config`-backed id `share members` labels "you".
/// One member-list call: the right choice for a caller that only ever needs
/// one folder's count; a caller rendering many folders at once should use
/// `peer_counts`.
pub async fn peer_count(group_id: &str) -> Result<usize, CoreError> {
    let members = group_members(group_id).await?;
    Ok(yadorilink_product_view::peer_count(&members, own_device_id().as_deref()))
}

/// The batched form of `peer_count`: one member-list call per distinct
/// `group_id` in `links`, every group's peer count keyed by `group_id`.
pub async fn peer_counts(links: &[LinkStatus]) -> Result<HashMap<String, usize>, CoreError> {
    let memberships = group_memberships(links).await?;
    Ok(yadorilink_product_view::peer_counts(
        memberships.iter().map(|(group_id, members)| (group_id.as_str(), members.as_slice())),
        own_device_id().as_deref(),
    ))
}

#[cfg(test)]
mod tests;

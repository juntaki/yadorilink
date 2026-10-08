//! `yadorilink preserved list | restore <item-id> | retry <item-id> | discard <item-id> [--yes]`: what a
//! rebootstrap set aside for you. A version another device wrote that the group's replacing
//! state did not contain stays until you restore it (as one ordinary new write) or discard it;
//! your own changes that could not be replayed are listed with where their files are.

use yadorilink_client_core::ops::storage;
use yadorilink_ipc_proto::daemonctl::PreservedItem;

use crate::error::CliError;

pub async fn list() -> Result<(), CliError> {
    let items = storage::list_preserved().await?;
    if items.is_empty() {
        println!("Nothing is preserved.");
        return Ok(());
    }
    for item in &items {
        println!("{}", format_item(item));
    }
    Ok(())
}

pub async fn restore(item_id: &str) -> Result<(), CliError> {
    let group = group_of(item_id).await?;
    storage::restore_preserved(&group, item_id).await?;
    println!("Restored {item_id}: it is written back as a new version; the item is kept.");
    Ok(())
}

pub async fn retry(item_id: &str) -> Result<(), CliError> {
    let group = group_of(item_id).await?;
    storage::retry_preserved(&group, item_id).await?;
    println!(
        "Retried {item_id}: its changes are written as new versions and it is no longer held."
    );
    Ok(())
}

pub async fn discard(item_id: &str, yes: bool) -> Result<(), CliError> {
    if !yes {
        return Err(CliError::Other(format!(
            "discarding {item_id} deletes the only copy kept on this device; \
             re-run with --yes to confirm"
        )));
    }
    let group = group_of(item_id).await?;
    storage::discard_preserved(&group, item_id).await?;
    println!("Discarded {item_id}.");
    Ok(())
}

/// The group an item belongs to: items are named by id alone on the command line.
async fn group_of(item_id: &str) -> Result<String, CliError> {
    storage::list_preserved()
        .await?
        .into_iter()
        .find(|item| item.item_id == item_id)
        .map(|item| item.group_id)
        .ok_or_else(|| CliError::Other(format!("no preserved item {item_id}")))
}

/// One line of `list`: id, group, what it is and where.
pub(crate) fn format_item(item: &PreservedItem) -> String {
    let removed = if item.group_removed { " (group removed)" } else { "" };
    match item.kind.as_str() {
        "own_unit" => format!(
            "{}  group={}{removed}  own changes not replayed: {}{}",
            item.item_id,
            item.group_id,
            item.paths.join(", "),
            if item.originals_quarantined {
                format!(
                    "  (originals moved out of the folder into recovery area {})",
                    item.recovery_id
                )
            } else {
                format!("  (files stay in recovery area {})", item.recovery_id)
            }
        ),
        kind => {
            let content = match item.content.as_str() {
                "complete" => "content complete".to_string(),
                "unavailable" => format!(
                    "content unavailable ({} of {} blocks)",
                    item.blocks_held, item.blocks_total
                ),
                _ => "record unavailable".to_string(),
            };
            format!(
                "{}  group={}{removed}  {}  {kind}  {content}  {} bytes",
                item.item_id, item.group_id, item.path, item.size
            )
        }
    }
}

#[cfg(test)]
mod tests;

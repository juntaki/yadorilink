//! One author's position in its own chain, and the retained state that
//! remembers it.
//!
//! A change's causal dot is `(group_id, device_id, author_seq)`. The author
//! component is the device id: the coordination plane issues one per
//! registration and binds a signing key to it once, so a device id is an
//! identity something outside this machine has attested, which a locally
//! minted author name would not be. The sequence counts only that author's
//! own changes in that group. It is consecutive from 1, and it never
//! restarts — not when history is compacted onto a new base, and not when
//! the author goes offline and comes back.
//!
//! What a sequence number does not survive a base switch as is the link.
//! Each author's position is a watermark plus an anchor: either the active
//! tip, the change that attained the watermark and that the next change
//! names as its `author_prev`, or a history base that carried the
//! watermark and absorbed the change that attained it. On a base, the next
//! change links through its signed history epoch and names no
//! predecessor; once it is admitted, the anchor is an active tip again.
//!
//! Two things record that position, and they answer different questions.
//!
//! `changes.author_seq` is a column copy of the signed field, carried so an
//! author's stored changes can be looked up by dot without decoding them,
//! and — through the unique index over `(group_id, device_id, author_seq)`
//! — so two different changes can never occupy one dot in the store. It
//! describes retained history only, and retained history shrinks: a
//! compaction deletes the rows below the new base.
//!
//! `author_chain_state` is the part that must not shrink. It holds, per
//! author per group, the highest sequence that author has ever reached here
//! and the change that reached it — the watermark and the tip. It is
//! written in the same transaction as the change that advances it, and it
//! is never lowered, so it still answers "what did this author write last"
//! after every one of those changes has been pruned away. That durability
//! is the whole reason it is a table of its own rather than a query over
//! `changes`: an author's next sequence read from retained history alone
//! would silently restart at the compaction boundary, and a restarted
//! sequence makes the watermark claim this replica holds changes it has
//! never seen.
//!
//! The watermark alone is not enough to decide admission, which is why the
//! tip is stored beside it: arithmetic on a counter cannot tell a change
//! that continues this author's history from one that forks off an
//! abandoned branch at the same number. The tip is what settles that, and
//! it settles it by NAME: every change carries a signed `author_prev`, the
//! change its author wrote immediately before it, and a change continues
//! this author's history exactly when the change it names is the tip this
//! replica holds.
//!
//! By name, and deliberately not by DAG ancestry. Author ordering and
//! causality are two different relations, and conflating them breaks the
//! ordinary case. A local edit is parented on the causal basis of the bytes
//! the user actually edited — which is what makes the edit mean what the
//! user's bytes meant, and what keeps a peer change that landed between
//! capture and emit from being falsely claimed as seen and overwritten. So
//! the same device's latest write, to some unrelated path, is routinely NOT
//! an ancestor of its own next change. Requiring ancestry would therefore
//! refuse a perfectly ordinary local edit on every replica but the one that
//! wrote it. Requiring the name refuses only a genuine fork of the author's
//! own chain, which is the thing the rule is actually for.

use rusqlite::{Connection, OptionalExtension};
use yadorilink_replica_domain::admission::{AuthorAnchor, AuthorChainRefusal};
use yadorilink_replica_domain::change::Change;
use yadorilink_replica_domain::ids::{AuthorSeq, ChangeHash};
use yadorilink_replica_domain::rebootstrap::{HistoryBase, HistoryEpoch};
use yadorilink_replica_engine::rebootstrap_snapshot::SnapshotAuthorState;

use crate::dag_store::RejectionDomain;
use crate::error::SyncSqliteError;

/// One author's retained position in one group: the highest sequence it has
/// reached, the change that reached it, and — when a history base carried
/// that position — the base.
///
/// `tip` is kept even while the position is anchored on a base. It is no
/// longer what the next change names, but it is still what the causal
/// summary records for the author, and a later base carries it on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthorChainState {
    pub(crate) watermark: AuthorSeq,
    pub(crate) tip: ChangeHash,
    pub(crate) anchored_on: Option<HistoryBase>,
}

/// The part of an author's state admission measures a change against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthorPosition {
    pub(crate) watermark: AuthorSeq,
    pub(crate) anchor: AuthorAnchor,
}

impl AuthorChainState {
    pub(crate) fn position(&self) -> AuthorPosition {
        AuthorPosition {
            watermark: self.watermark,
            anchor: match self.anchored_on {
                Some(base) => AuthorAnchor::Base(base),
                None => AuthorAnchor::ActiveTip(self.tip),
            },
        }
    }
}

pub(super) fn init_author_chain_schema(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        r#"
        -- One author's furthest position in one group, and the change that
        -- attained it. Unlike `changes`, this survives compaction: nothing
        -- deletes from it and nothing lowers a watermark, so an author's
        -- sequence continues across a history-base switch instead of
        -- restarting at whatever is left in retained history.
        --
        -- `tip_change_hash` is stored alongside the watermark because the
        -- number on its own cannot distinguish a change that continues this
        -- author's history from one that forks away from it at the same
        -- number. Every change names the change its author wrote before it,
        -- and matching that name against this tip is what decides it --
        -- by identity, never by DAG ancestry, which is a different relation
        -- and would refuse an ordinary local edit.
        --
        -- `anchor_base` is set when an installed history base carried this
        -- position: the base absorbed the tip, and the author's next change
        -- continues the base through its signed history epoch, naming no
        -- predecessor. Any forward move clears it.
        CREATE TABLE IF NOT EXISTS author_chain_state (
            group_id        TEXT NOT NULL,
            device_id       TEXT NOT NULL,
            watermark       INTEGER NOT NULL,
            tip_change_hash BLOB NOT NULL,
            anchor_base     BLOB,
            PRIMARY KEY (group_id, device_id)
        ) WITHOUT ROWID;
        "#,
    )?;
    Ok(())
}

/// This author's watermark and tip in this group, or `None` when it has
/// written nothing here yet.
pub(crate) fn author_chain_state(
    conn: &Connection,
    group_id: &str,
    device_id: &str,
) -> Result<Option<AuthorChainState>, SyncSqliteError> {
    let row: Option<(i64, Vec<u8>, Option<Vec<u8>>)> = conn
        .prepare_cached(
            "SELECT watermark, tip_change_hash, anchor_base FROM author_chain_state \
             WHERE group_id = ?1 AND device_id = ?2",
        )?
        .query_row(rusqlite::params![group_id, device_id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .optional()?;
    let Some((watermark, tip, anchor_base)) = row else {
        return Ok(None);
    };
    // A watermark outside the range the signed field can hold is not
    // something to round off or carry on from: the column copies a `u64`
    // that admission has already refused at 0, so anything else here means
    // the row was not written by this code path.
    if watermark < 1 {
        return Err(SyncSqliteError::CorruptState(format!(
            "author {device_id} in group {group_id} has a retained watermark of {watermark}, \
             which is not a position in any author chain"
        )));
    }
    let tip: [u8; 32] = tip.as_slice().try_into().map_err(|_| {
        SyncSqliteError::CorruptState(format!(
            "author {device_id} in group {group_id} has a retained tip of {} bytes, which is \
             not a change hash",
            tip.len()
        ))
    })?;
    let anchored_on = anchor_base
        .map(|base| {
            <[u8; 32]>::try_from(base.as_slice()).map(HistoryBase).map_err(|_| {
                SyncSqliteError::CorruptState(format!(
                    "author {device_id} in group {group_id} is anchored on a history base of {} \
                     bytes, which is not a history base",
                    base.len()
                ))
            })
        })
        .transpose()?;
    Ok(Some(AuthorChainState {
        watermark: AuthorSeq(watermark as u64),
        tip: ChangeHash(tip),
        anchored_on,
    }))
}

/// Every author's retained position in this group, as a history base
/// carries them.
///
/// All of them, not only the ones still holding a live head: an author
/// whose every write was later superseded appears nowhere in a frontier or
/// in a path-head set, and a receiver that learned nothing about it would
/// have no attested position to measure that author's next change against.
pub(crate) fn all_author_state(
    conn: &Connection,
    group_id: &str,
) -> Result<Vec<SnapshotAuthorState>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT device_id, watermark, tip_change_hash FROM author_chain_state \
         WHERE group_id = ?1 ORDER BY device_id",
    )?;
    let rows = stmt.query_map(rusqlite::params![group_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?, row.get::<_, Vec<u8>>(2)?))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (device_id, watermark, tip) = row?;
        if watermark < 1 {
            return Err(SyncSqliteError::CorruptState(format!(
                "author {device_id} in group {group_id} has a retained watermark of {watermark}, \
                 which is not a position in any author chain"
            )));
        }
        let tip: [u8; 32] = tip.as_slice().try_into().map_err(|_| {
            SyncSqliteError::CorruptState(format!(
                "author {device_id} in group {group_id} has a retained tip of {} bytes, which is \
                 not a change hash",
                tip.len()
            ))
        })?;
        out.push(SnapshotAuthorState {
            device_id,
            watermark: AuthorSeq(watermark as u64),
            tip_change_hash: ChangeHash(tip),
        });
    }
    Ok(out)
}

/// The only position this author's next change in this group may take: the
/// sequence it must carry, and the change it must name as its author's
/// predecessor — none, when the position was carried by the installed
/// history base.
///
/// Both together, never one without the other. Admission checks the pair,
/// so an emission that took the number from here and the link from anywhere
/// else would sign a change every peer refuses.
///
/// Read inside the emitting transaction, so the position this returns is
/// the position the change that follows it will actually be stored under.
///
/// Fails closed when the author has exhausted the sequence range: there is
/// no next position, and minting the last one again would put two changes
/// at one dot.
pub(crate) fn next_author_position(
    conn: &Connection,
    group_id: &str,
    device_id: &str,
) -> Result<(AuthorSeq, Option<ChangeHash>), SyncSqliteError> {
    Ok(match author_chain_state(conn, group_id, device_id)? {
        None => (AuthorSeq::FIRST, None),
        Some(state) => {
            let Some(next) = state.watermark.checked_next() else {
                return Err(SyncSqliteError::InvalidInput(format!(
                    "cannot emit local change for group {group_id}: author {device_id} has \
                     reached the highest sequence a change may carry ({}), so it has no next \
                     position; emitting one would reuse a position already taken",
                    state.watermark
                )));
            };
            match state.position().anchor {
                AuthorAnchor::ActiveTip(tip) => (next, Some(tip)),
                AuthorAnchor::Base(base) => {
                    // The change is signed on the group's current history,
                    // and only a change on the anchoring base may open it.
                    // A mismatch means the position was carried by a base
                    // this group no longer stands on, and every peer would
                    // refuse what this signed.
                    let current = crate::rebootstrap_store::current_history_epoch(conn, group_id)?;
                    if current != HistoryEpoch::Base(base) {
                        return Err(SyncSqliteError::CorruptState(format!(
                            "cannot emit local change for group {group_id}: author {device_id}'s \
                             position was carried by history base {}, but the group is on {current}",
                            base.to_hex()
                        )));
                    }
                    (next, None)
                }
            }
        }
    })
}

/// Moves this author's watermark and tip up to `seq`/`hash`, if that is
/// forward.
///
/// Called in the same transaction as the admission it describes, so the
/// state can never commit apart from the change it summarizes. The move is
/// one-way by construction: a sequence at or below the stored watermark
/// leaves the row exactly as it was, because a watermark that could step
/// back would let an author re-mint a position it has already used.
///
/// A forward move anchors the author on the change that made it, whatever
/// it was anchored on before.
pub(crate) fn advance_author_state(
    conn: &Connection,
    group_id: &str,
    device_id: &str,
    seq: AuthorSeq,
    hash: &ChangeHash,
) -> Result<(), SyncSqliteError> {
    conn.prepare_cached(
        "INSERT INTO author_chain_state (group_id, device_id, watermark, tip_change_hash) \
         VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT(group_id, device_id) DO UPDATE SET \
           watermark = excluded.watermark, \
           tip_change_hash = excluded.tip_change_hash, \
           anchor_base = NULL \
         WHERE excluded.watermark > author_chain_state.watermark",
    )?
    .execute(rusqlite::params![group_id, device_id, seq.get() as i64, &hash.0[..]])?;
    Ok(())
}

/// Anchors every author whose retained position is exactly the one `base`
/// carries on `base`, so its next change opens the epoch above the base.
///
/// Called as a base is put in place, after the positions it carries have
/// been restored. Only an exact match moves: an author this replica has
/// seen further than the base did still holds the change that took it
/// there, keeps that change as its anchor, and continues by naming it.
///
/// That continuation holds only on replicas that also hold the change. It
/// was written on the history the base replaced, so a replica that
/// installed the base fresh has the author at the base's position, refuses
/// that change as another history, and refuses whatever names it behind
/// it. Convergence needs the base to carry every position its authors
/// continue from.
pub(crate) fn anchor_carried_positions_on_base(
    conn: &Connection,
    group_id: &str,
    base: &HistoryBase,
    carried: &[SnapshotAuthorState],
) -> Result<(), SyncSqliteError> {
    let mut stmt = conn.prepare_cached(
        "UPDATE author_chain_state SET anchor_base = ?1 \
         WHERE group_id = ?2 AND device_id = ?3 AND watermark = ?4 AND tip_change_hash = ?5",
    )?;
    for author in carried {
        stmt.execute(rusqlite::params![
            &base.0[..],
            group_id,
            &author.device_id,
            author.watermark.get() as i64,
            &author.tip_change_hash.0[..],
        ])?;
    }
    Ok(())
}

/// What this author's chain says about `change`: admit it, hold it until
/// the predecessor it names arrives, or refuse it finally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AuthorChainVerdict {
    /// The change continues this author's chain here and may be stored.
    Admit,
    /// The change names a previous change of its own author that this
    /// replica does not hold. Nothing is decided yet: the named change may
    /// simply still be in flight, and once it is admitted this change's
    /// position becomes checkable. Held, exactly like a change with a
    /// missing DAG parent.
    AwaitAuthorPredecessor { named: ChangeHash },
    /// The chain refuses the change, finally, under its own rules.
    Refuse(AuthorChainRefusal),
    /// Refused finally because the predecessor the change names is itself
    /// permanently rejected here, so the position it claims to follow can
    /// never exist. This verdict is only as settled as that rejection:
    /// `decided_by` is the rule domain that rejected the predecessor, and
    /// the refusal is recorded under it so that when those rules move the
    /// predecessor and everything refused behind it are re-opened together.
    /// `rests_on` is that predecessor: the recorded refusal names it, so it
    /// also lapses whenever the predecessor's own verdict stops standing.
    RefuseBehindRejectedPredecessor {
        refusal: AuthorChainRefusal,
        decided_by: RejectionDomain,
        rests_on: ChangeHash,
    },
}

/// Decides whether this author's chain admits `change`, holds it, or
/// refuses it.
///
/// Two things must already be true when this is called, and both belong to
/// the caller because both are about the DAG rather than about the author:
///
/// * the change is not one this replica already holds. A change already
///   retained necessarily sits at or below its author's watermark, so
///   validating a re-delivery here would refuse ordinary repetition as a
///   forked history. Duplicates are decided first, always.
/// * every DAG parent is present. Only then is there a stored change to
///   append, and only then are the parent-shaped checks the caller runs
///   meaningful.
///
/// Every DAG parent being present says nothing at all about whether this
/// author's own previous change has arrived, and that is the reason this
/// function has a third answer rather than two. Author ordering is not DAG
/// causality: a change's parents are the basis its author actually edited,
/// so an author's previous change — written moments earlier, to some
/// unrelated path — is routinely not among them. A perfectly ordinary
/// chain therefore arrives out of order with complete ancestry and a
/// sequence one past what this replica has, and refusing that would refuse
/// a valid change permanently for being early. It is held instead, against
/// the name it carries, in the one holding buffer that already exists for
/// named-but-absent changes.
///
/// What is refused is a gap that cannot close: a change past the first that
/// names no predecessor at all, or one whose named predecessor is already
/// here and so already has a position of its own that contradicts the
/// claimed sequence.
///
/// An `Err` is a malformed change or a database problem, not a verdict
/// about the author.
pub(crate) fn check_admission(
    conn: &Connection,
    change: &Change,
) -> Result<AuthorChainVerdict, SyncSqliteError> {
    let group_id = change.group_id.as_str();
    let device_id = change.device_id.as_str();
    let seq = change.author_seq;
    // Zero is not a position in any chain, so there is no author state that
    // could accept or reject it. This is a property of the change's own
    // signed bytes, checkable with no history at all, and it is an error
    // rather than a refusal for that reason: a refusal describes a conflict
    // with this replica's history, and there is no history involved here.
    if seq.get() < 1 {
        return Err(SyncSqliteError::InvalidInput(format!(
            "change {} carries author sequence 0, which is not a position in any author chain",
            change.compute_hash().to_hex()
        )));
    }
    let hash = change.compute_hash();

    // The dot itself, first: a different change already standing at this
    // author's exact position is equivocation, and saying so is more
    // informative than anything the watermark comparison below could
    // conclude about the same change. The unique index over
    // `(group_id, device_id, author_seq)` will refuse the write regardless;
    // this turns that write failure into a verdict the caller can report.
    if let Some(held) = change_at_dot(conn, group_id, device_id, seq)? {
        if held != hash {
            return Ok(AuthorChainVerdict::Refuse(AuthorChainRefusal::AuthorEquivocation {
                seq,
                held,
            }));
        }
    }

    let Some(state) = author_chain_state(conn, group_id, device_id)? else {
        // An author with no position here may only take the first one. A
        // device that has genuinely never written in this group starts at
        // 1; a device claiming anything else is claiming a history this
        // replica has no record of, which is not something to take on
        // faith.
        //
        // An installed history base is not an exception to this. It is
        // true that a base's frontier alone does not mention an author
        // whose every write was later superseded — but the answer to that
        // is for the base to carry each retained author's position, which
        // it does, and for the install to restore those positions before
        // any change is measured against them, which it does. Taking an
        // unknown author's own first observed change as its position
        // instead would let whichever change arrived first name any
        // sequence and pin it as the watermark, and everything below a
        // watermark is treated as history already absorbed. That is not a
        // weaker check; it is the absence of one.
        if seq == AuthorSeq::FIRST {
            // A first change has nothing of its own to follow. One that
            // names a predecessor anyway is describing a history this
            // replica was never given — refused rather than admitted with
            // the claim ignored, because ignoring it would let the same
            // bytes mean one thing here and another on a replica that does
            // hold that author's earlier position.
            if let Some(named) = change.author_prev {
                return Ok(AuthorChainVerdict::Refuse(
                    AuthorChainRefusal::AuthorPrevWithoutPredecessor { named },
                ));
            }
            return Ok(AuthorChainVerdict::Admit);
        }
        // An author this replica has no position for, claiming a position
        // past the first. If it names the change it followed, that name is
        // one this replica demonstrably does not hold — an author with any
        // admitted change here would have a row — so this is the ordinary
        // out-of-order case and it waits, without the sequence being taken
        // on faith for anything: the position is measured against the
        // restored state once the named change lands, and refused then if
        // it still does not fit.
        //
        // (An installed history base does not make this an author the
        // replica "has no record of" by accident: the base carries each
        // retained author's position and the install restores it before any
        // change is measured, so a missing row really does mean nothing of
        // this author's is known here.)
        //
        // An author with no row is anchored, implicitly, on the history the
        // group is on at watermark zero. The caller has already refused a
        // change on any other history, so the epoch half of that anchor
        // needs no second check here.
        return hold_or_refuse_gap(conn, change, AuthorSeq::FIRST);
    };
    let position = state.position();

    let Some(expected) = position.watermark.checked_next() else {
        // This author has used every position a change may carry. There is
        // no next one to admit into, and reusing the last would put two
        // changes at one dot. Refused, in the same shape as every other
        // verdict here.
        return Ok(AuthorChainVerdict::Refuse(AuthorChainRefusal::AuthorSequenceExhausted {
            watermark: position.watermark,
        }));
    };
    if seq > expected {
        return hold_or_refuse_gap(conn, change, expected);
    }
    if seq < expected {
        // At or below the watermark, and not a change this replica holds
        // (the caller settled that) and not colliding with one it holds (the
        // dot lookup above settled that). The author's history forked
        // somewhere this replica has already passed. Deliberately NOT called
        // equivocation: the colliding change may have been compacted away,
        // or may never have existed — the watermark and tip alone cannot
        // tell. Refused either way, and never merged.
        return Ok(AuthorChainVerdict::Refuse(AuthorChainRefusal::ForkedAuthorHistory {
            watermark: position.watermark,
            seq,
        }));
    }

    // The right sequence is necessary and not sufficient. Arithmetic on a
    // counter cannot tell a change that continues this author's history
    // from one that abandons its latest change and forks off something
    // older at the same number; the name the change carries can, and it can
    // do it with no ancestry query at all.
    //
    // Identity, not ancestry, and the difference is the whole point.
    // `change.parents` is the causal basis this author observed and is left
    // entirely alone here — it decides what the change means for a path,
    // and nothing about the author chain is allowed to bend it. An ordinary
    // local edit's parents are older than its author's own latest write,
    // and that is correct, not a fork.
    let continues = match position.anchor {
        AuthorAnchor::ActiveTip(tip) => change.author_prev == Some(tip),
        // The position was carried by a base, which absorbed the change
        // that attained it. The first change above the base continues the
        // base itself, and the link to the base is the signed history
        // epoch: `author_prev` can only name a change, so it names none.
        AuthorAnchor::Base(base) => {
            if change.history_epoch != HistoryEpoch::Base(base) {
                return Ok(AuthorChainVerdict::Refuse(
                    AuthorChainRefusal::AuthorAnchoredOnAnotherBase {
                        seq,
                        anchor: base,
                        incoming: change.history_epoch,
                    },
                ));
            }
            change.author_prev.is_none()
        }
    };
    if continues {
        return Ok(AuthorChainVerdict::Admit);
    }
    // Not held, even though the name is one this replica may not hold: at
    // this exact sequence the author's predecessor is whatever attained the
    // watermark — the tip, or the base that absorbed it. Naming anything
    // else here is a fork of the author's own chain, and no later delivery
    // turns it back into a continuation.
    Ok(AuthorChainVerdict::Refuse(AuthorChainRefusal::AuthorPrevMismatch {
        seq,
        anchor: position.anchor,
        named: change.author_prev,
    }))
}

/// The verdict for a change whose sequence is past the next position this
/// replica can fill: hold it if the predecessor it names is simply not here
/// yet, refuse it if the gap is already decided.
///
/// The distinction is exactly whether a later delivery could still make the
/// change fit.
///
/// * It names nothing. A change past its author's first position that
///   declines to name what it followed has no name for anything to satisfy,
///   so the gap is permanent.
/// * It names a change this replica already holds. Then that change's own
///   position is known and settled, and it is not the position this change
///   claims to follow — because if it were, this replica's watermark for
///   the author would already be at least that position and the sequence
///   would not be past `expected`. Permanent, and an accusation nothing
///   further can retract. The change that attained the author's recorded
///   position counts as held even once an installed base has absorbed it:
///   the watermark is its position.
/// * It names a change this replica has permanently refused. The refusal is
///   a property of that change's own signed bytes, so no delivery of it can
///   ever put it into retained history and the position this change claims
///   to follow is one that will never exist here. Permanent, for the same
///   reason as the case above and not for a different one — and refusing it
///   is what stops the same bytes from being buffered against that dead
///   name on every redelivery, forever. The refusal is attributed to the
///   rule domain that rejected the named change, not to the author chain:
///   it stands exactly as long as that rejection does.
/// * It names a change this replica does not hold and has not decided.
///   Ordinary out-of-order delivery: the author's previous change is not
///   required to be an ancestor of this one, so it can perfectly well still
///   be in flight. Held against that name, and re-decided in full when it
///   lands.
fn hold_or_refuse_gap(
    conn: &Connection,
    change: &Change,
    expected: AuthorSeq,
) -> Result<AuthorChainVerdict, SyncSqliteError> {
    let gap = AuthorChainRefusal::AuthorSequenceGap { expected, found: change.author_seq };
    let Some(named) = change.author_prev else {
        return Ok(AuthorChainVerdict::Refuse(gap));
    };
    let present = crate::dag_store::retained_history_integrity::has_change_or_pruned(
        conn,
        change.group_id.as_str(),
        &named,
    )?;
    if present {
        return Ok(AuthorChainVerdict::Refuse(gap));
    }
    // The change that attained the author's recorded position, absorbed by
    // an installed base: no longer held, but its position is still known
    // here -- it is the watermark -- so the case is the one above.
    let names_recorded_tip =
        author_chain_state(conn, change.group_id.as_str(), change.device_id.as_str())?
            .is_some_and(|state| state.tip == named);
    if names_recorded_tip {
        return Ok(AuthorChainVerdict::Refuse(gap));
    }
    if let Some(decided_by) = crate::dag_store::current_rejection_domain(conn, &named)? {
        return Ok(AuthorChainVerdict::RefuseBehindRejectedPredecessor {
            refusal: gap,
            decided_by,
            rests_on: named,
        });
    }
    Ok(AuthorChainVerdict::AwaitAuthorPredecessor { named })
}

/// The retained change standing at this exact dot, if any.
fn change_at_dot(
    conn: &Connection,
    group_id: &str,
    device_id: &str,
    seq: AuthorSeq,
) -> Result<Option<ChangeHash>, SyncSqliteError> {
    let held: Option<Vec<u8>> = conn
        .prepare_cached(
            "SELECT change_hash FROM changes \
             WHERE group_id = ?1 AND device_id = ?2 AND author_seq = ?3",
        )?
        .query_row(rusqlite::params![group_id, device_id, seq.get() as i64], |row| row.get(0))
        .optional()?;
    let Some(held) = held else { return Ok(None) };
    let held: [u8; 32] = held.as_slice().try_into().map_err(|_| {
        SyncSqliteError::CorruptState(format!(
            "author {device_id} in group {group_id} has a retained change at sequence {seq} whose \
             hash is {} bytes",
            held.len()
        ))
    })?;
    Ok(Some(ChangeHash(held)))
}

/// True when `author_chain_state` already has nothing this rebuild could
/// change.
///
/// The rebuild only ever raises a watermark, never lowers one (see the
/// function this gates), so the only state it could still touch is one
/// where some author's retained history reaches a sequence past what is
/// currently recorded for it — a missing row counts as a recorded watermark
/// of 0. That is exactly what this checks, in one read-only query, instead
/// of the write this function exists to avoid on every ordinary open: a
/// crash between an admission and its `author_chain_state` write is rare,
/// so most opens have nothing to repair.
fn state_already_reflects_retained_history(conn: &Connection) -> Result<bool, SyncSqliteError> {
    let stale: i64 = conn.query_row(
        "SELECT COUNT(*) FROM ( \
           SELECT group_id, device_id, MAX(author_seq) AS max_seq \
           FROM changes GROUP BY group_id, device_id \
         ) retained \
         LEFT JOIN author_chain_state existing \
           ON existing.group_id = retained.group_id \
           AND existing.device_id = retained.device_id \
         WHERE retained.max_seq > COALESCE(existing.watermark, 0)",
        [],
        |row| row.get(0),
    )?;
    Ok(stale == 0)
}

/// Startup self-heal: restores any author position that retained history
/// still shows but `author_chain_state` has lost or fallen behind.
///
/// Only ever advances. Retained history is a suffix of what an author
/// wrote, so a group that has been compacted holds a watermark this pass
/// cannot see, and lowering the stored one to match what is left would
/// restart the sequence — the exact failure the table exists to prevent.
/// It therefore fills in a missing row and raises a stale one, and leaves
/// every state already ahead of retained history alone.
pub(super) fn rebuild_author_chain_state(conn: &Connection) -> Result<(), SyncSqliteError> {
    if state_already_reflects_retained_history(conn)? {
        return Ok(());
    }
    let highest: Vec<(String, String, i64, Vec<u8>)> = {
        // `change_hash` is a bare column beside `MAX(author_seq)`: SQLite
        // defines that to be the value from the row the maximum came from,
        // which is exactly the tip wanted here. The row is unambiguous
        // because `changes_by_author` is unique, so one author has at most
        // one change at a sequence.
        let mut stmt = conn.prepare(
            "SELECT group_id, device_id, MAX(author_seq), change_hash \
             FROM changes GROUP BY group_id, device_id",
        )?;
        let rows =
            stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    for (group_id, device_id, seq, hash) in highest {
        if seq < 1 {
            return Err(SyncSqliteError::CorruptState(format!(
                "author {device_id} in group {group_id} has a retained change stamped with \
                 author sequence {seq}, which is not a position in any author chain"
            )));
        }
        let hash: [u8; 32] = hash.as_slice().try_into().map_err(|_| {
            SyncSqliteError::CorruptState(format!(
                "author {device_id} in group {group_id} has a retained change whose hash is {} \
                 bytes",
                hash.len()
            ))
        })?;
        advance_author_state(
            conn,
            &group_id,
            &device_id,
            AuthorSeq(seq as u64),
            &ChangeHash(hash),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dag_store::init_dag_schema;
    use crate::dag_store::retained_history_integrity::append_change;
    use ed25519_dalek::SigningKey;
    use yadorilink_replica_domain::change::{Change, Op};
    use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId, SyncPath};

    const GROUP: &str = "author-state-group";

    fn conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        init_dag_schema(&conn).unwrap();
        conn
    }

    fn key(device: u8) -> SigningKey {
        SigningKey::from_bytes(&[device; 32])
    }

    /// A `Delete`-only change, so appending it needs no file version and no
    /// block store: the author's position is the only thing under test.
    ///
    /// `prev` and `parents` are separate arguments on purpose, because they
    /// are separate relations. `prev` is the change this author wrote just
    /// before this one — author ordering. `parents` is the causal basis
    /// this change was written on — what it means for a path. A real local
    /// edit routinely has a `prev` that is not among its `parents`, and
    /// these tests build that shape directly.
    fn change(
        device: u8,
        seq: u64,
        group: &str,
        prev: Option<&Change>,
        parents: &[&Change],
        path: &str,
    ) -> Change {
        let mut parent_hashes: Vec<ChangeHash> =
            parents.iter().map(|parent| parent.compute_hash()).collect();
        parent_hashes.sort();
        let max_parent_lamport = parents.iter().map(|p| p.lamport).max().unwrap_or(0);
        Change::create_signed(
            parent_hashes,
            max_parent_lamport,
            DeviceId(format!("device-{device}")),
            AuthorSeq(seq),
            prev.map(|prev| prev.compute_hash()),
            FolderGroupId(group.to_owned()),
            HistoryEpoch::Genesis,
            vec![Op::Delete { path: SyncPath(path.to_owned()) }],
            &key(device),
        )
    }

    /// A well-formed standing-in predecessor for a test that needs a
    /// change past sequence 1 but does not care what came before it.
    fn prev_stub(device: u8, group: &str) -> Change {
        change(device, 1, group, None, &[], "stub")
    }

    fn append(conn: &Connection, change: &Change) -> bool {
        append_change(conn, change, 0).unwrap()
    }

    fn state(conn: &Connection, device: u8, group: &str) -> Option<AuthorChainState> {
        author_chain_state(conn, group, &format!("device-{device}")).unwrap()
    }

    #[test]
    fn an_author_with_no_history_here_has_no_state_and_starts_at_one() {
        let conn = conn();
        assert_eq!(state(&conn, 1, GROUP), None);
        assert_eq!(
            next_author_position(&conn, GROUP, "device-1").unwrap(),
            (AuthorSeq::FIRST, None),
            "a first change takes position one and names nothing before it"
        );
    }

    #[test]
    fn the_state_advances_with_the_change_that_advances_it() {
        let conn = conn();
        let first = change(1, 1, GROUP, None, &[], "a");
        let second = change(1, 2, GROUP, Some(&first), &[&first], "b");
        assert!(append(&conn, &first));
        assert_eq!(
            state(&conn, 1, GROUP),
            Some(AuthorChainState {
                watermark: AuthorSeq(1),
                tip: first.compute_hash(),
                anchored_on: None
            })
        );
        assert!(append(&conn, &second));
        assert_eq!(
            state(&conn, 1, GROUP),
            Some(AuthorChainState {
                watermark: AuthorSeq(2),
                tip: second.compute_hash(),
                anchored_on: None
            })
        );
        assert_eq!(
            next_author_position(&conn, GROUP, "device-1").unwrap(),
            (AuthorSeq(3), Some(second.compute_hash())),
            "the next position names the change that took the one before it"
        );
    }

    /// A change this replica already holds must not move its author on. The
    /// same change delivered twice is one write, and a watermark that
    /// counted deliveries rather than changes would run ahead of the history
    /// it is supposed to summarize.
    #[test]
    fn a_duplicate_delivery_does_not_move_the_author_state() {
        let conn = conn();
        let first = change(1, 1, GROUP, None, &[], "a");
        assert!(append(&conn, &first));
        let before = state(&conn, 1, GROUP);
        assert!(!append(&conn, &first), "a change already retained is not appended again");
        assert_eq!(state(&conn, 1, GROUP), before);
    }

    #[test]
    fn each_author_and_each_group_keeps_its_own_position() {
        let conn = conn();
        let mine = change(1, 1, GROUP, None, &[], "a");
        let theirs = change(2, 1, GROUP, None, &[], "b");
        let elsewhere = change(1, 1, "other-group", None, &[], "c");
        assert!(append(&conn, &mine));
        assert!(append(&conn, &theirs));
        assert!(append(&conn, &elsewhere));
        assert_eq!(state(&conn, 1, GROUP).unwrap().tip, mine.compute_hash());
        assert_eq!(state(&conn, 2, GROUP).unwrap().tip, theirs.compute_hash());
        assert_eq!(state(&conn, 1, "other-group").unwrap().tip, elsewhere.compute_hash());
    }

    /// The move is one-way. A watermark that could step back would hand an
    /// author a position it has already used, which is the one thing the dot
    /// exists to make impossible.
    #[test]
    fn the_watermark_never_steps_back() {
        let conn = conn();
        let third = change(1, 3, GROUP, Some(&prev_stub(1, GROUP)), &[], "a");
        let tip = third.compute_hash();
        advance_author_state(&conn, GROUP, "device-1", AuthorSeq(3), &tip).unwrap();
        advance_author_state(&conn, GROUP, "device-1", AuthorSeq(2), &ChangeHash([9u8; 32]))
            .unwrap();
        assert_eq!(
            state(&conn, 1, GROUP),
            Some(AuthorChainState { watermark: AuthorSeq(3), tip, anchored_on: None })
        );
        advance_author_state(&conn, GROUP, "device-1", AuthorSeq(3), &ChangeHash([9u8; 32]))
            .unwrap();
        assert_eq!(
            state(&conn, 1, GROUP).unwrap().tip,
            tip,
            "an equal sequence is not forward either, so the tip stays put"
        );
    }

    /// The store's own last line against equivocation: whatever admission
    /// decides, two different changes cannot both come to occupy one dot.
    #[test]
    fn two_different_changes_cannot_both_be_stored_at_one_dot() {
        let conn = conn();
        let first = change(1, 1, GROUP, None, &[], "a");
        let rival = change(1, 1, GROUP, None, &[], "b");
        assert_ne!(first.compute_hash(), rival.compute_hash());
        assert!(append(&conn, &first));
        let refused = append_change(&conn, &rival, 0);
        assert!(refused.is_err(), "a second change at one dot must not be stored: {refused:?}");
    }

    #[test]
    fn the_startup_rebuild_restores_a_state_that_was_lost() {
        let conn = conn();
        let first = change(1, 1, GROUP, None, &[], "a");
        let second = change(1, 2, GROUP, Some(&first), &[&first], "b");
        assert!(append(&conn, &first));
        assert!(append(&conn, &second));
        conn.execute("DELETE FROM author_chain_state", []).unwrap();
        assert_eq!(state(&conn, 1, GROUP), None);
        rebuild_author_chain_state(&conn).unwrap();
        assert_eq!(
            state(&conn, 1, GROUP),
            Some(AuthorChainState {
                watermark: AuthorSeq(2),
                tip: second.compute_hash(),
                anchored_on: None
            }),
            "the rebuild takes the author's furthest retained change, not its first"
        );
    }

    /// Retained history is only a suffix of what an author wrote once
    /// compaction has run, so the rebuild must never take it as the whole
    /// story. Lowering the watermark to match what is left would restart the
    /// author's sequence at the compaction boundary.
    #[test]
    fn the_startup_rebuild_does_not_lower_a_state_past_compacted_history() {
        let conn = conn();
        let surviving = change(1, 7, GROUP, Some(&prev_stub(1, GROUP)), &[], "a");
        assert!(append(&conn, &surviving));
        let ahead = ChangeHash([5u8; 32]);
        advance_author_state(&conn, GROUP, "device-1", AuthorSeq(9), &ahead).unwrap();
        rebuild_author_chain_state(&conn).unwrap();
        assert_eq!(
            state(&conn, 1, GROUP),
            Some(AuthorChainState { watermark: AuthorSeq(9), tip: ahead, anchored_on: None })
        );
    }

    /// The common case: every author's recorded watermark already matches
    /// what retained history shows, because ordinary admission just wrote it
    /// in the same transaction as the change. The rebuild has nothing left
    /// to raise, so it must not touch `author_chain_state` at all —
    /// `Connection::changes()` reports the row count of the most recently
    /// completed INSERT/UPDATE/DELETE, so if the rebuild issued no write of
    /// its own it stays exactly what it was before the call.
    #[test]
    fn the_rebuild_performs_no_write_when_the_state_is_already_current() {
        let conn = conn();
        let first = change(1, 1, GROUP, None, &[], "a");
        let second = change(1, 2, GROUP, Some(&first), &[&first], "b");
        assert!(append(&conn, &first));
        assert!(append(&conn, &second));

        let changes_before = conn.changes();
        rebuild_author_chain_state(&conn).unwrap();
        assert_eq!(
            conn.changes(),
            changes_before,
            "a rebuild over an already-current state must not write to author_chain_state"
        );
        assert_eq!(
            state(&conn, 1, GROUP),
            Some(AuthorChainState {
                watermark: AuthorSeq(2),
                tip: second.compute_hash(),
                anchored_on: None
            }),
            "the already-correct state must be left exactly as it was"
        );
    }

    /// The point of keeping the state in its own table. Retained history
    /// shrinks; an author's position does not.
    #[test]
    fn the_next_sequence_follows_the_state_and_not_retained_history() {
        let conn = conn();
        let first = change(1, 1, GROUP, None, &[], "a");
        assert!(append(&conn, &first));
        conn.execute("DELETE FROM changes WHERE group_id = ?1", [GROUP]).unwrap();
        assert_eq!(
            next_author_position(&conn, GROUP, "device-1").unwrap(),
            (AuthorSeq(2), Some(first.compute_hash())),
            "an author's next position does not restart because its history was compacted \
             away, and it still names the change it followed even though that change is gone"
        );
    }

    /// The `check_admission` caller is responsible for the two preconditions
    /// (not a duplicate, parents all present), so these exercise the rule
    /// itself rather than the funnel — `tests/dag_author_chain_red.rs` pins
    /// the funnel end to end.
    fn verdict(conn: &Connection, change: &Change) -> AuthorChainVerdict {
        check_admission(conn, change).unwrap()
    }

    /// The case the integration suite cannot easily build: the change that
    /// occupied this dot has been compacted away, so nothing is left to
    /// convict the newcomer of colliding with. The watermark still says the
    /// author passed this position, which is enough to refuse and not
    /// enough to accuse — the Lean counterexample for reading equivocation
    /// out of `(watermark, tip)` alone.
    #[test]
    fn a_change_below_the_watermark_whose_rival_was_compacted_is_a_fork_not_equivocation() {
        let conn = conn();
        let first = change(1, 1, GROUP, None, &[], "a");
        let second = change(1, 2, GROUP, Some(&first), &[&first], "b");
        assert!(append(&conn, &first));
        assert!(append(&conn, &second));
        // Compaction leaves the state behind and takes the rows.
        conn.execute("DELETE FROM changes WHERE change_hash = ?1", [&first.compute_hash().0[..]])
            .unwrap();

        let rival = change(1, 1, GROUP, None, &[], "rival");
        assert!(matches!(
            verdict(&conn, &rival),
            AuthorChainVerdict::Refuse(AuthorChainRefusal::ForkedAuthorHistory {
                watermark: AuthorSeq(2),
                seq: AuthorSeq(1)
            })
        ));
    }

    /// A device this replica has never seen write here may take the first
    /// position and only the first. Claiming a later one asserts a history
    /// this replica has no record of, and the watermark it would install
    /// would then name changes that were never received.
    #[test]
    fn an_author_with_no_state_may_only_claim_the_first_position() {
        let conn = conn();
        let first = change(1, 1, GROUP, None, &[], "a");
        assert_eq!(verdict(&conn, &first), AuthorChainVerdict::Admit);

        // Naming nothing while claiming position four: no delivery could
        // supply the predecessor it declined to name, so this is decided
        // now.
        let jumped = change(2, 4, GROUP, None, &[], "b");
        assert!(matches!(
            verdict(&conn, &jumped),
            AuthorChainVerdict::Refuse(AuthorChainRefusal::AuthorSequenceGap {
                expected: AuthorSeq::FIRST,
                found: AuthorSeq(4)
            })
        ));
    }

    /// The rule the author chain actually enforces: the change names its
    /// author's tip. Both ends are worth stating together — a continuation
    /// that reaches its author's tip only through another device's change
    /// still admits, because it names the tip, and a change at the right
    /// sequence that names an earlier change of its own does not.
    #[test]
    fn a_change_must_name_its_authors_tip_and_only_its_authors_tip() {
        let conn = conn();
        let a1 = change(1, 1, GROUP, None, &[], "a1");
        assert!(append(&conn, &a1));
        let a2 = change(1, 2, GROUP, Some(&a1), &[&a1], "a2");
        assert!(append(&conn, &a2));
        let b1 = change(2, 1, GROUP, None, &[&a2], "b1");
        assert!(append(&conn, &b1));

        // Parented on another author's change, naming its own tip.
        let continuing = change(1, 3, GROUP, Some(&a2), &[&b1], "a3");
        assert_eq!(verdict(&conn, &continuing), AuthorChainVerdict::Admit);

        // The right sequence, naming A:1 and abandoning A:2.
        let forking = change(1, 3, GROUP, Some(&a1), &[&a1], "a3-fork");
        assert!(matches!(
            verdict(&conn, &forking),
            AuthorChainVerdict::Refuse(AuthorChainRefusal::AuthorPrevMismatch {
                seq: AuthorSeq(3),
                named: Some(_),
                ..
            })
        ));

        // The right sequence, naming nothing at all.
        let orphaned_link = change(1, 3, GROUP, None, &[&b1], "a3-none");
        assert!(matches!(
            verdict(&conn, &orphaned_link),
            AuthorChainVerdict::Refuse(AuthorChainRefusal::AuthorPrevMismatch {
                seq: AuthorSeq(3),
                named: None,
                ..
            })
        ));
    }

    /// The shape the separation exists for, and the one an ancestry rule
    /// refused: an ordinary local edit.
    ///
    /// A1 places a path. The same device then writes an unrelated path,
    /// producing A2 — now this author's tip. Then it edits the first path,
    /// whose bytes still come from A1, so the edit is parented on A1 and
    /// NOT on A2. Claiming A2 as an ancestor would assert the user saw and
    /// overwrote the unrelated write, which they never did. The edit names
    /// A2 as its author's previous change, which is simply true, and
    /// admission takes it.
    #[test]
    fn a_local_edit_parented_on_an_older_basis_than_its_authors_tip_admits() {
        let conn = conn();
        let a1 = change(1, 1, GROUP, None, &[], "doc.txt");
        assert!(append(&conn, &a1));
        let a2 = change(1, 2, GROUP, Some(&a1), &[&a1], "other.txt");
        assert!(append(&conn, &a2));

        let local_edit = change(1, 3, GROUP, Some(&a2), &[&a1], "doc.txt");
        assert!(
            !local_edit.parents.contains(&a2.compute_hash()),
            "the edit must not claim its author's tip as a causal parent"
        );
        assert_eq!(
            verdict(&conn, &local_edit),
            AuthorChainVerdict::Admit,
            "an edit onto the basis its bytes came from is ordinary, not a fork"
        );
    }

    /// An author this replica has no position for may take the first
    /// position and nothing before it. Naming a predecessor is claiming a
    /// history that was never delivered here.
    #[test]
    fn a_first_change_that_names_a_predecessor_is_refused() {
        let conn = conn();
        let stub = prev_stub(3, GROUP);
        let first = change(3, 1, GROUP, Some(&stub), &[], "a");
        assert!(matches!(
            verdict(&conn, &first),
            AuthorChainVerdict::Refuse(AuthorChainRefusal::AuthorPrevWithoutPredecessor { .. })
        ));
    }

    /// Fail-closed at the end of the range. There is no position after the
    /// last one, and handing back the last one again would put two changes
    /// at one dot.
    #[test]
    fn an_exhausted_author_has_no_next_position_and_is_refused_rather_than_reused() {
        let conn = conn();
        let tip = ChangeHash([4u8; 32]);
        advance_author_state(&conn, GROUP, "device-1", AuthorSeq::MAX, &tip).unwrap();

        assert!(
            next_author_position(&conn, GROUP, "device-1").is_err(),
            "emission must refuse rather than mint a position already taken"
        );

        let stub = prev_stub(1, "unrelated-group");
        let at_the_ceiling =
            change(1, AuthorSeq::MAX.get(), GROUP, Some(&stub), &[], "past-the-end");
        assert!(matches!(
            verdict(&conn, &at_the_ceiling),
            AuthorChainVerdict::Refuse(AuthorChainRefusal::AuthorSequenceExhausted {
                watermark: AuthorSeq::MAX
            })
        ));
    }

    /// The re-decided half of the gap rule, at the level of the rule
    /// itself. A sequence past the next position is not on its own a
    /// broken chain: the author's previous change is not required to be an
    /// ancestor of this one, so it can still be in flight while this one is
    /// here. Held against the name it carries.
    #[test]
    fn a_gap_naming_a_predecessor_this_replica_does_not_hold_is_held() {
        let conn = conn();
        let a1 = change(1, 1, GROUP, None, &[], "a1");
        assert!(append(&conn, &a1));
        // A:2 is never appended. A:3 is parented on A:1 — the basis its
        // bytes came from — and names A:2, which is exactly what an
        // ordinary edit looks like when delivery reorders it.
        let a2 = change(1, 2, GROUP, Some(&a1), &[&a1], "a2");
        let a3 = change(1, 3, GROUP, Some(&a2), &[&a1], "a3");
        assert_eq!(
            verdict(&conn, &a3),
            AuthorChainVerdict::AwaitAuthorPredecessor { named: a2.compute_hash() }
        );
    }

    /// The other half: the same arithmetic gap, but the named predecessor
    /// is already here. Its position is known and it is not the position
    /// this change claims to follow, so nothing further could reconcile
    /// them.
    #[test]
    fn a_gap_naming_a_predecessor_this_replica_already_holds_is_refused() {
        let conn = conn();
        let a1 = change(1, 1, GROUP, None, &[], "a1");
        assert!(append(&conn, &a1));
        let skipping = change(1, 3, GROUP, Some(&a1), &[&a1], "skipping");
        assert!(matches!(
            verdict(&conn, &skipping),
            AuthorChainVerdict::Refuse(AuthorChainRefusal::AuthorSequenceGap {
                expected: AuthorSeq(2),
                found: AuthorSeq(3)
            })
        ));
    }

    /// A predecessor that was admitted and later compacted away still
    /// counts as one this replica held: waiting for it would wait for
    /// something that is never coming back, and its position is settled
    /// regardless.
    #[test]
    fn a_gap_naming_a_compacted_predecessor_is_refused_rather_than_held_forever() {
        let conn = conn();
        let a1 = change(1, 1, GROUP, None, &[], "a1");
        assert!(append(&conn, &a1));
        let skipping = change(1, 3, GROUP, Some(&a1), &[&a1], "skipping");
        conn.execute(
            "INSERT INTO pruned_changes \
             (group_id, change_hash, checkpoint_hash, lamport, encoding_version) \
             VALUES (?1, ?2, ?3, 0, 1)",
            rusqlite::params![GROUP, &a1.compute_hash().0[..], &[0x7fu8; 32][..]],
        )
        .unwrap();
        conn.execute("DELETE FROM changes WHERE change_hash = ?1", [&a1.compute_hash().0[..]])
            .unwrap();
        assert!(matches!(
            verdict(&conn, &skipping),
            AuthorChainVerdict::Refuse(AuthorChainRefusal::AuthorSequenceGap { .. })
        ));
    }

    /// An unknown author arriving mid-chain waits too, and waiting records
    /// nothing: the sequence it claims is never taken on faith, it is
    /// measured once the change it names establishes a position.
    #[test]
    fn an_unknown_author_naming_an_absent_predecessor_is_held() {
        let conn = conn();
        let stub = prev_stub(2, GROUP);
        let jumped = change(2, 4, GROUP, Some(&stub), &[], "b");
        assert_eq!(
            verdict(&conn, &jumped),
            AuthorChainVerdict::AwaitAuthorPredecessor { named: stub.compute_hash() }
        );
        assert_eq!(state(&conn, 2, GROUP), None, "a held change writes no state");
    }

    /// Not a verdict about the author: zero is not a position, so there is
    /// no history for it to conflict with and nothing to report about the
    /// chain. It is refused as a malformed change instead.
    #[test]
    fn sequence_zero_is_an_error_rather_than_a_chain_verdict() {
        let conn = conn();
        let zeroed = change(1, 0, GROUP, None, &[], "a");
        assert!(check_admission(&conn, &zeroed).is_err());
    }

    fn carried(device: u8, watermark: u64, tip: ChangeHash) -> SnapshotAuthorState {
        SnapshotAuthorState {
            device_id: format!("device-{device}"),
            watermark: AuthorSeq(watermark),
            tip_change_hash: tip,
        }
    }

    /// Only a position exactly as the base carries it is anchored on the
    /// base. An author this replica has seen further keeps its own tip, and
    /// the next forward move re-anchors a base-anchored author on the change
    /// that made it.
    #[test]
    fn a_base_anchors_only_the_positions_it_carries_and_a_forward_move_releases_them() {
        let conn = conn();
        let base = HistoryBase([3u8; 32]);
        let carried_tip = ChangeHash([4u8; 32]);
        let local_tip = ChangeHash([5u8; 32]);
        advance_author_state(&conn, GROUP, "device-1", AuthorSeq(4), &carried_tip).unwrap();
        advance_author_state(&conn, GROUP, "device-2", AuthorSeq(9), &local_tip).unwrap();

        anchor_carried_positions_on_base(
            &conn,
            GROUP,
            &base,
            &[carried(1, 4, carried_tip), carried(2, 8, ChangeHash([6u8; 32]))],
        )
        .unwrap();
        assert_eq!(
            state(&conn, 1, GROUP).unwrap().position(),
            AuthorPosition { watermark: AuthorSeq(4), anchor: AuthorAnchor::Base(base) }
        );
        assert_eq!(
            state(&conn, 2, GROUP).unwrap().position(),
            AuthorPosition { watermark: AuthorSeq(9), anchor: AuthorAnchor::ActiveTip(local_tip) },
            "a position ahead of the base's keeps the change that attained it"
        );

        let next = ChangeHash([7u8; 32]);
        advance_author_state(&conn, GROUP, "device-1", AuthorSeq(5), &next).unwrap();
        assert_eq!(
            state(&conn, 1, GROUP).unwrap().position(),
            AuthorPosition { watermark: AuthorSeq(5), anchor: AuthorAnchor::ActiveTip(next) }
        );
    }

    /// An author idle across two bases is carried by both, so the second
    /// re-anchors it. That rests on the anchored row still exporting the
    /// position the first base carried: the second base's snapshot is read
    /// back from these rows, and only an exact match is anchored.
    #[test]
    fn an_idle_author_carried_by_two_bases_is_re_anchored_on_the_second() {
        let conn = conn();
        let first = HistoryBase([3u8; 32]);
        let second = HistoryBase([8u8; 32]);
        let tip = ChangeHash([4u8; 32]);
        advance_author_state(&conn, GROUP, "device-1", AuthorSeq(4), &tip).unwrap();

        for base in [first, second] {
            let exported = all_author_state(&conn, GROUP).unwrap();
            assert_eq!(
                exported,
                vec![carried(1, 4, tip)],
                "an anchored author still exports the position it holds, tip included"
            );
            anchor_carried_positions_on_base(&conn, GROUP, &base, &exported).unwrap();
        }
        assert_eq!(
            state(&conn, 1, GROUP).unwrap().position(),
            AuthorPosition { watermark: AuthorSeq(4), anchor: AuthorAnchor::Base(second) }
        );

        let opening = Change::create_signed(
            vec![],
            0,
            DeviceId("device-1".into()),
            AuthorSeq(5),
            None,
            FolderGroupId(GROUP.into()),
            HistoryEpoch::Base(second),
            vec![Op::Delete { path: SyncPath("a".into()) }],
            &key(1),
        );
        assert_eq!(verdict(&conn, &opening), AuthorChainVerdict::Admit);
    }

    /// The first change above a carried position links to the base through
    /// its signed history epoch, so it must be written on that base. The
    /// admission funnel refuses other histories before asking the author
    /// chain; this is the chain's own half of the same rule.
    #[test]
    fn a_base_anchored_author_is_refused_a_change_on_another_history() {
        let conn = conn();
        let base = HistoryBase([3u8; 32]);
        let tip = ChangeHash([4u8; 32]);
        advance_author_state(&conn, GROUP, "device-1", AuthorSeq(1), &tip).unwrap();
        anchor_carried_positions_on_base(&conn, GROUP, &base, &[carried(1, 1, tip)]).unwrap();

        let on_genesis = change(1, 2, GROUP, None, &[], "a");
        assert_eq!(
            verdict(&conn, &on_genesis),
            AuthorChainVerdict::Refuse(AuthorChainRefusal::AuthorAnchoredOnAnotherBase {
                seq: AuthorSeq(2),
                anchor: base,
                incoming: HistoryEpoch::Genesis,
            })
        );
    }

    #[test]
    fn a_stored_watermark_that_is_not_a_position_is_refused_rather_than_rounded() {
        let conn = conn();
        conn.execute(
            "INSERT INTO author_chain_state (group_id, device_id, watermark, tip_change_hash) \
             VALUES (?1, 'device-1', 0, ?2)",
            rusqlite::params![GROUP, &[0u8; 32][..]],
        )
        .unwrap();
        assert!(author_chain_state(&conn, GROUP, "device-1").is_err());
    }
}

//! Client-side verifier for the signed group policy log carried in netmap
//! updates. This mirrors the coordination plane's canonical record encoding
//! using plain data types owned here, so verification has no dependency on
//! the coordination plane's transport or wire format.

use std::collections::{BTreeMap, HashMap};

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use yadorilink_sync_core::change::ChangeAuth;
use yadorilink_sync_core::index::PolicyWatermark;

/// A group's signed policy log as delivered by the coordination plane in a
/// netmap update. Plain data the netmap client fills from the coordination
/// plane's response; verified below against the pinned service key.
#[derive(Debug, Clone, Default)]
pub struct GroupPolicyLog {
    pub group_id: String,
    pub current_seq: u64,
    pub current_epoch: u64,
    /// 32-byte hash of the latest record (zero if none).
    pub policy_head: Vec<u8>,
    pub records: Vec<PolicyRecord>,
}

/// One signed entry in a group's policy log. Field layout matches the
/// coordination plane's canonical record so the signing-bytes computation
/// below reproduces exactly what the signer hashed.
#[derive(Debug, Clone, Default)]
pub struct PolicyRecord {
    pub group_id: String,
    pub seq: u64,
    /// 32 bytes; zero for the genesis record.
    pub prev_record_hash: Vec<u8>,
    /// 32 bytes; SHA-256(signing_bytes || signature).
    pub record_hash: Vec<u8>,
    /// `auth_epoch` after this record applies.
    pub epoch: u64,
    /// 0 Grant | 1 Revoke | 2 RotateAuthority.
    pub action_type: u32,
    /// Grant/Revoke.
    pub device_id: String,
    /// Grant only; 32 bytes (zero if the device has no signing key).
    pub signing_key_fingerprint: Vec<u8>,
    /// RotateAuthority only; 32 bytes.
    pub new_authority_key: Vec<u8>,
    /// 32-byte fingerprint of the signing authority key.
    pub signer_key_id: Vec<u8>,
    /// 64-byte Ed25519 over the signing bytes.
    pub signature: Vec<u8>,
}

const POLICY_DOMAIN_TAG: &[u8; 8] = b"ylpolic1";
const ACTION_GRANT: u32 = 0;
const ACTION_REVOKE: u32 = 1;
const ACTION_ROTATE_AUTHORITY: u32 = 2;
const HASH_LEN: usize = 32;
const SIGNATURE_LEN: usize = 64;
const ZERO_HASH: [u8; HASH_LEN] = [0u8; HASH_LEN];

/// Whether a Grant's bound signing-key fingerprint admits a change whose
/// verifying key hashes to `presented_fingerprint`. A Grant records the
/// SHA-256 fingerprint of the device's signing key so admission can confirm
/// the key that actually verified a change is the same key policy bound to
/// that device — not merely that the device is *a* writer. Admission is
/// fail-closed: an all-zero (absent/unbound) bound fingerprint admits
/// *nothing* — there is deliberately no "unbound key admits any key" fallback,
/// because that let a Grant with a zero fingerprint ride an arbitrary key and
/// defeated the whole binding. The coordination plane never emits a
/// zero-fingerprint grant (every Grant binds the device's registered signing
/// key), so a zero bound fingerprint can only be a malformed or downgraded
/// record and must be rejected. A real change's `presented_fingerprint` is the
/// SHA-256 of an Ed25519 key and so is never all-zero, so the `bound != ZERO`
/// guard is the load-bearing check.
fn fingerprint_admits(bound: [u8; HASH_LEN], presented_fingerprint: [u8; HASH_LEN]) -> bool {
    bound != ZERO_HASH && bound == presented_fingerprint
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PolicyAction {
    Grant { device_id: String, signing_key_fingerprint: [u8; HASH_LEN] },
    Revoke { device_id: String },
    RotateAuthority { new_authority_key: [u8; HASH_LEN] },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VerifiedPolicyRecord {
    seq: u64,
    prev_record_hash: [u8; HASH_LEN],
    record_hash: [u8; HASH_LEN],
    epoch: u64,
    signer_key_id: [u8; HASH_LEN],
    action: PolicyAction,
    signature: [u8; SIGNATURE_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupPolicyState {
    pub current_seq: u64,
    pub current_epoch: u64,
    pub policy_head: [u8; HASH_LEN],
    pub final_authority_key: [u8; HASH_LEN],
    /// How many `RotateAuthority` records the verified chain contains — a
    /// monotonic generation counter for the group's signing authority.
    /// Persisted alongside the rollback watermark so an older chain that
    /// predates a rotation can be recognized and rejected after a restart.
    pub authority_generation: u64,
    records: BTreeMap<u64, VerifiedPolicyRecord>,
}

/// The outcome of checking a freshly verified policy snapshot against the
/// persisted rollback watermark for its group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatermarkVerdict {
    /// The snapshot is at least as new as the watermark and continuous with
    /// it; adopt it and advance the persisted watermark to these coordinates.
    Accept(PolicyWatermark),
    /// The snapshot is a rollback, a fork, or an unrelated chain relative to
    /// the watermark; reject it (fail closed) and do not lower the watermark.
    Reject(String),
}

impl GroupPolicyState {
    pub fn change_auth(&self) -> ChangeAuth {
        ChangeAuth {
            auth_seq: self.current_seq,
            auth_epoch: self.current_epoch,
            policy_head_hash: self.policy_head,
        }
    }

    pub fn author_was_writer_at(
        &self,
        author: &str,
        signing_key_fingerprint: [u8; HASH_LEN],
        auth: ChangeAuth,
    ) -> bool {
        if auth == ChangeAuth::PLACEHOLDER {
            return self.records.is_empty()
                && self.current_seq == 0
                && self.current_epoch == 0
                && self.policy_head == ZERO_HASH;
        }
        let Some(head) = self.records.get(&auth.auth_seq) else {
            return false;
        };
        if head.record_hash != auth.policy_head_hash || head.epoch != auth.auth_epoch {
            return false;
        }

        let mut grants: HashMap<&str, [u8; HASH_LEN]> = HashMap::new();
        for record in self.records.range(..=auth.auth_seq).map(|(_, record)| record) {
            match &record.action {
                PolicyAction::Grant { device_id, signing_key_fingerprint } => {
                    grants.insert(device_id.as_str(), *signing_key_fingerprint);
                }
                PolicyAction::Revoke { device_id } => {
                    grants.remove(device_id.as_str());
                }
                PolicyAction::RotateAuthority { .. } => {}
            }
        }
        grants
            .get(author)
            .map(|bound_fingerprint| {
                fingerprint_admits(*bound_fingerprint, signing_key_fingerprint)
            })
            .unwrap_or(false)
    }

    /// SHA-256 of the group's current authority public key. Pins WHICH trust
    /// root produced this state, so the watermark can catch a fork that swaps
    /// the authority key without advancing the generation counter, and an audit
    /// can name the exact key that was trusted. `final_authority_key` is the
    /// authority Ed25519 public key (32 bytes) in effect at the verified head,
    /// after applying every `RotateAuthority` in the chain.
    pub fn authority_key_fingerprint(&self) -> [u8; HASH_LEN] {
        Sha256::digest(self.final_authority_key).into()
    }

    /// This state's rollback watermark coordinates: the highest verified
    /// sequence, its head hash, the authority generation at that head, and the
    /// fingerprint of the authority key that signed up to it. A freshly
    /// verified snapshot always carries the fingerprint (`Some`), so persisting
    /// this also backfills the fingerprint onto a legacy watermark row that had
    /// none.
    pub fn to_watermark(&self) -> PolicyWatermark {
        PolicyWatermark {
            highest_verified_seq: self.current_seq,
            highest_verified_head: self.policy_head,
            authority_key_generation: self.authority_generation,
            authority_key_fingerprint: Some(self.authority_key_fingerprint()),
        }
    }

    /// The verified `record_hash` at `seq`, if the verified chain covers it.
    /// A snapshot verified with `base = None` (as after a daemon restart, when
    /// the coordination plane resends the full chain) carries every record
    /// from seq 1, so this resolves any `seq` up to `current_seq`.
    fn record_head_at(&self, seq: u64) -> Option<[u8; HASH_LEN]> {
        self.records.get(&seq).map(|record| record.record_hash)
    }

    /// Decides whether adopting this verified snapshot is permitted given the
    /// group's persisted rollback watermark (`None` when the group has never
    /// been recorded). The signed hash-chain + signature check that produced
    /// `self` proves the chain is internally valid, but a *past* valid chain
    /// is equally signature-valid, so a peer or the coordination plane could
    /// replay an old chain after a restart to hide a later revoke. The
    /// watermark closes that: it is the highest chain this device has ever
    /// verified, and it never moves backward.
    ///
    /// - A lower `current_seq`, or a lower authority generation, is a
    ///   rollback — reject.
    /// - The SAME authority generation but a DIFFERENT authority-key
    ///   fingerprint is a fork at the trust root — reject. Two chains at the
    ///   same rotation count must share the same authority key; a differing key
    ///   means the snapshot descends from a different root than the one this
    ///   device verified. The head-hash chaining below remains the primary
    ///   cryptographic binding; this fingerprint check is an additional guard
    ///   that also catches a same-generation swap directly.
    /// - The same `current_seq` with a different head is a fork — reject;
    ///   an identical resend is accepted and keeps the watermark.
    /// - A higher `current_seq` must *extend* the watermark: the new chain's
    ///   record at the watermark's sequence must hash to the watermark's head
    ///   (the hash chain then guarantees identical history up to that point).
    ///   An unrelated or forked longer chain is rejected.
    ///
    /// A generation INCREASE legitimately changes the authority key: each
    /// `RotateAuthority` was already signature-verified against the key it
    /// replaces while producing `self`, and (for a longer chain) the
    /// extend-the-head check below proves the rotation happened on top of the
    /// verified history — so a higher generation is accepted and its new
    /// fingerprint recorded, exactly as before, without newly rejecting a
    /// legitimate rotation. The fingerprint is only compared for EQUALITY, and
    /// only at an equal generation.
    ///
    /// A stored watermark with NO fingerprint (`None`) is a legacy row written
    /// before the fingerprint column existed. It cannot be compared, so it is
    /// treated as "unknown", NOT as a fork: the snapshot is accepted on the
    /// other checks and `to_watermark` backfills the fingerprint. Migration
    /// safety — an already-trusted chain must stay trusted across the upgrade.
    pub fn watermark_verdict(&self, stored: Option<&PolicyWatermark>) -> WatermarkVerdict {
        let Some(stored) = stored else {
            // First time this group is seen locally — nothing to roll back to.
            return WatermarkVerdict::Accept(self.to_watermark());
        };
        if self.current_seq < stored.highest_verified_seq {
            return WatermarkVerdict::Reject(format!(
                "policy rollback: snapshot seq {} is below verified watermark {}",
                self.current_seq, stored.highest_verified_seq
            ));
        }
        if self.authority_generation < stored.authority_key_generation {
            return WatermarkVerdict::Reject(format!(
                "policy authority rollback: snapshot generation {} is below verified {}",
                self.authority_generation, stored.authority_key_generation
            ));
        }
        // Same authority generation must mean the same authority key. A stored
        // fingerprint of `None` is a legacy row (pre-fingerprint column): it
        // cannot be compared, so it is not treated as a fork — the snapshot is
        // accepted on the remaining checks and the fingerprint is backfilled.
        if self.authority_generation == stored.authority_key_generation {
            if let Some(stored_fingerprint) = stored.authority_key_fingerprint {
                if stored_fingerprint != self.authority_key_fingerprint() {
                    return WatermarkVerdict::Reject(format!(
                        "policy fork: snapshot at authority generation {} presents a different \
                         authority key than the verified watermark",
                        self.authority_generation
                    ));
                }
            }
        }
        if self.current_seq == stored.highest_verified_seq {
            if self.policy_head != stored.highest_verified_head {
                return WatermarkVerdict::Reject(format!(
                    "policy fork: snapshot at seq {} has a different head than the verified \
                     watermark",
                    self.current_seq
                ));
            }
            // Identical to what we already trust — keep the watermark's
            // coordinates. Return `self`'s watermark rather than the stored one
            // so a legacy row with no fingerprint gets it backfilled here (seq,
            // head, and generation are all equal in this branch, so the only
            // field that can differ is a previously-absent fingerprint).
            return WatermarkVerdict::Accept(self.to_watermark());
        }
        // Strictly higher: the new chain must contain the watermark's head at
        // the watermark's sequence, proving it continues that exact history.
        match self.record_head_at(stored.highest_verified_seq) {
            Some(head) if head == stored.highest_verified_head => {
                WatermarkVerdict::Accept(self.to_watermark())
            }
            _ => WatermarkVerdict::Reject(format!(
                "policy fork: snapshot seq {} does not extend verified head at seq {}",
                self.current_seq, stored.highest_verified_seq
            )),
        }
    }
}

pub fn verify_group_policy_log(
    service_public_key: &[u8],
    log: &GroupPolicyLog,
) -> Result<GroupPolicyState, String> {
    verify_group_policy_log_with_base(service_public_key, None, log)
}

pub fn verify_group_policy_log_with_base(
    service_public_key: &[u8],
    base: Option<&GroupPolicyState>,
    log: &GroupPolicyLog,
) -> Result<GroupPolicyState, String> {
    let mut authority_key = fixed::<HASH_LEN>(service_public_key, "service public key")?;
    let current_head = fixed::<HASH_LEN>(&log.policy_head, "policy head")?;
    let mut expected_prev = ZERO_HASH;
    let mut expected_seq = 1u64;
    let mut authority_generation = base.map(|b| b.authority_generation).unwrap_or(0);
    let mut records = BTreeMap::new();
    if let Some(base) = base {
        authority_key = base.final_authority_key;
        expected_prev = base.policy_head;
        expected_seq = base.current_seq.saturating_add(1);
        records = base.records.clone();
        if log.records.is_empty() {
            if log.current_seq == base.current_seq
                && log.current_epoch == base.current_epoch
                && current_head == base.policy_head
            {
                return Ok(base.clone());
            }
            return Err("policy snapshot has no records beyond the retained prefix".into());
        }
    }

    let mut ordered = log.records.clone();
    ordered.sort_by_key(|record| record.seq);

    for record in &ordered {
        if record.group_id != log.group_id {
            return Err(format!(
                "policy record group {} does not match log group {}",
                record.group_id, log.group_id
            ));
        }
        if record.seq != expected_seq {
            return Err(format!("policy sequence gap at {}", record.seq));
        }
        let verified = verify_record(record, &authority_key, expected_prev)?;
        expected_prev = verified.record_hash;
        if let PolicyAction::RotateAuthority { new_authority_key } = &verified.action {
            authority_key = *new_authority_key;
            authority_generation += 1;
        }
        records.insert(verified.seq, verified);
        expected_seq += 1;
    }

    let derived_head =
        records.last_key_value().map(|(_, record)| record.record_hash).unwrap_or(ZERO_HASH);
    let derived_seq = records.last_key_value().map(|(seq, _)| *seq).unwrap_or(0);
    let derived_epoch = records.last_key_value().map(|(_, record)| record.epoch).unwrap_or(0);
    if log.current_seq != derived_seq {
        return Err(format!(
            "policy current_seq {} does not match derived {}",
            log.current_seq, derived_seq
        ));
    }
    if log.current_epoch != derived_epoch {
        return Err(format!(
            "policy current_epoch {} does not match derived {}",
            log.current_epoch, derived_epoch
        ));
    }
    if current_head != derived_head {
        return Err("policy head does not match the verified chain".into());
    }

    Ok(GroupPolicyState {
        current_seq: derived_seq,
        current_epoch: derived_epoch,
        policy_head: derived_head,
        final_authority_key: authority_key,
        authority_generation,
        records,
    })
}

fn verify_record(
    record: &PolicyRecord,
    authority_key: &[u8; HASH_LEN],
    expected_prev: [u8; HASH_LEN],
) -> Result<VerifiedPolicyRecord, String> {
    let prev_record_hash = fixed::<HASH_LEN>(&record.prev_record_hash, "prev_record_hash")?;
    if prev_record_hash != expected_prev {
        return Err(format!("policy record {} has a broken prev hash", record.seq));
    }
    let record_hash = fixed::<HASH_LEN>(&record.record_hash, "record_hash")?;
    let signer_key_id = fixed::<HASH_LEN>(&record.signer_key_id, "signer_key_id")?;
    let expected_signer_key_id: [u8; HASH_LEN] = Sha256::digest(authority_key).into();
    if signer_key_id != expected_signer_key_id {
        return Err(format!("policy record {} signer key id mismatch", record.seq));
    }
    let signature = fixed::<SIGNATURE_LEN>(&record.signature, "signature")?;
    let action = parse_action(record)?;
    let verified = VerifiedPolicyRecord {
        seq: record.seq,
        prev_record_hash,
        record_hash,
        epoch: record.epoch,
        signer_key_id,
        action,
        signature,
    };
    let signing_bytes = signing_bytes(&record.group_id, &verified);
    let verifying_key = VerifyingKey::from_bytes(authority_key)
        .map_err(|_| "invalid policy service public key".to_string())?;
    let sig = Signature::from_bytes(&verified.signature);
    verifying_key
        .verify_strict(&signing_bytes, &sig)
        .map_err(|_| format!("policy record {} signature verification failed", record.seq))?;
    let mut hasher = Sha256::new();
    hasher.update(&signing_bytes);
    hasher.update(verified.signature);
    let computed_hash: [u8; HASH_LEN] = hasher.finalize().into();
    if computed_hash != verified.record_hash {
        return Err(format!("policy record {} hash mismatch", record.seq));
    }
    Ok(verified)
}

fn parse_action(record: &PolicyRecord) -> Result<PolicyAction, String> {
    match record.action_type {
        ACTION_GRANT => {
            let signing_key_fingerprint =
                fixed::<HASH_LEN>(&record.signing_key_fingerprint, "signing_key_fingerprint")?;
            Ok(PolicyAction::Grant { device_id: record.device_id.clone(), signing_key_fingerprint })
        }
        ACTION_REVOKE => Ok(PolicyAction::Revoke { device_id: record.device_id.clone() }),
        ACTION_ROTATE_AUTHORITY => {
            let new_authority_key =
                fixed::<HASH_LEN>(&record.new_authority_key, "new_authority_key")?;
            Ok(PolicyAction::RotateAuthority { new_authority_key })
        }
        _ => Err(format!("policy record {} has invalid action type", record.seq)),
    }
}

fn signing_bytes(group_id: &str, record: &VerifiedPolicyRecord) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(POLICY_DOMAIN_TAG);
    put_str(&mut buf, group_id);
    put_u64(&mut buf, record.seq);
    buf.extend_from_slice(&record.prev_record_hash);
    put_u64(&mut buf, record.epoch);
    buf.extend_from_slice(&record.signer_key_id);
    match &record.action {
        PolicyAction::Grant { device_id, signing_key_fingerprint } => {
            buf.push(ACTION_GRANT as u8);
            put_str(&mut buf, device_id);
            buf.extend_from_slice(signing_key_fingerprint);
        }
        PolicyAction::Revoke { device_id } => {
            buf.push(ACTION_REVOKE as u8);
            put_str(&mut buf, device_id);
        }
        PolicyAction::RotateAuthority { new_authority_key } => {
            buf.push(ACTION_ROTATE_AUTHORITY as u8);
            buf.extend_from_slice(new_authority_key);
        }
    }
    buf
}

fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn put_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn put_str(buf: &mut Vec<u8>, s: &str) {
    put_u32(buf, s.len() as u32);
    buf.extend_from_slice(s.as_bytes());
}

fn fixed<const N: usize>(bytes: &[u8], field: &str) -> Result<[u8; N], String> {
    bytes.try_into().map_err(|_| format!("{field} is not {N} bytes"))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    fn service_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn grant_record(
        key: &SigningKey,
        group_id: &str,
        seq: u64,
        prev: [u8; HASH_LEN],
        device_id: &str,
        signing_key_fingerprint: [u8; HASH_LEN],
    ) -> PolicyRecord {
        signed_record(
            key,
            group_id,
            seq,
            prev,
            0,
            PolicyAction::Grant { device_id: device_id.to_string(), signing_key_fingerprint },
        )
    }

    fn revoke_record(
        key: &SigningKey,
        group_id: &str,
        seq: u64,
        prev: [u8; HASH_LEN],
        device_id: &str,
    ) -> PolicyRecord {
        signed_record(
            key,
            group_id,
            seq,
            prev,
            1,
            PolicyAction::Revoke { device_id: device_id.to_string() },
        )
    }

    fn rotate_record(
        key: &SigningKey,
        group_id: &str,
        seq: u64,
        prev: [u8; HASH_LEN],
        new_authority_key: [u8; HASH_LEN],
    ) -> PolicyRecord {
        signed_record(
            key,
            group_id,
            seq,
            prev,
            0,
            PolicyAction::RotateAuthority { new_authority_key },
        )
    }

    fn signed_record(
        key: &SigningKey,
        group_id: &str,
        seq: u64,
        prev: [u8; HASH_LEN],
        epoch: u64,
        action: PolicyAction,
    ) -> PolicyRecord {
        let public = key.verifying_key().to_bytes();
        let signer_key_id: [u8; HASH_LEN] = Sha256::digest(public).into();
        let mut verified = VerifiedPolicyRecord {
            seq,
            prev_record_hash: prev,
            record_hash: ZERO_HASH,
            epoch,
            signer_key_id,
            action,
            signature: [0u8; SIGNATURE_LEN],
        };
        let bytes = signing_bytes(group_id, &verified);
        verified.signature = key.sign(&bytes).to_bytes();
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        hasher.update(verified.signature);
        verified.record_hash = hasher.finalize().into();

        let mut record = PolicyRecord {
            group_id: group_id.to_string(),
            seq,
            prev_record_hash: prev.to_vec(),
            record_hash: verified.record_hash.to_vec(),
            epoch,
            action_type: ACTION_GRANT,
            device_id: String::new(),
            signing_key_fingerprint: Vec::new(),
            new_authority_key: Vec::new(),
            signer_key_id: signer_key_id.to_vec(),
            signature: verified.signature.to_vec(),
        };
        match verified.action {
            PolicyAction::Grant { device_id, signing_key_fingerprint } => {
                record.action_type = ACTION_GRANT;
                record.device_id = device_id;
                record.signing_key_fingerprint = signing_key_fingerprint.to_vec();
            }
            PolicyAction::Revoke { device_id } => {
                record.action_type = ACTION_REVOKE;
                record.device_id = device_id;
            }
            PolicyAction::RotateAuthority { new_authority_key } => {
                record.action_type = ACTION_ROTATE_AUTHORITY;
                record.new_authority_key = new_authority_key.to_vec();
            }
        }
        record
    }

    #[test]
    fn admission_uses_policy_history_not_current_head() {
        let key = service_key();
        let group_id = "group";
        // device-a's Grant pins a concrete signing-key fingerprint, so
        // admission checks BOTH history (writer at the pinned seq) AND the key
        // binding (the change's verifying key matches the granted one).
        let a_fp = [9u8; HASH_LEN];
        let b_fp = [7u8; HASH_LEN];
        let a = grant_record(&key, group_id, 1, ZERO_HASH, "device-a", a_fp);
        let a_hash: [u8; HASH_LEN] = a.record_hash.as_slice().try_into().unwrap();
        let b = grant_record(&key, group_id, 2, a_hash, "device-b", b_fp);
        let b_hash: [u8; HASH_LEN] = b.record_hash.as_slice().try_into().unwrap();
        let revoke_a = revoke_record(&key, group_id, 3, b_hash, "device-a");
        let revoke_hash: [u8; HASH_LEN] = revoke_a.record_hash.as_slice().try_into().unwrap();

        let log = GroupPolicyLog {
            group_id: group_id.to_string(),
            current_seq: 3,
            current_epoch: 1,
            policy_head: revoke_hash.to_vec(),
            records: vec![a, b, revoke_a],
        };
        let policy = verify_group_policy_log(&key.verifying_key().to_bytes(), &log).unwrap();

        // device-a was a writer at seq 1 and presents its granted key.
        assert!(policy.author_was_writer_at(
            "device-a",
            a_fp,
            ChangeAuth { auth_seq: 1, auth_epoch: 0, policy_head_hash: a_hash }
        ));
        // Same history, but a different signing key than the Grant bound —
        // rejected, so a stolen device_id can't ride another key.
        assert!(!policy.author_was_writer_at(
            "device-a",
            [1u8; HASH_LEN],
            ChangeAuth { auth_seq: 1, auth_epoch: 0, policy_head_hash: a_hash }
        ));
        // device-b is not yet granted at seq 1.
        assert!(!policy.author_was_writer_at(
            "device-b",
            b_fp,
            ChangeAuth { auth_seq: 1, auth_epoch: 0, policy_head_hash: a_hash }
        ));
        // device-a is revoked by seq 3.
        assert!(!policy.author_was_writer_at(
            "device-a",
            a_fp,
            ChangeAuth { auth_seq: 3, auth_epoch: 1, policy_head_hash: revoke_hash }
        ));
    }

    #[test]
    fn zero_fingerprint_grant_admits_no_signing_key() {
        // A Grant carrying an all-zero fingerprint binds no signing key. The
        // coordination plane never emits one (every Grant binds the device's
        // registered signing key), so such a record is malformed/downgraded
        // and admission is fail-closed: it admits NOTHING, not "any key". This
        // is the fix for the former fail-open where a zero fingerprint let a
        // change signed by an arbitrary key ride the grant.
        let key = service_key();
        let group_id = "group";
        let a = grant_record(&key, group_id, 1, ZERO_HASH, "device-a", ZERO_HASH);
        let a_hash: [u8; HASH_LEN] = a.record_hash.as_slice().try_into().unwrap();

        let log = GroupPolicyLog {
            group_id: group_id.to_string(),
            current_seq: 1,
            current_epoch: 0,
            policy_head: a_hash.to_vec(),
            records: vec![a],
        };
        let policy = verify_group_policy_log(&key.verifying_key().to_bytes(), &log).unwrap();

        // No presented fingerprint is admitted for a zero-fingerprint grant —
        // not an arbitrary real key, and not the all-zero fingerprint itself.
        assert!(!policy.author_was_writer_at(
            "device-a",
            [42u8; HASH_LEN],
            ChangeAuth { auth_seq: 1, auth_epoch: 0, policy_head_hash: a_hash }
        ));
        assert!(!policy.author_was_writer_at(
            "device-a",
            ZERO_HASH,
            ChangeAuth { auth_seq: 1, auth_epoch: 0, policy_head_hash: a_hash }
        ));
        // A device with no grant at all is likewise rejected.
        assert!(!policy.author_was_writer_at(
            "device-b",
            [42u8; HASH_LEN],
            ChangeAuth { auth_seq: 1, auth_epoch: 0, policy_head_hash: a_hash }
        ));
    }

    #[test]
    fn verified_rotation_updates_final_authority_key() {
        let old_key = service_key();
        let new_key = SigningKey::from_bytes(&[8u8; 32]);
        let group_id = "group";
        let rotate =
            rotate_record(&old_key, group_id, 1, ZERO_HASH, new_key.verifying_key().to_bytes());
        let rotate_hash: [u8; HASH_LEN] = rotate.record_hash.as_slice().try_into().unwrap();

        let log = GroupPolicyLog {
            group_id: group_id.to_string(),
            current_seq: 1,
            current_epoch: 0,
            policy_head: rotate_hash.to_vec(),
            records: vec![rotate],
        };
        let policy = verify_group_policy_log(&old_key.verifying_key().to_bytes(), &log).unwrap();
        assert_eq!(policy.final_authority_key, new_key.verifying_key().to_bytes());
        // One rotation record -> generation 1.
        assert_eq!(policy.authority_generation, 1);
    }

    fn hash_of(record: &PolicyRecord) -> [u8; HASH_LEN] {
        record.record_hash.as_slice().try_into().unwrap()
    }

    /// A three-record chain (grant a, grant b, revoke a) and its verified
    /// state, reused by the watermark tests below.
    fn revoke_chain() -> (SigningKey, [u8; HASH_LEN], [u8; HASH_LEN], GroupPolicyState) {
        let key = service_key();
        let group_id = "group";
        let a = grant_record(&key, group_id, 1, ZERO_HASH, "device-a", [9u8; HASH_LEN]);
        let a_hash = hash_of(&a);
        let b = grant_record(&key, group_id, 2, a_hash, "device-b", [7u8; HASH_LEN]);
        let b_hash = hash_of(&b);
        let revoke = revoke_record(&key, group_id, 3, b_hash, "device-a");
        let revoke_hash = hash_of(&revoke);
        let log = GroupPolicyLog {
            group_id: group_id.to_string(),
            current_seq: 3,
            current_epoch: 1,
            policy_head: revoke_hash.to_vec(),
            records: vec![a, b, revoke],
        };
        let verified = verify_group_policy_log(&key.verifying_key().to_bytes(), &log).unwrap();
        (key, a_hash, b_hash, verified)
    }

    #[test]
    fn watermark_accepts_first_sight() {
        let (_key, _a, _b, verified) = revoke_chain();
        match verified.watermark_verdict(None) {
            WatermarkVerdict::Accept(w) => {
                assert_eq!(w.highest_verified_seq, 3);
                assert_eq!(w.highest_verified_head, verified.policy_head);
            }
            other => panic!("expected first-sight accept, got {other:?}"),
        }
    }

    #[test]
    fn watermark_rejects_restart_rollback() {
        // The device verified the full chain (through the seq-3 revoke) and
        // persisted that watermark.
        let (key, a_hash, b_hash, verified) = revoke_chain();
        let watermark = verified.to_watermark();

        // After a restart the in-memory state is gone (base = None); a peer
        // replays the OLD chain up to seq 2 — signature-valid, but a rollback
        // that hides the seq-3 revoke of device-a.
        let a = grant_record(&key, "group", 1, ZERO_HASH, "device-a", [9u8; HASH_LEN]);
        assert_eq!(hash_of(&a), a_hash);
        let b = grant_record(&key, "group", 2, a_hash, "device-b", [7u8; HASH_LEN]);
        let old_log = GroupPolicyLog {
            group_id: "group".to_string(),
            current_seq: 2,
            current_epoch: 0,
            policy_head: b_hash.to_vec(),
            records: vec![a, b],
        };
        let replayed = verify_group_policy_log(&key.verifying_key().to_bytes(), &old_log).unwrap();
        assert!(matches!(
            replayed.watermark_verdict(Some(&watermark)),
            WatermarkVerdict::Reject(_)
        ));
    }

    #[test]
    fn watermark_rejects_fork_at_same_seq() {
        let key = service_key();
        let group_id = "group";
        // Two distinct seq-1 chains signed by the same authority: granting
        // different devices yields different record hashes (heads).
        let x = grant_record(&key, group_id, 1, ZERO_HASH, "device-a", [9u8; HASH_LEN]);
        let x_hash = hash_of(&x);
        let y = grant_record(&key, group_id, 1, ZERO_HASH, "device-b", [7u8; HASH_LEN]);
        let y_hash = hash_of(&y);
        assert_ne!(x_hash, y_hash);

        let x_log = GroupPolicyLog {
            group_id: group_id.to_string(),
            current_seq: 1,
            current_epoch: 0,
            policy_head: x_hash.to_vec(),
            records: vec![x],
        };
        let watermark = verify_group_policy_log(&key.verifying_key().to_bytes(), &x_log)
            .unwrap()
            .to_watermark();

        let y_log = GroupPolicyLog {
            group_id: group_id.to_string(),
            current_seq: 1,
            current_epoch: 0,
            policy_head: y_hash.to_vec(),
            records: vec![y],
        };
        let forked = verify_group_policy_log(&key.verifying_key().to_bytes(), &y_log).unwrap();
        assert!(matches!(forked.watermark_verdict(Some(&watermark)), WatermarkVerdict::Reject(_)));
    }

    #[test]
    fn watermark_accepts_forward_extension() {
        let key = service_key();
        let group_id = "group";
        // Watermark at seq 2 (grant a, grant b).
        let a = grant_record(&key, group_id, 1, ZERO_HASH, "device-a", [9u8; HASH_LEN]);
        let a_hash = hash_of(&a);
        let b = grant_record(&key, group_id, 2, a_hash, "device-b", [7u8; HASH_LEN]);
        let b_hash = hash_of(&b);
        let base_log = GroupPolicyLog {
            group_id: group_id.to_string(),
            current_seq: 2,
            current_epoch: 0,
            policy_head: b_hash.to_vec(),
            records: vec![a.clone(), b.clone()],
        };
        let watermark = verify_group_policy_log(&key.verifying_key().to_bytes(), &base_log)
            .unwrap()
            .to_watermark();

        // A longer chain that genuinely extends the watermark head at seq 2.
        let revoke = revoke_record(&key, group_id, 3, b_hash, "device-a");
        let revoke_hash = hash_of(&revoke);
        let ext_log = GroupPolicyLog {
            group_id: group_id.to_string(),
            current_seq: 3,
            current_epoch: 1,
            policy_head: revoke_hash.to_vec(),
            records: vec![a, b, revoke],
        };
        let extended = verify_group_policy_log(&key.verifying_key().to_bytes(), &ext_log).unwrap();
        match extended.watermark_verdict(Some(&watermark)) {
            WatermarkVerdict::Accept(w) => {
                assert_eq!(w.highest_verified_seq, 3);
                assert_eq!(w.highest_verified_head, revoke_hash);
            }
            other => panic!("expected forward-extension accept, got {other:?}"),
        }
    }

    #[test]
    fn watermark_accepts_identical_resend() {
        let (_key, _a, _b, verified) = revoke_chain();
        let watermark = verified.to_watermark();
        // The coordination plane resends the same head; nothing to advance.
        assert!(matches!(
            verified.watermark_verdict(Some(&watermark)),
            WatermarkVerdict::Accept(w) if w == watermark
        ));
    }

    #[test]
    fn watermark_rejects_authority_key_swap_at_same_generation() {
        // Two chains at the SAME authority generation must share the same
        // authority key. A snapshot whose authority-key fingerprint differs
        // from the verified watermark's — with no rotation to justify it — is a
        // fork at the trust root, and the fingerprint guard rejects it directly
        // even where the seq/head would otherwise line up.
        let (_key, _a, _b, verified) = revoke_chain();
        let mut watermark = verified.to_watermark();
        let mut swapped = verified.authority_key_fingerprint();
        swapped[0] ^= 0xFF;
        watermark.authority_key_fingerprint = Some(swapped);
        // Generation is unchanged (revoke_chain performs no rotation), so the
        // equal-generation fingerprint comparison is what fires here.
        assert_eq!(watermark.authority_key_generation, verified.authority_generation);
        assert!(matches!(
            verified.watermark_verdict(Some(&watermark)),
            WatermarkVerdict::Reject(_)
        ));
    }

    #[test]
    fn watermark_accepts_authority_rotation_and_records_new_fingerprint() {
        let key1 = service_key();
        let group_id = "group";
        // Watermark at seq 1 under the original authority key (generation 0).
        let a = grant_record(&key1, group_id, 1, ZERO_HASH, "device-a", [9u8; HASH_LEN]);
        let a_hash = hash_of(&a);
        let base_log = GroupPolicyLog {
            group_id: group_id.to_string(),
            current_seq: 1,
            current_epoch: 0,
            policy_head: a_hash.to_vec(),
            records: vec![a.clone()],
        };
        let base = verify_group_policy_log(&key1.verifying_key().to_bytes(), &base_log).unwrap();
        let watermark = base.to_watermark();
        assert_eq!(watermark.authority_key_generation, 0);

        // A longer chain rotates the authority key at seq 2 — a legitimate
        // rotation, signed by the current (key1) authority, that bumps the
        // generation to 1 and changes the authority key to key2.
        let key2 = SigningKey::from_bytes(&[11u8; 32]);
        let rotate = rotate_record(&key1, group_id, 2, a_hash, key2.verifying_key().to_bytes());
        let rotate_hash = hash_of(&rotate);
        let rotated_log = GroupPolicyLog {
            group_id: group_id.to_string(),
            current_seq: 2,
            current_epoch: 0,
            policy_head: rotate_hash.to_vec(),
            records: vec![a, rotate],
        };
        let rotated =
            verify_group_policy_log(&key1.verifying_key().to_bytes(), &rotated_log).unwrap();
        assert_eq!(rotated.authority_generation, 1);

        match rotated.watermark_verdict(Some(&watermark)) {
            WatermarkVerdict::Accept(w) => {
                assert_eq!(w.authority_key_generation, 1);
                // The persisted fingerprint is the rotated-to key's, not the
                // pre-rotation one.
                assert_eq!(w.authority_key_fingerprint, Some(rotated.authority_key_fingerprint()));
                assert_ne!(w.authority_key_fingerprint, watermark.authority_key_fingerprint);
            }
            other => panic!("expected rotation accept, got {other:?}"),
        }
    }

    #[test]
    fn watermark_accepts_and_backfills_legacy_row_without_fingerprint() {
        // A watermark persisted before the fingerprint column existed reads
        // back with `authority_key_fingerprint = None`. It must NOT be treated
        // as a fork against a fresh snapshot of the same trusted chain — the
        // snapshot is accepted and the fingerprint backfilled.
        let (_key, _a, _b, verified) = revoke_chain();
        let mut legacy = verified.to_watermark();
        legacy.authority_key_fingerprint = None;
        match verified.watermark_verdict(Some(&legacy)) {
            WatermarkVerdict::Accept(w) => {
                assert_eq!(w.authority_key_fingerprint, Some(verified.authority_key_fingerprint()));
            }
            other => panic!("expected legacy accept + backfill, got {other:?}"),
        }
    }

    /// This is the actual peer-side predicate a daemon that races a local
    /// edit ahead of its own policy load runs into: `author_was_writer_at`
    /// only admits a placeholder-auth change when ITS OWN chain is
    /// completely empty (see the `auth == ChangeAuth::PLACEHOLDER` branch
    /// above). A group that already has real, established policy elsewhere
    /// in the swarm — one Grant is enough — fails that check for every
    /// author, including one the Grant actually names, because the check
    /// never looks at the grants at all once the chain is non-empty.
    ///
    /// This is why a daemon that has not yet resolved a group's real policy
    /// state must not stamp a local edit with `ChangeAuth::PLACEHOLDER` and
    /// commit it locally: any peer already holding this exact history
    /// rejects it outright, and every change built on top of the rejected
    /// one inherits the same fate.
    #[test]
    fn placeholder_auth_is_rejected_by_a_peer_whose_policy_chain_is_not_empty() {
        let key = service_key();
        let group_id = "group";
        let a_fp = [9u8; HASH_LEN];
        let a = grant_record(&key, group_id, 1, ZERO_HASH, "device-a", a_fp);
        let a_hash: [u8; HASH_LEN] = a.record_hash.as_slice().try_into().unwrap();

        let log = GroupPolicyLog {
            group_id: group_id.to_string(),
            current_seq: 1,
            current_epoch: 0,
            policy_head: a_hash.to_vec(),
            records: vec![a],
        };
        let policy = verify_group_policy_log(&key.verifying_key().to_bytes(), &log).unwrap();

        // Even for device-a, the very device the real chain grants write
        // access to, a placeholder-auth change is rejected once the chain is
        // non-empty -- the placeholder path only ever admits a peer whose
        // chain is genuinely empty, never "some device this chain granted".
        assert!(!policy.author_was_writer_at("device-a", a_fp, ChangeAuth::PLACEHOLDER));
    }
}

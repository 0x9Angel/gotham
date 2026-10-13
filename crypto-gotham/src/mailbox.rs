use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub type MailboxId = [u8; 32];

const MAILBOX_ID_DOMAIN: &[u8] = b"gotham-mailbox-id-v1";

pub fn mailbox_id_for(recipient_pubkey: &[u8]) -> MailboxId {
    let mut h = blake3::Hasher::new();
    h.update(MAILBOX_ID_DOMAIN);
    h.update(recipient_pubkey);
    *h.finalize().as_bytes()
}

#[must_use]
pub fn mailbox_id_legacy(recipient_pubkey: &[u8]) -> MailboxId {
    mailbox_id_for(recipient_pubkey)
}

#[must_use]
pub fn mailbox_id_for_epoch(recipient_pubkey: &[u8], epoch: u64) -> MailboxId {
    let mut h = blake3::Hasher::new();
    h.update(MAILBOX_ID_DOMAIN);
    h.update(recipient_pubkey);
    h.update(&epoch.to_be_bytes());
    *h.finalize().as_bytes()
}

#[must_use]
pub fn mailbox_id_for_deposit(recipient_pubkey: &[u8], valid_after: u64) -> MailboxId {
    mailbox_id_for_epoch(recipient_pubkey, mailbox_epoch_of(valid_after))
}

#[must_use]
pub fn mailbox_ids_to_read(recipient_pubkey: &[u8], valid_after: u64) -> [MailboxId; 2] {
    let e = mailbox_epoch_of(valid_after);
    [
        mailbox_id_for_epoch(recipient_pubkey, e),
        mailbox_id_for_epoch(recipient_pubkey, e.saturating_sub(1)),
    ]
}

pub const FETCH_EPOCHS_BEHIND: u64 = DEFAULT_MAX_TTL_SECS / MAILBOX_EPOCH_SECS + 2;

pub const FETCH_EPOCHS_AHEAD: u64 = 1;

#[must_use]
pub fn mailbox_id_owned_at(pk: &[u8], id: &MailboxId, now: u64) -> bool {
    if mailbox_id_legacy(pk) == *id {
        return true;
    }
    let cur = mailbox_epoch_of(now);
    (cur.saturating_sub(FETCH_EPOCHS_BEHIND)..=cur.saturating_add(FETCH_EPOCHS_AHEAD))
        .any(|e| mailbox_id_for_epoch(pk, e) == *id)
}

const MAILBOX_FETCH_AUTH_DOMAIN: &str = "gotham-mailbox-fetch-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchAuth {
    pub pk: [u8; 32],
    pub tag: [u8; 32],
}

#[must_use]
pub fn fetch_auth_tag(shared: &[u8; 32], binding: &[u8], id: &MailboxId) -> [u8; 32] {
    let k = blake3::derive_key(MAILBOX_FETCH_AUTH_DOMAIN, shared);
    let mut h = blake3::Hasher::new_keyed(&k);
    h.update(&(binding.len() as u64).to_le_bytes());
    h.update(binding);
    h.update(id);
    *h.finalize().as_bytes()
}

impl FetchAuth {
    #[must_use]
    pub fn verify(&self, shared: &[u8; 32], binding: &[u8], id: &MailboxId) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        self.verify_at(shared, binding, id, now)
    }

    #[must_use]
    pub fn verify_at(&self, shared: &[u8; 32], binding: &[u8], id: &MailboxId, now: u64) -> bool {
        if !mailbox_id_owned_at(&self.pk, id, now) {
            return false;
        }
        let expected = fetch_auth_tag(shared, binding, id);
        let diff = self
            .tag
            .iter()
            .zip(expected.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        diff == 0
    }
}

#[must_use]
pub fn surb_fetch_binding(surb_bytes: &[u8]) -> Vec<u8> {
    let mut h = blake3::Hasher::new();
    h.update(b"gotham-mailbox-surb-binding-v1");
    h.update(surb_bytes);
    h.finalize().as_bytes().to_vec()
}

const MAILBOX_RENDEZVOUS_DOMAIN: &[u8] = b"gotham-mailbox-rendezvous-v1";

pub fn mailbox_host_score(recipient_pubkey: &[u8], host_id: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(MAILBOX_RENDEZVOUS_DOMAIN);
    h.update(recipient_pubkey);
    h.update(host_id);
    *h.finalize().as_bytes()
}

pub const MAILBOX_EPOCH_SECS: u64 = 86_400;

pub fn mailbox_epoch_of(valid_after: u64) -> u64 {
    valid_after / MAILBOX_EPOCH_SECS
}

const MAILBOX_RENDEZVOUS_DOMAIN_V2: &[u8] = b"gotham-mailbox-rendezvous-v2";

pub fn mailbox_host_score_at(epoch: u64, recipient_pubkey: &[u8], host_id: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(MAILBOX_RENDEZVOUS_DOMAIN_V2);
    h.update(&epoch.to_le_bytes());
    h.update(recipient_pubkey);
    h.update(host_id);
    *h.finalize().as_bytes()
}

#[derive(Clone, Debug)]
struct Entry {
    sealed: Vec<u8>,
    expires_at: u64,
}

pub const DEFAULT_MAX_TTL_SECS: u64 = 30 * 24 * 3600;

#[derive(Clone, Debug)]
pub struct MailboxPolicy {
    pub max_mailboxes: usize,
    pub max_msgs_per_mailbox: usize,
    pub max_total_msgs: usize,
    pub max_msg_bytes: usize,
    pub max_total_bytes: usize,
    pub default_ttl_secs: u64,
    pub max_ttl_secs: u64,
}

impl Default for MailboxPolicy {
    fn default() -> Self {
        Self {
            max_mailboxes: 100_000,
            max_msgs_per_mailbox: 1000,
            max_total_msgs: 1_000_000,
            max_msg_bytes: 16 * 1024,
            max_total_bytes: 512 * 1024 * 1024,
            default_ttl_secs: 7 * 24 * 3600,
            max_ttl_secs: DEFAULT_MAX_TTL_SECS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepositError {
    TooLarge,
    MailboxFull,
    StoreFull,
}

impl core::fmt::Display for DepositError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            DepositError::TooLarge => "sealed envelope too large",
            DepositError::MailboxFull => "mailbox is full",
            DepositError::StoreFull => "mailbox store is at capacity",
        };
        f.write_str(s)
    }
}

impl std::error::Error for DepositError {}

pub struct Mailbox {
    boxes: HashMap<MailboxId, Vec<Entry>>,
    policy: MailboxPolicy,
    total: usize,
    bytes: usize,
}

impl Mailbox {
    pub fn new(policy: MailboxPolicy) -> Self {
        let mut policy = policy;
        let ceiling = MAX_MAILBOX_FRAME.saturating_sub(4096);
        if policy.max_msg_bytes > ceiling {
            policy.max_msg_bytes = ceiling;
        }
        Self {
            boxes: HashMap::new(),
            policy,
            total: 0,
            bytes: 0,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(MailboxPolicy::default())
    }

    pub fn policy(&self) -> &MailboxPolicy {
        &self.policy
    }

    pub fn total(&self) -> usize {
        self.total
    }

    pub fn total_bytes(&self) -> usize {
        self.bytes
    }

    pub fn mailbox_count(&self) -> usize {
        self.boxes.len()
    }

    pub fn deposit(
        &mut self,
        id: MailboxId,
        sealed: Vec<u8>,
        now: u64,
        ttl_secs: u64,
    ) -> Result<(), DepositError> {
        if sealed.len() > self.policy.max_msg_bytes {
            return Err(DepositError::TooLarge);
        }
        let ttl = if ttl_secs == 0 {
            self.policy.default_ttl_secs
        } else {
            ttl_secs.min(self.policy.max_ttl_secs).max(1)
        };
        let expires_at = now.saturating_add(ttl);

        let is_new = !self.boxes.contains_key(&id);
        if is_new && self.boxes.len() >= self.policy.max_mailboxes {
            return Err(DepositError::StoreFull);
        }

        if let Some(v) = self.boxes.get_mut(&id) {
            let before = v.len();
            let before_bytes: usize = v.iter().map(|e| e.sealed.len()).sum();
            v.retain(|e| e.expires_at > now);
            let after_bytes: usize = v.iter().map(|e| e.sealed.len()).sum();
            self.total -= before - v.len();
            self.bytes -= before_bytes - after_bytes;
        }

        let cur = self.boxes.get(&id).map_or(0, Vec::len);
        if cur >= self.policy.max_msgs_per_mailbox {
            return Err(DepositError::MailboxFull);
        }
        if self.total >= self.policy.max_total_msgs
            || self.bytes + sealed.len() > self.policy.max_total_bytes
        {
            self.prune_expired(now);
        }
        if self.total >= self.policy.max_total_msgs {
            return Err(DepositError::StoreFull);
        }
        if self.bytes + sealed.len() > self.policy.max_total_bytes {
            return Err(DepositError::StoreFull);
        }

        self.bytes += sealed.len();
        self.boxes
            .entry(id)
            .or_default()
            .push(Entry { sealed, expires_at });
        self.total += 1;
        Ok(())
    }

    pub fn fetch(&mut self, id: &MailboxId, now: u64) -> Vec<Vec<u8>> {
        let Some(entries) = self.boxes.remove(id) else {
            return Vec::new();
        };
        self.total -= entries.len();
        self.bytes -= entries.iter().map(|e| e.sealed.len()).sum::<usize>();
        entries
            .into_iter()
            .filter(|e| e.expires_at > now)
            .map(|e| e.sealed)
            .collect()
    }

    pub fn pending(&self, id: &MailboxId, now: u64) -> usize {
        self.boxes
            .get(id)
            .map_or(0, |v| v.iter().filter(|e| e.expires_at > now).count())
    }

    pub fn prune_expired(&mut self, now: u64) -> usize {
        let mut removed = 0usize;
        let mut removed_bytes = 0usize;
        self.boxes.retain(|_, entries| {
            let before = entries.len();
            let before_bytes: usize = entries.iter().map(|e| e.sealed.len()).sum();
            entries.retain(|e| e.expires_at > now);
            removed += before - entries.len();
            removed_bytes += before_bytes - entries.iter().map(|e| e.sealed.len()).sum::<usize>();
            !entries.is_empty()
        });
        self.total -= removed;
        self.bytes -= removed_bytes;
        removed
    }

    pub fn fetch_batch(
        &mut self,
        id: &MailboxId,
        now: u64,
        max_total_bytes: usize,
    ) -> (Vec<Vec<u8>>, bool) {
        let Some(entries) = self.boxes.get_mut(id) else {
            return (Vec::new(), false);
        };
        let before = entries.len();
        let before_bytes: usize = entries.iter().map(|e| e.sealed.len()).sum();
        entries.retain(|e| e.expires_at > now);
        let expired = before - entries.len();
        let expired_bytes = before_bytes - entries.iter().map(|e| e.sealed.len()).sum::<usize>();

        let mut batch: Vec<Vec<u8>> = Vec::new();
        let mut used = 0usize;
        while let Some(front) = entries.first() {
            let len = front.sealed.len();
            if !batch.is_empty() && used + len > max_total_bytes {
                break;
            }
            let e = entries.remove(0);
            used += e.sealed.len();
            batch.push(e.sealed);
        }
        let more = !entries.is_empty();
        let taken = batch.len();
        if entries.is_empty() {
            self.boxes.remove(id);
        }
        self.total -= expired + taken;
        self.bytes -= expired_bytes + used;
        (batch, more)
    }

    pub fn snapshot(&self) -> MailboxSnapshot {
        let boxes = self
            .boxes
            .iter()
            .map(|(id, v)| {
                (
                    *id,
                    v.iter().map(|e| (e.sealed.clone(), e.expires_at)).collect(),
                )
            })
            .collect();
        MailboxSnapshot { boxes }
    }

    pub fn from_snapshot(policy: MailboxPolicy, snap: MailboxSnapshot, now: u64) -> Self {
        let mut boxes = HashMap::new();
        let mut total = 0usize;
        let mut bytes = 0usize;
        for (id, entries) in snap.boxes {
            let live: Vec<Entry> = entries
                .into_iter()
                .filter(|(_, exp)| *exp > now)
                .map(|(sealed, expires_at)| Entry { sealed, expires_at })
                .collect();
            if !live.is_empty() {
                total += live.len();
                bytes += live.iter().map(|e| e.sealed.len()).sum::<usize>();
                boxes.insert(id, live);
            }
        }
        Self {
            boxes,
            policy,
            total,
            bytes,
        }
    }
}

pub const MAX_MAILBOX_FRAME: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MailboxRequest {
    Deposit {
        id: MailboxId,
        sealed: Vec<u8>,
        ttl_secs: u64,
    },
    Fetch {
        id: MailboxId,
        #[serde(default)]
        auth: Option<FetchAuth>,
    },
    FetchWithSurb {
        id: MailboxId,
        surb: Vec<u8>,
        #[serde(default)]
        auth: Option<FetchAuth>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MailboxResponse {
    Ack,
    Delivery { sealed: Vec<Vec<u8>>, more: bool },
    Error(MailboxWireError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MailboxWireError {
    TooLarge,
    MailboxFull,
    StoreFull,
    Malformed,
    Unauthorized,
    RateLimited,
}

impl From<DepositError> for MailboxWireError {
    fn from(e: DepositError) -> Self {
        match e {
            DepositError::TooLarge => MailboxWireError::TooLarge,
            DepositError::MailboxFull => MailboxWireError::MailboxFull,
            DepositError::StoreFull => MailboxWireError::StoreFull,
        }
    }
}

impl MailboxRequest {
    pub fn to_bytes(&self) -> Result<Vec<u8>, MailboxWireError> {
        rmp_serde::to_vec_named(self).map_err(|_| MailboxWireError::Malformed)
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self, MailboxWireError> {
        rmp_serde::from_slice(b).map_err(|_| MailboxWireError::Malformed)
    }
}

impl MailboxResponse {
    pub fn to_bytes(&self) -> Result<Vec<u8>, MailboxWireError> {
        rmp_serde::to_vec_named(self).map_err(|_| MailboxWireError::Malformed)
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self, MailboxWireError> {
        rmp_serde::from_slice(b).map_err(|_| MailboxWireError::Malformed)
    }
}

pub type SnapshotEntry = (Vec<u8>, u64);
pub type SnapshotBox = (MailboxId, Vec<SnapshotEntry>);

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MailboxSnapshot {
    pub boxes: Vec<SnapshotBox>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: u64 = 3600;

    fn id(n: u8) -> MailboxId {
        [n; 32]
    }

    #[test]
    fn deposit_then_fetch_is_fifo_and_draining() {
        let mut mb = Mailbox::with_defaults();
        mb.deposit(id(1), b"first".to_vec(), 0, HOUR).unwrap();
        mb.deposit(id(1), b"second".to_vec(), 0, HOUR).unwrap();
        assert_eq!(mb.pending(&id(1), 0), 2);
        assert_eq!(mb.total(), 2);

        let got = mb.fetch(&id(1), 0);
        assert_eq!(got, vec![b"first".to_vec(), b"second".to_vec()]);
        assert!(mb.fetch(&id(1), 0).is_empty());
        assert_eq!(mb.total(), 0);
        assert_eq!(mb.mailbox_count(), 0);
    }

    #[test]
    fn expired_messages_are_not_returned_and_get_pruned() {
        let mut mb = Mailbox::with_defaults();
        mb.deposit(id(1), b"old".to_vec(), 0, HOUR).unwrap();
        mb.deposit(id(1), b"fresh".to_vec(), 0, 10 * HOUR).unwrap();
        let now = 2 * HOUR;
        assert_eq!(mb.pending(&id(1), now), 1);
        let got = mb.fetch(&id(1), now);
        assert_eq!(got, vec![b"fresh".to_vec()]);
        assert_eq!(mb.total(), 0);
    }

    #[test]
    fn prune_expired_reclaims_and_empties() {
        let mut mb = Mailbox::with_defaults();
        mb.deposit(id(1), b"a".to_vec(), 0, HOUR).unwrap();
        mb.deposit(id(2), b"b".to_vec(), 0, 10 * HOUR).unwrap();
        let removed = mb.prune_expired(2 * HOUR);
        assert_eq!(removed, 1);
        assert_eq!(mb.total(), 1);
        assert_eq!(mb.mailbox_count(), 1);
        assert_eq!(mb.pending(&id(2), 2 * HOUR), 1);
    }

    #[test]
    fn default_caps_stay_proportionate_to_the_protocol() {
        let p = MailboxPolicy::default();
        const LARGEST_REAL_DEPOSIT: usize = 1664 + 60;
        assert!(
            p.max_msg_bytes >= LARGEST_REAL_DEPOSIT * 4,
            "the per-message cap must leave room for protocol growth"
        );
        assert!(
            p.max_msg_bytes <= LARGEST_REAL_DEPOSIT * 16,
            "a cap far above the largest real deposit only buys an attacker room"
        );
        let worst_one_mailbox = p.max_msgs_per_mailbox * p.max_msg_bytes;
        assert!(
            worst_one_mailbox * 16 <= p.max_total_bytes,
            "one full mailbox is {worst_one_mailbox} bytes of a {} byte budget — \
             too few mailboxes would exhaust the relay",
            p.max_total_bytes
        );
        assert!(p.max_msgs_per_mailbox >= 1000);
    }

    #[test]
    fn rejects_oversize_payload() {
        let policy = MailboxPolicy {
            max_msg_bytes: 8,
            ..MailboxPolicy::default()
        };
        let mut mb = Mailbox::new(policy);
        assert_eq!(
            mb.deposit(id(1), vec![0u8; 9], 0, HOUR),
            Err(DepositError::TooLarge)
        );
        assert_eq!(mb.total(), 0);
    }

    #[test]
    fn enforces_per_mailbox_cap() {
        let policy = MailboxPolicy {
            max_msgs_per_mailbox: 2,
            ..MailboxPolicy::default()
        };
        let mut mb = Mailbox::new(policy);
        mb.deposit(id(1), b"a".to_vec(), 0, HOUR).unwrap();
        mb.deposit(id(1), b"b".to_vec(), 0, HOUR).unwrap();
        assert_eq!(
            mb.deposit(id(1), b"c".to_vec(), 0, HOUR),
            Err(DepositError::MailboxFull)
        );
        assert!(mb.deposit(id(1), b"d".to_vec(), 2 * HOUR, HOUR).is_ok());
    }

    #[test]
    fn enforces_store_and_mailbox_ceilings() {
        let policy = MailboxPolicy {
            max_mailboxes: 1,
            max_total_msgs: 1,
            ..MailboxPolicy::default()
        };
        let mut mb = Mailbox::new(policy);
        mb.deposit(id(1), b"a".to_vec(), 0, HOUR).unwrap();
        assert_eq!(
            mb.deposit(id(2), b"b".to_vec(), 0, HOUR),
            Err(DepositError::StoreFull)
        );
        let policy2 = MailboxPolicy {
            max_mailboxes: 10,
            max_total_msgs: 1,
            ..MailboxPolicy::default()
        };
        let mut mb2 = Mailbox::new(policy2);
        mb2.deposit(id(1), b"a".to_vec(), 0, HOUR).unwrap();
        assert_eq!(
            mb2.deposit(id(1), b"b".to_vec(), 0, HOUR),
            Err(DepositError::StoreFull)
        );
    }

    #[test]
    fn ttl_is_clamped_to_ceiling_and_default_applies() {
        let policy = MailboxPolicy {
            default_ttl_secs: 100,
            max_ttl_secs: 1000,
            ..MailboxPolicy::default()
        };
        let mut mb = Mailbox::new(policy);
        mb.deposit(id(1), b"def".to_vec(), 0, 0).unwrap();
        assert_eq!(mb.pending(&id(1), 50), 1);
        assert_eq!(mb.pending(&id(1), 150), 0);
        mb.deposit(id(2), b"clamp".to_vec(), 0, 1_000_000).unwrap();
        assert_eq!(mb.pending(&id(2), 999), 1);
        assert_eq!(mb.pending(&id(2), 1000), 0);
    }

    #[test]
    fn rendezvous_host_selection_is_deterministic_and_spreads() {
        let hosts: Vec<[u8; 32]> = (0..8u8).map(|i| [i + 100; 32]).collect();
        let pick = |r: &[u8]| {
            *hosts
                .iter()
                .max_by_key(|h| mailbox_host_score(r, *h))
                .unwrap()
        };
        assert_eq!(pick(&[7u8; 32]), pick(&[7u8; 32]));
        let picked: std::collections::HashSet<_> = (0..64u8).map(|n| pick(&[n; 32])).collect();
        assert!(
            picked.len() > 1,
            "rendezvous must spread recipients, not funnel them to one host"
        );
    }

    #[test]
    fn mailbox_id_is_deterministic_domain_separated_and_key_specific() {
        let k1 = [7u8; 32];
        let k2 = [8u8; 32];
        assert_eq!(mailbox_id_for(&k1), mailbox_id_for(&k1));
        assert_ne!(mailbox_id_for(&k1), mailbox_id_for(&k2));
        assert_ne!(mailbox_id_for(&k1), *blake3::hash(&k1).as_bytes());
    }

    #[test]
    fn fetch_batch_honours_byte_budget_and_reports_more() {
        let mut mb = Mailbox::with_defaults();
        for _ in 0..4 {
            mb.deposit(id(1), vec![0u8; 100], 0, HOUR).unwrap();
        }
        let (batch, more) = mb.fetch_batch(&id(1), 0, 250);
        assert_eq!(batch.len(), 2, "250B budget fits two 100B msgs, not three");
        assert!(more, "two of four remain");
        assert_eq!(mb.total(), 2);
        let (batch2, more2) = mb.fetch_batch(&id(1), 0, 250);
        assert_eq!(batch2.len(), 2);
        assert!(!more2);
        assert_eq!(mb.total(), 0);
        assert_eq!(mb.mailbox_count(), 0);
    }

    #[test]
    fn fetch_batch_always_makes_progress_on_oversized_first_message() {
        let mut mb = Mailbox::with_defaults();
        mb.deposit(id(1), vec![0u8; 5000], 0, HOUR).unwrap();
        let (batch, more) = mb.fetch_batch(&id(1), 0, 10);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].len(), 5000);
        assert!(!more);
        assert_eq!(mb.total(), 0);
        assert_eq!(mb.total_bytes(), 0, "byte accounting follows the drain");
    }

    #[test]
    fn a_flooder_cannot_exceed_the_global_byte_ceiling() {
        let policy = MailboxPolicy {
            max_total_bytes: 10_000,
            max_msg_bytes: 4_000,
            max_msgs_per_mailbox: 1_000_000,
            max_total_msgs: 1_000_000,
            ..MailboxPolicy::default()
        };
        let mut mb = Mailbox::new(policy);
        mb.deposit(id(1), vec![0u8; 4_000], 0, HOUR).unwrap();
        mb.deposit(id(2), vec![0u8; 4_000], 0, HOUR).unwrap();
        assert_eq!(mb.total_bytes(), 8_000);
        assert_eq!(
            mb.deposit(id(3), vec![0u8; 4_000], 0, HOUR),
            Err(DepositError::StoreFull),
            "the byte ceiling must refuse the deposit that would cross it"
        );
        mb.deposit(id(3), vec![0u8; 2_000], 0, HOUR).unwrap();
        assert_eq!(mb.total_bytes(), 10_000);
        assert_eq!(mb.total(), 3);

        let (batch, _) = mb.fetch_batch(&id(1), 0, usize::MAX);
        assert_eq!(batch.len(), 1);
        assert_eq!(mb.total_bytes(), 6_000);
        mb.deposit(id(4), vec![0u8; 4_000], 0, HOUR).unwrap();
    }

    #[test]
    fn byte_accounting_stays_exact_across_expiry_prune_and_fetch() {
        let mut mb = Mailbox::with_defaults();
        mb.deposit(id(1), vec![0u8; 100], 0, 10).unwrap();
        mb.deposit(id(1), vec![0u8; 250], 0, HOUR).unwrap();
        mb.deposit(id(2), vec![0u8; 400], 0, 10).unwrap();
        assert_eq!(mb.total_bytes(), 750);

        assert_eq!(mb.prune_expired(20), 2);
        assert_eq!(mb.total_bytes(), 250);
        assert_eq!(mb.total(), 1);

        assert_eq!(mb.fetch(&id(1), 20).len(), 1);
        assert_eq!(mb.total_bytes(), 0);
        assert_eq!(mb.total(), 0);

        mb.deposit(id(5), vec![0u8; 333], 0, HOUR).unwrap();
        let restored = Mailbox::from_snapshot(MailboxPolicy::default(), mb.snapshot(), 0);
        assert_eq!(restored.total_bytes(), 333);
    }

    #[test]
    fn fetch_batch_skips_expired_and_unknown_is_empty() {
        let mut mb = Mailbox::with_defaults();
        mb.deposit(id(1), b"old".to_vec(), 0, HOUR).unwrap();
        mb.deposit(id(1), b"fresh".to_vec(), 0, 10 * HOUR).unwrap();
        let (batch, more) = mb.fetch_batch(&id(1), 2 * HOUR, MAX_MAILBOX_FRAME);
        assert_eq!(batch, vec![b"fresh".to_vec()]);
        assert!(!more);
        assert_eq!(mb.total(), 0);
        assert_eq!(mb.fetch_batch(&id(2), 0, 1024), (Vec::new(), false));
    }

    #[test]
    fn wire_requests_and_responses_round_trip() {
        let reqs = [
            MailboxRequest::Deposit {
                id: id(1),
                sealed: vec![1, 2, 3, 4],
                ttl_secs: 3600,
            },
            MailboxRequest::Fetch {
                id: id(2),
                auth: None,
            },
        ];
        for r in &reqs {
            let bytes = r.to_bytes().unwrap();
            assert_eq!(&MailboxRequest::from_bytes(&bytes).unwrap(), r);
        }
        let resps = [
            MailboxResponse::Ack,
            MailboxResponse::Delivery {
                sealed: vec![vec![9, 9], vec![8]],
                more: true,
            },
            MailboxResponse::Error(MailboxWireError::StoreFull),
        ];
        for r in &resps {
            let bytes = r.to_bytes().unwrap();
            assert_eq!(&MailboxResponse::from_bytes(&bytes).unwrap(), r);
        }
    }

    #[test]
    fn snapshot_round_trips_and_drops_expired_on_restore() {
        let mut mb = Mailbox::with_defaults();
        mb.deposit(id(1), b"keep".to_vec(), 0, 10 * HOUR).unwrap();
        mb.deposit(id(1), b"stale".to_vec(), 0, HOUR).unwrap();
        mb.deposit(id(2), b"other".to_vec(), 0, 10 * HOUR).unwrap();

        let snap = mb.snapshot();
        let bytes = rmp_serde::to_vec_named(&snap).unwrap();
        let restored: MailboxSnapshot = rmp_serde::from_slice(&bytes).unwrap();
        let mb2 = Mailbox::from_snapshot(MailboxPolicy::default(), restored, 2 * HOUR);

        assert_eq!(mb2.total(), 2, "the stale entry is dropped on restore");
        assert_eq!(mb2.pending(&id(1), 2 * HOUR), 1);
        assert_eq!(mb2.pending(&id(2), 2 * HOUR), 1);
    }

    #[test]
    fn the_rendezvous_score_moves_with_the_epoch() {
        let victim = [0x11u8; 32];
        let hosts: Vec<[u8; 32]> = (0..8u8).map(|i| [i; 32]).collect();

        let winner_at = |epoch: u64| -> usize {
            hosts
                .iter()
                .enumerate()
                .max_by_key(|(_, h)| mailbox_host_score_at(epoch, &victim, h.as_slice()))
                .map(|(i, _)| i)
                .unwrap()
        };

        assert_eq!(winner_at(100), winner_at(100));

        let winners: std::collections::HashSet<usize> = (0..200).map(winner_at).collect();
        assert!(
            winners.len() > 1,
            "the host must not be fixed for the life of a key"
        );

        assert_ne!(
            mailbox_host_score_at(1, &victim, b"host"),
            mailbox_host_score_at(2, &victim, b"host"),
        );
        assert_ne!(
            mailbox_host_score_at(1, &victim, b"host"),
            mailbox_host_score_at(1, &[0x22u8; 32], b"host"),
        );
        assert_ne!(
            mailbox_host_score_at(0, &victim, b"host").to_vec(),
            mailbox_host_score(&victim, b"host").to_vec(),
        );
    }

    #[test]
    fn the_epoch_comes_from_the_signed_validity_stamp() {
        assert_eq!(mailbox_epoch_of(0), 0);
        assert_eq!(mailbox_epoch_of(MAILBOX_EPOCH_SECS - 1), 0);
        assert_eq!(mailbox_epoch_of(MAILBOX_EPOCH_SECS), 1);
        let valid_after = 1_757_000_000u64;
        assert_eq!(mailbox_epoch_of(valid_after), mailbox_epoch_of(valid_after));
    }
}

#[cfg(test)]
mod relay_epoch_window_tests {
    use super::*;

    const DAY: u64 = MAILBOX_EPOCH_SECS;
    const HOUR: u64 = 3600;
    const NOW: u64 = 20_000 * DAY + 12 * HOUR;

    fn proof_for(pk: [u8; 32], id: &MailboxId) -> (FetchAuth, [u8; 32], &'static [u8]) {
        let shared = [0x5Au8; 32];
        let binding: &[u8] = b"noise handshake hash";
        let auth = FetchAuth {
            pk,
            tag: fetch_auth_tag(&shared, binding, id),
        };
        (auth, shared, binding)
    }

    #[test]
    fn the_epoch_address_is_domain_key_then_big_endian_epoch() {
        let pk = [0x11u8; 32];
        let mut h = blake3::Hasher::new();
        h.update(b"gotham-mailbox-id-v1");
        h.update(&pk);
        h.update(&7u64.to_be_bytes());
        assert_eq!(mailbox_id_for_epoch(&pk, 7), *h.finalize().as_bytes());
        assert_ne!(mailbox_id_for_epoch(&pk, 7), mailbox_id_legacy(&pk));
    }

    #[test]
    fn a_proof_for_the_epoch_address_a_client_reads_is_accepted() {
        let pk = [7u8; 32];
        for id in mailbox_ids_to_read(&pk, NOW) {
            let (auth, shared, binding) = proof_for(pk, &id);
            assert!(auth.verify_at(&shared, binding, &id, NOW));
        }
        let deposit = mailbox_id_for_deposit(&pk, NOW);
        let (auth, shared, binding) = proof_for(pk, &deposit);
        assert!(auth.verify_at(&shared, binding, &deposit, NOW));
    }

    #[test]
    fn verify_with_the_real_clock_accepts_todays_address() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let pk = [8u8; 32];
        let id = mailbox_id_for_deposit(&pk, now);
        let (auth, shared, binding) = proof_for(pk, &id);
        assert!(auth.verify(&shared, binding, &id));
    }

    #[test]
    fn the_legacy_address_is_still_served() {
        let pk = [9u8; 32];
        let id = mailbox_id_legacy(&pk);
        let (auth, shared, binding) = proof_for(pk, &id);
        assert!(auth.verify_at(&shared, binding, &id, NOW));
        assert!(auth.verify_at(&shared, binding, &id, 0));
    }

    #[test]
    fn every_directory_a_client_may_hold_is_covered() {
        let pk = [3u8; 32];
        for relay_now in [
            NOW,
            20_001 * DAY,
            20_001 * DAY + 5 * 60,
            20_001 * DAY + 2 * HOUR,
        ] {
            for age in [0, 30 * 60, HOUR, 2 * HOUR, 3 * HOUR] {
                let valid_after = relay_now - age;
                for id in mailbox_ids_to_read(&pk, valid_after) {
                    assert!(
                        mailbox_id_owned_at(&pk, &id, relay_now),
                        "relay at {relay_now} refused a read for a document {age}s old",
                    );
                }
            }
        }
    }

    #[test]
    fn a_relay_clock_behind_the_authority_still_serves() {
        let pk = [4u8; 32];
        let authority_signed = 20_001 * DAY + 60;
        let relay_now = 20_001 * DAY - 10 * 60;
        for id in mailbox_ids_to_read(&pk, authority_signed) {
            assert!(mailbox_id_owned_at(&pk, &id, relay_now));
        }
    }

    #[test]
    fn another_keys_epoch_address_is_refused() {
        let victim = [1u8; 32];
        let attacker = [2u8; 32];
        let victims = mailbox_id_for_deposit(&victim, NOW);
        assert!(!mailbox_id_owned_at(&attacker, &victims, NOW));
        let (auth, shared, binding) = proof_for(attacker, &victims);
        assert!(!auth.verify_at(&shared, binding, &victims, NOW));
    }

    #[test]
    fn the_window_is_bounded() {
        let pk = [5u8; 32];
        let cur = mailbox_epoch_of(NOW);
        for e in cur - FETCH_EPOCHS_BEHIND..=cur + FETCH_EPOCHS_AHEAD {
            assert!(mailbox_id_owned_at(&pk, &mailbox_id_for_epoch(&pk, e), NOW));
        }
        let too_old = mailbox_id_for_epoch(&pk, cur - FETCH_EPOCHS_BEHIND - 1);
        let too_new = mailbox_id_for_epoch(&pk, cur + FETCH_EPOCHS_AHEAD + 1);
        assert!(!mailbox_id_owned_at(&pk, &too_old, NOW));
        assert!(!mailbox_id_owned_at(&pk, &too_new, NOW));
    }

    #[test]
    fn mail_alive_on_the_relay_stays_fetchable_by_its_owner() {
        let pk = [7u8; 32];
        let deposited_at = NOW;
        let id = mailbox_id_for_deposit(&pk, deposited_at - DAY);
        for now in [
            deposited_at,
            deposited_at + 7 * DAY,
            deposited_at + DEFAULT_MAX_TTL_SECS,
        ] {
            assert!(mailbox_id_owned_at(&pk, &id, now));
        }
    }

    #[test]
    fn a_tag_for_one_owned_address_does_not_open_another() {
        let pk = [6u8; 32];
        let [current, previous] = mailbox_ids_to_read(&pk, NOW);
        let (auth, shared, binding) = proof_for(pk, &current);
        assert!(auth.verify_at(&shared, binding, &current, NOW));
        assert!(!auth.verify_at(&shared, binding, &previous, NOW));
    }
}

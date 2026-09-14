// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

//! Bounded LRU + TTL replay cache.
//!
//! Each entry is keyed by the packet's `γ` MAC (16 B). Inserts return
//! [`ReplayCheck::Replay`] if the key was already present; otherwise the
//! key is recorded and [`ReplayCheck::Fresh`] is returned.
//!
//! TTL eviction is amortised: every insert sweeps expired entries from
//! the FIFO head. Hot path remains O(1) amortised. The hard `max_size`
//! cap is enforced via FIFO eviction of the oldest entry when full.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Outcome of a [`ReplayCache::check_and_insert`].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ReplayCheck {
    /// Key was not in the cache. It has now been inserted.
    Fresh,
    /// Key was already in the cache — the packet is a replay and must be
    /// dropped silently.
    Replay,
}

/// Bounded LRU + TTL cache of `γ` MACs.
pub struct ReplayCache {
    map: HashMap<[u8; 16], Instant>,
    queue: VecDeque<([u8; 16], Instant)>,
    ttl: Duration,
    max_size: usize,
}

impl ReplayCache {
    /// Create a new cache with at most `max_size` entries and per-entry
    /// `ttl`. Recommended defaults: `max_size = 1_000_000`, `ttl = 5 min`.
    #[must_use]
    pub fn new(max_size: usize, ttl: Duration) -> Self {
        Self {
            map: HashMap::with_capacity(max_size / 8),
            queue: VecDeque::with_capacity(max_size / 8),
            ttl,
            max_size,
        }
    }

    /// Sweep expired entries from the FIFO head until the next entry is
    /// younger than `ttl`.
    fn sweep_expired(&mut self, now: Instant) {
        while let Some(&(_, ts)) = self.queue.front() {
            if now.duration_since(ts) > self.ttl {
                if let Some((k, _)) = self.queue.pop_front() {
                    self.map.remove(&k);
                }
            } else {
                break;
            }
        }
    }

    /// Test-friendly variant of [`Self::check_and_insert`] taking an
    /// explicit `now`. Production callers should use the convenience
    /// wrapper.
    pub fn check_and_insert_at(&mut self, key: [u8; 16], now: Instant) -> ReplayCheck {
        self.sweep_expired(now);
        if self.map.contains_key(&key) {
            return ReplayCheck::Replay;
        }
        // Enforce the hard cap by evicting the oldest entry if full.
        if self.map.len() >= self.max_size {
            if let Some((old_k, _)) = self.queue.pop_front() {
                self.map.remove(&old_k);
            }
        }
        self.map.insert(key, now);
        self.queue.push_back((key, now));
        ReplayCheck::Fresh
    }

    /// Check whether `key` is a replay. If not, record it and return
    /// [`ReplayCheck::Fresh`].
    pub fn check_and_insert(&mut self, key: [u8; 16]) -> ReplayCheck {
        self.check_and_insert_at(key, Instant::now())
    }

    /// Export live entries as `(γ, unix seconds)` pairs, newest last.
    ///
    /// F-25 — the cache was RAM-only, so a relay restart forgot every γ it had
    /// seen and the replay window reopened to its full width. An attacker does
    /// not even need to cause the restart: relays restart on their own, for
    /// upgrades, for reboots, for a crash. "Replay detection, except after a
    /// restart" is not replay detection.
    ///
    /// `Instant` is monotonic and has no meaning across processes, so the
    /// snapshot converts to wall-clock seconds against the `(now, now_unix)`
    /// pair the caller supplies.
    #[must_use]
    pub fn snapshot_at(&self, now: Instant, now_unix: u64) -> Vec<([u8; 16], u64)> {
        self.queue
            .iter()
            .filter(|(_, ts)| now.duration_since(*ts) <= self.ttl)
            .map(|(k, ts)| {
                let age = now.duration_since(*ts).as_secs();
                (*k, now_unix.saturating_sub(age))
            })
            .collect()
    }

    /// Encode live entries directly into one buffer: `MAGIC` then
    /// `(γ:16, unix_secs:8)` big-endian records, oldest first.
    ///
    /// The single-allocation twin of [`Self::snapshot_at`]. `snapshot_at`
    /// stays for the tests, which want the pairs; the relay wants the bytes
    /// and takes this, because it builds them under the lock the packet path
    /// shares.
    #[must_use]
    pub fn encode_into(&self, now: Instant, now_unix: u64, magic: &[u8], record: usize) -> Vec<u8> {
        let mut buf = Vec::with_capacity(magic.len() + self.queue.len() * record);
        buf.extend_from_slice(magic);
        for (key, ts) in &self.queue {
            let elapsed = now.duration_since(*ts);
            if elapsed > self.ttl {
                continue;
            }
            buf.extend_from_slice(key);
            buf.extend_from_slice(&now_unix.saturating_sub(elapsed.as_secs()).to_be_bytes());
        }
        buf
    }

    /// Reload a snapshot, dropping entries already older than the TTL.
    ///
    /// Returns how many were adopted. Entries are inserted oldest-first so the
    /// FIFO stays ordered; a snapshot from a clock that has since gone
    /// BACKWARDS yields entries that look like the future, and those are kept
    /// at full TTL rather than discarded — erring toward remembering too long,
    /// which costs a little memory, instead of too briefly, which costs the
    /// property.
    ///
    /// When the snapshot holds more live entries than `max_size` (an operator
    /// lowered `--replay-size`, or a state directory was copied from a bigger
    /// relay), the NEWEST entries win. The first version of this kept the
    /// oldest — the ones about to expire anyway — and dropped the freshest,
    /// which is exactly backwards: a replay attacker retransmits a packet
    /// captured moments ago, not one at the end of its window.
    pub fn restore_at(
        &mut self,
        entries: &[([u8; 16], u64)],
        now: Instant,
        now_unix: u64,
    ) -> usize {
        let mut adopted = Vec::with_capacity(entries.len());
        for (key, ts) in entries {
            let age = Duration::from_secs(now_unix.saturating_sub(*ts));
            if age > self.ttl {
                continue;
            }
            // `checked_sub` because `now - age` may predate this process's
            // start, which `Instant` arithmetic is not required to represent.
            // Falling back to `now` keeps the entry LONGER, never shorter.
            adopted.push((*key, now.checked_sub(age).unwrap_or(now)));
        }
        // Oldest first for FIFO order…
        adopted.sort_by_key(|(_, ts)| *ts);
        // …and dedup BEFORE the room arithmetic. A snapshot may name the same
        // γ twice, and one already in the cache is not a new entry either.
        // Counting those toward the skip dropped distinct fresh entries while
        // room was still free — the cap is on what we INSERT, not on what we
        // were handed.
        let mut seen: std::collections::HashSet<[u8; 16]> = std::collections::HashSet::new();
        adopted.retain(|(key, _)| !self.map.contains_key(key) && seen.insert(*key));
        // …but if there is still no room for all of them, it is the OLDEST
        // that go: a replay attacker retransmits a packet captured moments
        // ago, not one at the end of its window.
        let room = self.max_size.saturating_sub(self.map.len());
        let skip = adopted.len().saturating_sub(room);
        let mut count = 0;
        for (key, ts) in adopted.into_iter().skip(skip) {
            if self.map.len() >= self.max_size {
                break;
            }
            self.map.insert(key, ts);
            self.queue.push_back((key, ts));
            count += 1;
        }
        count
    }

    /// Current number of live entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// `true` if the cache currently holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// On-disk form of the replay cache: a length byte of version, then
/// `(γ:16, unix_secs:8)` big-endian records.
///
/// Deliberately not JSON. At a million entries this is 24 MB of fixed-width
/// records that load with one read and no parser; the same data as JSON would
/// be several times larger and would need a serde pass on every relay start.
pub mod persist {
    use super::ReplayCache;
    use std::io::Write as _;
    use std::path::Path;
    use std::time::Instant;

    const MAGIC: &[u8; 8] = b"GTHMRPL1";
    const RECORD: usize = 24;

    fn now_unix() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }

    /// Serialise the cache. In-memory only — no I/O, cheap to do under the
    /// relay's lock.
    ///
    /// Writes straight into the output buffer rather than building a
    /// `Vec<(key, ts)>` first: at a million entries that intermediate was a
    /// second 24 MB allocation, and both of them were made while holding the
    /// mutex the packet path takes.
    #[must_use]
    pub fn encode(cache: &ReplayCache) -> Vec<u8> {
        cache.encode_into(Instant::now(), now_unix(), MAGIC, RECORD)
    }

    /// Atomically write an already-encoded snapshot (temp file + rename).
    ///
    /// BLOCKING — a full cache is ~24 MB plus an fsync. Never call this from
    /// an async task while holding the relay lock; go through
    /// `spawn_blocking`. The split from `encode` exists so the lock is held
    /// only for the in-memory copy.
    ///
    /// A torn file would be worse than no file: the relay would start with a
    /// partial view of what it has seen and believe it complete.
    ///
    /// Owner-only (0600). This is the one on-disk record that packets passed
    /// and when — the relay's key file gets the same mode, and this must not
    /// be the file any local account can read.
    pub fn write_encoded(buf: &[u8], path: &Path) -> std::io::Result<usize> {
        // Two writers reach this: the periodic task (on the blocking pool) and
        // `main`'s final save at shutdown. They derive the SAME `.tmp` path, so
        // without this they interleave — one truncates the file the other is
        // writing, or renames it out from under it and the second `rename`
        // fails with ENOENT. The loser is usually the shutdown save, which is
        // the one that matters most. Serialise them; the lock is held for one
        // write and the contention window is once a minute.
        static WRITE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        // A poisoned lock means a previous writer panicked mid-write. The file
        // is then stale or partial, not corrupt-in-place (the rename is
        // atomic), so writing over it is exactly the right recovery.
        let _guard = WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let tmp = path.with_extension("tmp");
        {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                opts.mode(0o600);
            }
            let mut f = opts.open(&tmp)?;
            // `mode` applies only when the file is CREATED. A `.tmp` left
            // behind by a crash between create and rename keeps whatever mode
            // it had, so set it explicitly as well.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }
            f.write_all(buf)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(buf.len().saturating_sub(MAGIC.len()) / RECORD)
    }

    /// `encode` then `write_encoded`, for synchronous callers (tests, and the
    /// final save at shutdown where blocking is the point).
    pub fn save(cache: &ReplayCache, path: &Path) -> std::io::Result<usize> {
        write_encoded(&encode(cache), path)
    }

    /// Load `path` into the cache. A missing file is not an error — that is
    /// simply the first run. A corrupt one is reported, and the relay starts
    /// with an empty cache rather than a half-trusted one.
    pub fn load(cache: &mut ReplayCache, path: &Path) -> std::io::Result<usize> {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e),
        };
        if bytes.len() < MAGIC.len() || &bytes[..MAGIC.len()] != MAGIC {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "replay cache: bad magic",
            ));
        }
        let body = &bytes[MAGIC.len()..];
        if body.len() % RECORD != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "replay cache: truncated record",
            ));
        }
        // `as_chunks` rather than `chunks_exact`: the length is a constant, so
        // the compiler gets fixed-size arrays instead of slices it must
        // bounds-check. The remainder is provably empty — checked above.
        let entries: Vec<([u8; 16], u64)> = body
            .as_chunks::<RECORD>()
            .0
            .iter()
            .map(|c| {
                let mut key = [0u8; 16];
                key.copy_from_slice(&c[..16]);
                let mut ts = [0u8; 8];
                ts.copy_from_slice(&c[16..]);
                (key, u64::from_be_bytes(ts))
            })
            .collect();
        Ok(cache.restore_at(&entries, Instant::now(), now_unix()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(byte: u8) -> [u8; 16] {
        [byte; 16]
    }

    #[test]
    fn fresh_then_replay() {
        let mut cache = ReplayCache::new(100, Duration::from_secs(60));
        let key = k(1);
        assert_eq!(cache.check_and_insert(key), ReplayCheck::Fresh);
        assert_eq!(cache.check_and_insert(key), ReplayCheck::Replay);
        assert_eq!(cache.check_and_insert(key), ReplayCheck::Replay);
    }

    #[test]
    fn different_keys_independent() {
        let mut cache = ReplayCache::new(100, Duration::from_secs(60));
        for i in 0..50u8 {
            assert_eq!(cache.check_and_insert(k(i)), ReplayCheck::Fresh);
        }
        for i in 0..50u8 {
            assert_eq!(cache.check_and_insert(k(i)), ReplayCheck::Replay);
        }
    }

    #[test]
    fn ttl_eviction() {
        let mut cache = ReplayCache::new(100, Duration::from_secs(1));
        let now = Instant::now();
        assert_eq!(cache.check_and_insert_at(k(1), now), ReplayCheck::Fresh);
        // 0.5 s later: still in cache.
        let later = now + Duration::from_millis(500);
        assert_eq!(cache.check_and_insert_at(k(1), later), ReplayCheck::Replay);
        // 2 s later: TTL expired, entry evicted, fresh again.
        let much_later = now + Duration::from_secs(2);
        assert_eq!(
            cache.check_and_insert_at(k(1), much_later),
            ReplayCheck::Fresh
        );
    }

    #[test]
    fn capacity_enforced_via_fifo_eviction() {
        let mut cache = ReplayCache::new(3, Duration::from_secs(3600));
        let now = Instant::now();
        cache.check_and_insert_at(k(1), now);
        cache.check_and_insert_at(k(2), now);
        cache.check_and_insert_at(k(3), now);
        assert_eq!(cache.len(), 3);
        // Inserting a 4th evicts the oldest (k(1)).
        cache.check_and_insert_at(k(4), now);
        assert_eq!(cache.len(), 3);
        // k(2), k(3), k(4) are still in the cache (we check k(1) last so
        // the act of testing replay status doesn't mutate it).
        assert_eq!(cache.check_and_insert_at(k(2), now), ReplayCheck::Replay);
        assert_eq!(cache.check_and_insert_at(k(3), now), ReplayCheck::Replay);
        assert_eq!(cache.check_and_insert_at(k(4), now), ReplayCheck::Replay);
        // k(1) was evicted at step 4 — re-insertion is Fresh (and would
        // itself evict k(2), but we don't probe further here).
        assert_eq!(cache.check_and_insert_at(k(1), now), ReplayCheck::Fresh);
    }

    #[test]
    fn empty_cache_is_empty() {
        let cache = ReplayCache::new(10, Duration::from_secs(60));
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }
}

/// F-25 — replay detection must survive a restart.
#[cfg(test)]
mod persistence_tests {
    use super::*;

    fn k(byte: u8) -> [u8; 16] {
        [byte; 16]
    }

    /// The finding in one test: a relay that restarts used to forget every γ it
    /// had seen, so a captured packet replayed straight after a restart was
    /// accepted as fresh — a confirmation attack for the price of waiting for
    /// an upgrade window.
    #[test]
    fn a_restart_does_not_forget_what_was_seen() {
        let dir = std::env::temp_dir().join("gotham-replay-restart-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("replay.bin");
        let _ = std::fs::remove_file(&path);

        let mut before = ReplayCache::new(1000, Duration::from_secs(300));
        assert_eq!(before.check_and_insert(k(1)), ReplayCheck::Fresh);
        assert_eq!(before.check_and_insert(k(2)), ReplayCheck::Fresh);
        let written = persist::save(&before, &path).expect("save");
        assert_eq!(written, 2);

        // The process dies here. A brand-new cache is all the relay has.
        let mut after = ReplayCache::new(1000, Duration::from_secs(300));
        assert_eq!(after.check_and_insert(k(1)), ReplayCheck::Fresh);

        let mut restored = ReplayCache::new(1000, Duration::from_secs(300));
        let loaded = persist::load(&mut restored, &path).expect("load");
        assert_eq!(loaded, 2);
        assert_eq!(
            restored.check_and_insert(k(1)),
            ReplayCheck::Replay,
            "a γ seen before the restart is still a replay after it",
        );
        assert_eq!(restored.check_and_insert(k(2)), ReplayCheck::Replay);
        assert_eq!(restored.check_and_insert(k(3)), ReplayCheck::Fresh);

        let _ = std::fs::remove_file(&path);
    }

    /// The TTL still applies across the restart — a snapshot is not a way to
    /// smuggle expired entries back in and grow the cache without bound.
    #[test]
    fn entries_older_than_the_ttl_are_not_restored() {
        let mut cache = ReplayCache::new(1000, Duration::from_secs(60));
        let now = Instant::now();
        let now_unix = 1_000_000u64;

        let entries = [
            (k(1), now_unix - 10),  // 10 s old: still live
            (k(2), now_unix - 600), // 10 min old: gone
        ];
        let adopted = cache.restore_at(&entries, now, now_unix);

        assert_eq!(adopted, 1, "only the live entry comes back");
        assert_eq!(cache.check_and_insert_at(k(1), now), ReplayCheck::Replay);
        assert_eq!(cache.check_and_insert_at(k(2), now), ReplayCheck::Fresh);
    }

    /// A truncated or foreign file must not be read as a partial cache — the
    /// relay would then believe it remembers more than it does. Fail loudly and
    /// start empty instead.
    #[test]
    fn a_corrupt_snapshot_is_refused_rather_than_half_read() {
        let dir = std::env::temp_dir().join("gotham-replay-corrupt-test");
        std::fs::create_dir_all(&dir).unwrap();

        let bad_magic = dir.join("bad-magic.bin");
        std::fs::write(&bad_magic, b"NOTGOTHAMxxxxxxx").unwrap();
        let mut c1 = ReplayCache::new(10, Duration::from_secs(60));
        assert!(persist::load(&mut c1, &bad_magic).is_err());
        assert!(c1.is_empty());

        let truncated = dir.join("truncated.bin");
        std::fs::write(&truncated, b"GTHMRPL1\x01\x02\x03").unwrap();
        let mut c2 = ReplayCache::new(10, Duration::from_secs(60));
        assert!(persist::load(&mut c2, &truncated).is_err());
        assert!(c2.is_empty());

        // A missing file is the first run, not a failure.
        let mut c3 = ReplayCache::new(10, Duration::from_secs(60));
        assert_eq!(
            persist::load(&mut c3, &dir.join("does-not-exist.bin")).unwrap(),
            0,
        );

        let _ = std::fs::remove_file(&bad_magic);
        let _ = std::fs::remove_file(&truncated);
    }
}

/// The three defects the adversarial review found in the first version.
#[cfg(test)]
mod persistence_review_tests {
    use super::*;

    fn k(i: u32) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[..4].copy_from_slice(&i.to_be_bytes());
        b
    }

    /// When the snapshot does not fit, the FRESHEST entries must survive. The
    /// first version kept the oldest — the ones about to age out anyway — and
    /// a packet captured seconds before the restart came back as Fresh.
    #[test]
    fn an_oversized_snapshot_keeps_the_newest_entries() {
        let mut cache = ReplayCache::new(1000, Duration::from_secs(300));
        let now = Instant::now();
        let now_unix = 1_000_000u64;
        // 2000 live entries, ages 100 s … 299 s. Entry i was seen (299 - i/10) s ago.
        let entries: Vec<_> = (0..2000u32)
            .map(|i| (k(i), now_unix - 299 + u64::from(i) / 10))
            .collect();

        let adopted = cache.restore_at(&entries, now, now_unix);
        assert_eq!(adopted, 1000);

        assert_eq!(
            cache.check_and_insert_at(k(1999), now),
            ReplayCheck::Replay,
            "the freshest entry (100 s old, 200 s of protection left) must be kept",
        );
        assert_eq!(
            cache.check_and_insert_at(k(0), now),
            ReplayCheck::Fresh,
            "the oldest (299 s old, 1 s left) is the one to let go",
        );
    }

    /// The snapshot records that packets passed, and when. It must not be the
    /// one file in the state directory any local account can read.
    #[cfg(unix)]
    #[test]
    fn the_snapshot_is_owner_only_even_after_a_second_save() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join("gotham-replay-mode-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("replay.bin");
        let _ = std::fs::remove_file(&path);

        let mut cache = ReplayCache::new(10, Duration::from_secs(60));
        cache.check_and_insert(k(1));
        persist::save(&cache, &path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
        );
        // The rename replaces the inode: the mode must hold on the SECOND
        // write too, which is the case a create-time-only mode gets wrong.
        cache.check_and_insert(k(2));
        persist::save(&cache, &path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
        );
        let _ = std::fs::remove_file(&path);
    }

    /// `encode` must not touch the disk — it is the half that runs under the
    /// relay lock, on the packet path.
    #[test]
    fn encode_then_write_round_trips() {
        let dir = std::env::temp_dir().join("gotham-replay-split-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("replay.bin");
        let _ = std::fs::remove_file(&path);

        let mut cache = ReplayCache::new(10, Duration::from_secs(60));
        cache.check_and_insert(k(7));
        let buf = persist::encode(&cache);
        assert!(!path.exists(), "encode is in-memory only");
        assert_eq!(persist::write_encoded(&buf, &path).unwrap(), 1);

        let mut back = ReplayCache::new(10, Duration::from_secs(60));
        assert_eq!(persist::load(&mut back, &path).unwrap(), 1);
        assert_eq!(back.check_and_insert(k(7)), ReplayCheck::Replay);
        let _ = std::fs::remove_file(&path);
    }
}

/// The second adversarial pass, on the fixes from the first.
#[cfg(test)]
mod persistence_second_pass_tests {
    use super::*;

    fn k(i: u32) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[..4].copy_from_slice(&i.to_be_bytes());
        b
    }

    /// Duplicates in the snapshot must not eat the budget. They used to count
    /// toward the skip, so a snapshot naming the same γ twice silently dropped
    /// distinct fresh entries while room was still free.
    #[test]
    fn duplicates_do_not_displace_distinct_entries() {
        let mut cache = ReplayCache::new(3, Duration::from_secs(300));
        let now = Instant::now();
        let now_unix = 1_000_000u64;

        // Five records, three DISTINCT keys: 1 (×3), 2, 3. All fit in a cap of 3.
        let entries = [
            (k(1), now_unix - 50),
            (k(1), now_unix - 40),
            (k(1), now_unix - 30),
            (k(2), now_unix - 20),
            (k(3), now_unix - 10),
        ];
        assert_eq!(cache.restore_at(&entries, now, now_unix), 3);

        for i in 1..=3u32 {
            assert_eq!(
                cache.check_and_insert_at(k(i), now),
                ReplayCheck::Replay,
                "key {i} must have been adopted",
            );
        }
    }

    /// An entry already live in the cache is not a new one either, and must
    /// not consume a slot from the snapshot's budget.
    #[test]
    fn entries_already_present_do_not_consume_the_budget() {
        let mut cache = ReplayCache::new(2, Duration::from_secs(300));
        let now = Instant::now();
        let now_unix = 1_000_000u64;
        assert_eq!(cache.check_and_insert_at(k(1), now), ReplayCheck::Fresh);

        // k(1) is already there; k(2) is new and there is exactly one slot.
        let entries = [(k(1), now_unix - 50), (k(2), now_unix - 10)];
        assert_eq!(cache.restore_at(&entries, now, now_unix), 1);
        assert_eq!(cache.check_and_insert_at(k(2), now), ReplayCheck::Replay);
    }

    /// `encode_into` must produce exactly what `snapshot_at` + the old manual
    /// loop produced — same entries, same order, same bytes. It replaced that
    /// loop to avoid a second 24 MB allocation under the relay lock.
    #[test]
    fn the_single_pass_encoder_matches_the_snapshot() {
        let mut cache = ReplayCache::new(100, Duration::from_secs(300));
        let now = Instant::now();
        let now_unix = 1_000_000u64;
        for i in 0..20u32 {
            cache.check_and_insert_at(k(i), now);
        }

        let via_snapshot: Vec<u8> = {
            let entries = cache.snapshot_at(now, now_unix);
            let mut buf = Vec::new();
            buf.extend_from_slice(b"GTHMRPL1");
            for (key, ts) in &entries {
                buf.extend_from_slice(key);
                buf.extend_from_slice(&ts.to_be_bytes());
            }
            buf
        };
        assert_eq!(
            cache.encode_into(now, now_unix, b"GTHMRPL1", 24),
            via_snapshot
        );
    }

    /// Both writers derive the same `.tmp` path. Hammering them concurrently
    /// must never leave a truncated or missing file — before the write lock,
    /// one truncated what the other was writing, or renamed it away and the
    /// second `rename` failed with ENOENT.
    #[test]
    fn concurrent_writers_never_tear_the_snapshot() {
        let dir = std::env::temp_dir().join("gotham-replay-concurrent-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("replay.bin");
        let _ = std::fs::remove_file(&path);

        let mut cache = ReplayCache::new(5000, Duration::from_secs(300));
        for i in 0..5000u32 {
            cache.check_and_insert(k(i));
        }
        let buf = std::sync::Arc::new(persist::encode(&cache));
        let expected = buf.len();

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let buf = std::sync::Arc::clone(&buf);
                let path = path.clone();
                std::thread::spawn(move || {
                    for _ in 0..10 {
                        persist::write_encoded(&buf, &path).expect("a write must not fail");
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(
            std::fs::metadata(&path).unwrap().len() as usize,
            expected,
            "the file must be whole, never a partial write",
        );
        let mut back = ReplayCache::new(5000, Duration::from_secs(300));
        assert_eq!(persist::load(&mut back, &path).unwrap(), 5000);
        let _ = std::fs::remove_file(&path);
    }
}

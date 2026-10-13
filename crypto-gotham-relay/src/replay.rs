// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ReplayCheck {
    Fresh,
    Replay,
}

pub struct ReplayCache {
    map: HashMap<[u8; 16], Instant>,
    queue: VecDeque<([u8; 16], Instant)>,
    ttl: Duration,
    max_size: usize,
}

impl ReplayCache {
    #[must_use]
    pub fn new(max_size: usize, ttl: Duration) -> Self {
        Self {
            map: HashMap::with_capacity(max_size / 8),
            queue: VecDeque::with_capacity(max_size / 8),
            ttl,
            max_size,
        }
    }

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

    pub fn check_and_insert_at(&mut self, key: [u8; 16], now: Instant) -> ReplayCheck {
        self.sweep_expired(now);
        if self.map.contains_key(&key) {
            return ReplayCheck::Replay;
        }
        if self.map.len() >= self.max_size {
            if let Some((old_k, _)) = self.queue.pop_front() {
                self.map.remove(&old_k);
            }
        }
        self.map.insert(key, now);
        self.queue.push_back((key, now));
        ReplayCheck::Fresh
    }

    pub fn check_and_insert(&mut self, key: [u8; 16]) -> ReplayCheck {
        self.check_and_insert_at(key, Instant::now())
    }

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
            adopted.push((*key, now.checked_sub(age).unwrap_or(now)));
        }
        adopted.sort_by_key(|(_, ts)| *ts);
        let mut seen: std::collections::HashSet<[u8; 16]> = std::collections::HashSet::new();
        adopted.retain(|(key, _)| !self.map.contains_key(key) && seen.insert(*key));
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

    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

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

    #[must_use]
    pub fn encode(cache: &ReplayCache) -> Vec<u8> {
        cache.encode_into(Instant::now(), now_unix(), MAGIC, RECORD)
    }

    pub fn write_encoded(buf: &[u8], path: &Path) -> std::io::Result<usize> {
        static WRITE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
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

    pub fn save(cache: &ReplayCache, path: &Path) -> std::io::Result<usize> {
        write_encoded(&encode(cache), path)
    }

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
        let later = now + Duration::from_millis(500);
        assert_eq!(cache.check_and_insert_at(k(1), later), ReplayCheck::Replay);
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
        cache.check_and_insert_at(k(4), now);
        assert_eq!(cache.len(), 3);
        assert_eq!(cache.check_and_insert_at(k(2), now), ReplayCheck::Replay);
        assert_eq!(cache.check_and_insert_at(k(3), now), ReplayCheck::Replay);
        assert_eq!(cache.check_and_insert_at(k(4), now), ReplayCheck::Replay);
        assert_eq!(cache.check_and_insert_at(k(1), now), ReplayCheck::Fresh);
    }

    #[test]
    fn empty_cache_is_empty() {
        let cache = ReplayCache::new(10, Duration::from_secs(60));
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }
}

#[cfg(test)]
mod persistence_tests {
    use super::*;

    fn k(byte: u8) -> [u8; 16] {
        [byte; 16]
    }

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

    #[test]
    fn entries_older_than_the_ttl_are_not_restored() {
        let mut cache = ReplayCache::new(1000, Duration::from_secs(60));
        let now = Instant::now();
        let now_unix = 1_000_000u64;

        let entries = [(k(1), now_unix - 10), (k(2), now_unix - 600)];
        let adopted = cache.restore_at(&entries, now, now_unix);

        assert_eq!(adopted, 1, "only the live entry comes back");
        assert_eq!(cache.check_and_insert_at(k(1), now), ReplayCheck::Replay);
        assert_eq!(cache.check_and_insert_at(k(2), now), ReplayCheck::Fresh);
    }

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

        let mut c3 = ReplayCache::new(10, Duration::from_secs(60));
        assert_eq!(
            persist::load(&mut c3, &dir.join("does-not-exist.bin")).unwrap(),
            0,
        );

        let _ = std::fs::remove_file(&bad_magic);
        let _ = std::fs::remove_file(&truncated);
    }
}

#[cfg(test)]
mod persistence_review_tests {
    use super::*;

    fn k(i: u32) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[..4].copy_from_slice(&i.to_be_bytes());
        b
    }

    #[test]
    fn an_oversized_snapshot_keeps_the_newest_entries() {
        let mut cache = ReplayCache::new(1000, Duration::from_secs(300));
        let now = Instant::now();
        let now_unix = 1_000_000u64;
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
        cache.check_and_insert(k(2));
        persist::save(&cache, &path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
        );
        let _ = std::fs::remove_file(&path);
    }

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

#[cfg(test)]
mod persistence_second_pass_tests {
    use super::*;

    fn k(i: u32) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[..4].copy_from_slice(&i.to_be_bytes());
        b
    }

    #[test]
    fn duplicates_do_not_displace_distinct_entries() {
        let mut cache = ReplayCache::new(3, Duration::from_secs(300));
        let now = Instant::now();
        let now_unix = 1_000_000u64;

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

    #[test]
    fn entries_already_present_do_not_consume_the_budget() {
        let mut cache = ReplayCache::new(2, Duration::from_secs(300));
        let now = Instant::now();
        let now_unix = 1_000_000u64;
        assert_eq!(cache.check_and_insert_at(k(1), now), ReplayCheck::Fresh);

        let entries = [(k(1), now_unix - 50), (k(2), now_unix - 10)];
        assert_eq!(cache.restore_at(&entries, now, now_unix), 1);
        assert_eq!(cache.check_and_insert_at(k(2), now), ReplayCheck::Replay);
    }

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

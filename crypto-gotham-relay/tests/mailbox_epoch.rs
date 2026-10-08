// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

//! NET-01 — a mailbox deposited at a per-epoch address must be fetchable.
//!
//! F-07 (2.4.0) moved every deposit to `mailbox_id_for_deposit` and every read
//! to `mailbox_ids_to_read`, while the relay's possession check still accepted
//! the permanent address alone. The deposit was acknowledged and the fetch
//! refused as `Unauthorized`, so mail between two 2.4.x clients sat on the relay
//! until it expired. The unit tests on the ownership window cannot see that; this
//! runs the real relay serve loop and the real client over QUIC + Noise, with
//! the relay's real clock, which is the configuration that failed.
//!
//! ```text
//! cargo test -p crypto-gotham-relay --test mailbox_epoch
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crypto_gotham::mailbox::{
    mailbox_id_for_deposit, mailbox_id_legacy, mailbox_ids_to_read, Mailbox, MailboxPolicy,
    MailboxWireError,
};
use crypto_gotham_relay::transport::{build_server_endpoint, serve_endpoint_with_mailbox};
use crypto_gotham_relay::{MailboxClient, MailboxClientError, Relay};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use tokio::sync::Mutex;
use x25519_dalek::{PublicKey, StaticSecret};

fn clamped_sk(rng: &mut ChaCha20Rng) -> [u8; 32] {
    let mut sk = [0u8; 32];
    rng.fill_bytes(&mut sk);
    sk[0] &= 248;
    sk[31] &= 127;
    sk[31] |= 64;
    sk
}

fn public(sk: [u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(sk)).to_bytes()
}

/// What a client would take as `valid_after`: a directory signed just now.
/// The relay under test reads the same clock, which is the deployed situation
/// when the fleet and the authority keep time.
fn freshly_signed_directory_stamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A mailbox-hosting relay on 127.0.0.1:0, served by the production loop.
async fn spawn_mailbox_relay(sk: [u8; 32]) -> (SocketAddr, [u8; 32], Arc<Mutex<Mailbox>>) {
    crypto_gotham_relay::init_crypto();
    let endpoint = build_server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let store = Arc::new(Mutex::new(Mailbox::new(MailboxPolicy::default())));
    let relay = Relay::new(sk, 1024, Duration::from_secs(60), 0);
    let served = Arc::clone(&store);
    tokio::spawn(async move {
        let _ = serve_endpoint_with_mailbox(endpoint, sk, relay, None, Some(served)).await;
    });
    (addr, public(sk), store)
}

/// The whole F-07 read set, end to end: the deposit address, both addresses a
/// recipient reads, and the permanent one it still drains.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_address_a_client_reads_is_fetchable_after_a_deposit() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x0E90_C4E1);
    let (addr, relay_pk, store) = spawn_mailbox_relay(clamped_sk(&mut rng)).await;

    let recipient_sk = clamped_sk(&mut rng);
    let recipient_pk = public(recipient_sk);
    let valid_after = freshly_signed_directory_stamp();

    let deposit_at = mailbox_id_for_deposit(&recipient_pk, valid_after);
    let [current, previous] = mailbox_ids_to_read(&recipient_pk, valid_after);
    let legacy = mailbox_id_legacy(&recipient_pk);
    assert_eq!(
        deposit_at, current,
        "a sender and its recipient holding the same directory meet at one address",
    );

    let client = MailboxClient::new(&mut rng).unwrap();
    // What a 2.4.x sender does, plus a sender one epoch behind, plus a pre-2.4
    // sender still on the permanent address.
    client
        .deposit(addr, &relay_pk, deposit_at, b"this epoch".to_vec(), 3600)
        .await
        .expect("deposit at the current epoch address");
    client
        .deposit(addr, &relay_pk, previous, b"last epoch".to_vec(), 3600)
        .await
        .expect("deposit at the previous epoch address");
    client
        .deposit(addr, &relay_pk, legacy, b"old build".to_vec(), 3600)
        .await
        .expect("deposit at the legacy address");
    assert_eq!(store.lock().await.total(), 3);

    // The recipient reads the three addresses exactly as `poll_mailbox` does.
    // Before the fix the first two came back `Unauthorized`.
    let got = client
        .fetch_all(addr, &relay_pk, current, &recipient_sk)
        .await
        .expect("fetch of the current epoch address must be authorised");
    assert_eq!(got, vec![b"this epoch".to_vec()]);
    let got = client
        .fetch_all(addr, &relay_pk, previous, &recipient_sk)
        .await
        .expect("fetch of the previous epoch address must be authorised");
    assert_eq!(got, vec![b"last epoch".to_vec()]);
    let got = client
        .fetch_all(addr, &relay_pk, legacy, &recipient_sk)
        .await
        .expect("fetch of the legacy address must stay authorised");
    assert_eq!(got, vec![b"old build".to_vec()]);

    assert_eq!(
        store.lock().await.total(),
        0,
        "nothing is left stranded on the relay",
    );
}

/// Widening what the relay accepts must not widen WHO it accepts: a key that
/// proves possession of its own secret still cannot drain another key's epoch
/// address, and the victim's mail survives the attempt.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn another_keys_epoch_address_is_refused() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x0E90_BAD0);
    let (addr, relay_pk, store) = spawn_mailbox_relay(clamped_sk(&mut rng)).await;

    let victim_sk = clamped_sk(&mut rng);
    let victim_pk = public(victim_sk);
    let attacker_sk = clamped_sk(&mut rng);
    let valid_after = freshly_signed_directory_stamp();
    let victims = mailbox_id_for_deposit(&victim_pk, valid_after);

    let client = MailboxClient::new(&mut rng).unwrap();
    client
        .deposit(addr, &relay_pk, victims, b"not yours".to_vec(), 3600)
        .await
        .expect("deposit");

    for id in mailbox_ids_to_read(&victim_pk, valid_after) {
        let err = client
            .fetch_all(addr, &relay_pk, id, &attacker_sk)
            .await
            .expect_err("a proof by another key must be refused");
        assert!(
            matches!(
                err,
                MailboxClientError::Wire(MailboxWireError::Unauthorized)
            ),
            "expected Unauthorized, got {err:?}",
        );
    }
    assert_eq!(
        store.lock().await.total(),
        1,
        "the refused fetch drained nothing"
    );

    let got = client
        .fetch_all(addr, &relay_pk, victims, &victim_sk)
        .await
        .expect("the owner still fetches");
    assert_eq!(got, vec![b"not yours".to_vec()]);
}

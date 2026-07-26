//! Send one sealed test message through a running Gotham testnet.
//!
//! Reads the relay set from a signed `directory.json` (as produced by
//! `scripts/local-testnet.sh`), builds a real Gotham client, and routes a
//! sealed packet through the tier-selected 3-hop path. Run the testnet with
//! `RUST_LOG=debug` and watch the three relay logs show the packet traverse
//! entry → mix → exit ("delivered locally" on the exit hop).
//!
//! The standalone `gotham-relay run` daemons carry no delivery handler, so
//! nothing is handed to a recipient app — the point here is to prove the
//! inter-process 3-hop route works against real, separately-running relays.
//!
//! Usage:
//!   cargo run -p crypto-gotham-relay --example testnet_send -- <directory.json>

use crypto_gotham::directory::SignedDirectory;
use crypto_gotham_relay::GothamClient;
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    crypto_gotham_relay::init_crypto();

    let path = std::env::args()
        .nth(1)
        .ok_or("usage: testnet_send <directory.json>")?;
    let raw = std::fs::read(&path)?;
    let signed = SignedDirectory::from_json(&raw).map_err(|e| format!("parse directory: {e:?}"))?;
    let relays = &signed.doc.relays;
    println!("loaded {} relays from {path}:", relays.len());
    for r in relays {
        println!("  {:?}  {}", r.tier, r.addr);
    }

    // Throwaway recipient + sender identities for the test send.
    let recipient_pk = PublicKey::from(&StaticSecret::random_from_rng(OsRng)).to_bytes();
    let sender_pk = PublicKey::from(&StaticSecret::random_from_rng(OsRng)).to_bytes();

    let body = b"hello over a real 3-process Gotham testnet".to_vec();
    let mut rng = OsRng;
    let client = GothamClient::new(&mut rng)?;
    client
        .send_sealed(&mut rng, relays, 3, &recipient_pk, &sender_pk, &body)
        .await
        .map_err(|e| format!("send_sealed: {e}"))?;

    println!(
        "send_sealed OK — the entry relay accepted the packet; check the \
         relay logs for the entry → mix → exit traversal."
    );
    Ok(())
}

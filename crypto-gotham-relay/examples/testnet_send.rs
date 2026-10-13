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

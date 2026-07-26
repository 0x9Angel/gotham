// Anti-worm fuzz on the relay DATA PLANE.
//
// The packet processor and the gossip deserializer must never panic on
// arbitrary/adversarial input — a crafted packet is at most `Drop`ped, a crafted
// gossip blob at most an `Err`. This is the core guarantee that a payload
// injected into Gotham cannot execute on, crash, or self-propagate across
// relays: relays only peel one opaque crypto layer and forward (1-in → 1-out,
// bounded to MAX_HOPS), never interpreting the payload as code.

use crypto_gotham_relay::Relay;
use proptest::prelude::*;
use std::time::Duration;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    // Full Sphinx packet processor on arbitrary 2048-byte packets.
    #[test]
    fn relay_process_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), crypto_gotham::PACKET_SIZE)
    ) {
        let mut relay = Relay::new([7u8; 32], 1024, Duration::from_secs(300), 0);
        let mut rng = rand::rngs::OsRng;
        let _ = relay.process(&mut rng, &bytes);
    }

    // Gossip roster deserializer on arbitrary peer bytes (peer entries are
    // additionally k-of-n verified before trust; this hardens the parse entry).
    #[test]
    fn gossip_roster_decode_never_panics(
        blob in proptest::collection::vec(any::<u8>(), 0..4096usize)
    ) {
        let _: Result<crypto_gotham_directory::Roster, _> = rmp_serde::from_slice(&blob);
    }
}

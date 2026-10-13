use crypto_gotham_relay::Relay;
use proptest::prelude::*;
use std::time::Duration;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn relay_process_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), crypto_gotham::PACKET_SIZE)
    ) {
        let mut relay = Relay::new([7u8; 32], 1024, Duration::from_secs(300), 0);
        let mut rng = rand::rngs::OsRng;
        let _ = relay.process(&mut rng, &bytes);
    }

    #[test]
    fn gossip_roster_decode_never_panics(
        blob in proptest::collection::vec(any::<u8>(), 0..4096usize)
    ) {
        let _: Result<crypto_gotham_directory::Roster, _> = rmp_serde::from_slice(&blob);
    }
}

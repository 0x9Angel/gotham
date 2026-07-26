// Anti-worm fuzz: the Sphinx header parser must never panic on arbitrary bytes.
//
// A crafted header returns `Err` at worst. Combined with safe Rust
// (`forbid(unsafe_code)`) and fixed-size framing, this removes the header parse
// surface as a crash/RCE vector — so a malicious packet injected into the
// network cannot corrupt memory or take over a relay through header parsing.

use crypto_gotham::header::{Header, HEADER_LEN};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn header_decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), HEADER_LEN)) {
        let mut arr = [0u8; HEADER_LEN];
        arr.copy_from_slice(&bytes);
        // The only contract: never panic. Ok(garbage) or Err are both fine.
        let _ = Header::decode(&arr);
    }
}

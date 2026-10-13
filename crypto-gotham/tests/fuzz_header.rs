use crypto_gotham::header::{Header, HEADER_LEN};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn header_decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), HEADER_LEN)) {
        let mut arr = [0u8; HEADER_LEN];
        arr.copy_from_slice(&bytes);
        let _ = Header::decode(&arr);
    }
}

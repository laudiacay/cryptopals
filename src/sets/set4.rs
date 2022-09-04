#[cfg(test)]
mod tests {
    use crate::{aes_fun, cryptopal_util};

    #[test]
    fn s4c25_break_randomaccess_readwrite() {
        let filename = "./data/25.txt";
        let lines = cryptopal_util::read_lines_from_file(filename.to_string()).unwrap();
        let bytes = cryptopal_util::b64_to_bytes(lines.join("")).unwrap();
        let ciphertext = aes_fun::challenge_25::encrypt(&bytes);
        let plaintext = aes_fun::challenge_25::attack(&ciphertext).unwrap();
        assert_eq!(plaintext, bytes)
    }

    #[test]
    fn s4c26_break_ctr_bitflipping() {

    }

    #[test]
    fn s4c27_recover_key_from_cbc_with_iv_equal_to_key() {
        unimplemented!();
    }

    #[test]
    fn s4c28_implement_sha1_mac() {
        unimplemented!();
    }

    #[test]
    fn s4c29_break_sha1_mac_using_length_extension() {
        unimplemented!();
    }

    #[test]
    fn s4c30_break_md4_mac_using_length_extension() {
        unimplemented!();
    }

    #[test]
    fn s4c31_break_hmac_sha1_with_artificial_timing_leak() {
        unimplemented!();
    }

    #[test]
    fn s4c32_break_hmac_sha1_with_less_artificial_timing_leak() {
        unimplemented!();
    }
}

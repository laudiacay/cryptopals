#[cfg(test)]
mod tests {
    use crate::{aes_fun, cryptopal_util, sha1};

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
        assert!(aes_fun::challenge_16::attack().unwrap());
    }

    #[test]
    fn s4c27_recover_key_from_cbc_with_iv_equal_to_key() {
        aes_fun::challenge_27::attack().unwrap()
    }

    #[test]
    fn s4c28_implement_sha1_mac() {
        //Write a function to authenticate a message under a secret key by using a secret-prefix MAC, which is simply:
        //
        // SHA1(key || message)
        // Verify that you cannot tamper with the message without breaking the MAC you've produced, and that you can't produce a new MAC without knowing the secret key.
        let key = b"YELLOW SUBMARINE";
        let message = b"Hello, world!";
        let mac = sha1::mac(key, message);
        let tampered_message = b"Hello, world! tampered";
        let tampered_mac = sha1::mac(key, tampered_message);
        assert_ne!(mac, tampered_mac);
        assert!(sha1::verify_mac(key, message, &mac));
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

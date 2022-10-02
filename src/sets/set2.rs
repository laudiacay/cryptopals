#[cfg(test)]
mod tests {
    pub use crate::aes_fun::{Iv, Key};
    use crate::{aes_fun, cryptopal_util, pkcs7};

    #[test]
    fn s2c9_implement_pkcs7() {
        let input = "YELLOW SUBMARINE";
        let output = "YELLOW SUBMARINE\x04\x04\x04\x04";
        let input_bytes = cryptopal_util::ascii_to_bytes(input).unwrap();
        let my_output =
            cryptopal_util::bytes_to_ascii(&pkcs7::pkcs7_pad(&input_bytes, 20)).unwrap();
        assert_eq!(my_output, output);
    }

    #[test]
    fn s2c10_implement_cbc() {
        let data = cryptopal_util::read_bytes_from_b64_file("./data/10.txt".to_string()).unwrap();
        let key = cryptopal_util::ascii_to_bytes("YELLOW SUBMARINE").unwrap();
        let iv = cryptopal_util::ascii_to_bytes(
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        )
        .unwrap();
        assert_eq!(iv.len(), 16);
        let decrypted_bytes = aes_fun::cbc::decrypt(&data, Key(&key), Iv(&iv)).unwrap();
        let my_output = cryptopal_util::bytes_to_ascii(&decrypted_bytes).unwrap();
        assert_eq!(&my_output[..33], "I'm back and I'm ringin' the bell");
        let re_encrypt = aes_fun::cbc::encrypt(&decrypted_bytes, Key(&key), Iv(&iv)).unwrap();
        assert_eq!(re_encrypt, data);
    }

    #[test]
    fn s2c11_ecb_cbc_detection_oracle() {
        for _ in 0..=30 {
            let oracle_input = [b'a'; 70];
            let (was_ecb, oracle_output) = aes_fun::challenge_11::oracle(&oracle_input);
            assert_eq!(aes_fun::ecb::is_ecb(oracle_output.as_slice()), was_ecb);
        }
    }

    #[test]
    fn s2c12_byte_at_a_time_ecb_decryption() {
        // I JUST WANT YOU ALL TO KNOW THAT I GOT THIS ON THE FIRST GODDAMN TRY!!!!!!! GET FUCKED LMAOOOOFDSAJKLFDSJAKLFJDSKLA
        let oh_my_god_i_cant_believe_i_got_this_in_one_run =
            cryptopal_util::bytes_to_ascii(&aes_fun::challenge_12::attack()).unwrap();
        assert_eq!("Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n", oh_my_god_i_cant_believe_i_got_this_in_one_run);
    }

    #[test]
    fn s2c13_ecb_cutnpaste() {
        assert!(aes_fun::challenge_13::attack().unwrap());
    }

    #[test]
    fn s2c14_byte_at_a_time_ecb_decryption_harder() {
        let whoop = cryptopal_util::bytes_to_ascii(&aes_fun::challenge_14::attack()).unwrap();
        assert_eq!("Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n", whoop);
    }

    #[test]
    fn s2c15_pkcs7_padding_validation() {
        // The string:
        //
        // "ICE ICE BABY\x04\x04\x04\x04"
        // ... has valid padding, and produces the result "ICE ICE BABY".
        //
        // The string:
        //
        // "ICE ICE BABY\x05\x05\x05\x05"
        // ... does not have valid padding, nor does:
        //
        // "ICE ICE BABY\x01\x02\x03\x04"
        assert!(pkcs7::pkcs7_unpad(
            &cryptopal_util::ascii_to_bytes("ICE ICE BABY\x04\x04\x04\x04").unwrap()
        )
        .is_ok());
        assert!(pkcs7::pkcs7_unpad(
            &cryptopal_util::ascii_to_bytes("ICE ICE BABY\x05\x05\x05\x05").unwrap()
        )
        .is_err());
        assert!(pkcs7::pkcs7_unpad(
            &cryptopal_util::ascii_to_bytes("ICE ICE BABY\x01\x02\x03\x04").unwrap()
        )
        .is_err());
    }

    #[test]
    fn s2c16_cbc_bitflipping() {
        assert!(aes_fun::challenge_16::attack().unwrap());
    }
}

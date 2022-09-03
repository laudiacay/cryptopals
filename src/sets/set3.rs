#[cfg(test)]
mod tests {
    use crate::mersenne_twister::MersenneTwister;
    use crate::{aes_fun, cryptopal_util};
    use rand_mt::Mt19937GenRand32;
    #[test]
    fn s3c17_cbc_padding_oracle() {
        unimplemented!();
    }

    #[test]
    fn s3c18_implement_ctr() {
        let encrypted = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
        let key = "YELLOW SUBMARINE";
        let encrypted_bytes = cryptopal_util::b64_to_bytes(encrypted).unwrap();
        let key_bytes = cryptopal_util::ascii_to_bytes(key).unwrap();
        let decrypted_bytes =
            aes_fun::ctr::decrypt(encrypted_bytes.as_slice(), key_bytes.as_slice(), 0).unwrap();
        // printstring
        assert_eq!(
            cryptopal_util::bytes_to_ascii(&decrypted_bytes).unwrap(),
            "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
        );
    }

    #[test]
    fn s3c19c20_break_fixednonce_ctr_statistically() {
        assert_eq!(
            "I'm rated \"R\"...this is a warning, ya better void / P".to_string(),
            cryptopal_util::bytes_to_ascii(&aes_fun::challenge_19_and_20::attack().unwrap()).unwrap()[..53]
        );
    }

    #[test]
    fn s3c21_implement_mt19937() {
        // open mersenne_test_vector.txt and read the lines
        let seed: u32 = 1131464071;
        let mut rng = MersenneTwister::new(seed);

        let mut system_rng = Mt19937GenRand32::new(seed);
        // start grabbing randomness from rng...
        for i in 0..1800 {
            println!("{}", i);
            let system_rand = system_rng.next_u32();
            let rng_rand = rng.extract_number();
            assert_eq!(system_rand, rng_rand);
        }
    }

    #[test]
    fn s3c22_crack_mt19937_seed() {
        unimplemented!();
    }

    #[test]
    fn s3c23_clone_mt19937_rng() {
        unimplemented!();
    }

    #[test]
    fn s3c24_create_mt19937_stream_cipher_and_break_it() {
        unimplemented!();
    }
}

#[cfg(test)]
mod tests {
    use crate::mersenne_twister::MersenneTwister;
    use crate::{aes_fun, cryptopal_util};
    use rand_mt::Mt19937GenRand32;
    use std::collections::HashSet;
    #[test]
    fn s3c17_cbc_padding_oracle() {
        let output_bytes = aes_fun::challenge_17::challenge_17_attack().unwrap();
        let output_string = cryptopal_util::bytes_to_ascii(&output_bytes).unwrap();
        println!("{}", output_string);
        let mut outputs: HashSet<String> = HashSet::new();
        outputs.insert("000000Now that the party is jumping".to_string());
        outputs.insert("000001With the bass kicked in and the Vega's are pumpin'".to_string());
        outputs.insert("000002Quick to the point, to the point, no faking".to_string());
        outputs.insert("000003Cooking MC's like a pound of bacon".to_string());
        outputs.insert("000004Burning 'em, if you ain't quick and nimble".to_string());
        outputs.insert("000005I go crazy when I hear a cymbal".to_string());
        outputs.insert("000006And a high hat with a souped up tempo".to_string());
        outputs.insert("000007I'm on a roll, it's time to go solo".to_string());
        outputs.insert("000008ollin' in my five point oh".to_string());
        outputs.insert("000009ith my rag-top down so my hair can blow".to_string());
        assert!(outputs.contains(&output_string));
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
            cryptopal_util::bytes_to_ascii(&aes_fun::challenge_19_and_20::attack().unwrap())
                .unwrap()[..53]
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

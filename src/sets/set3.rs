#[cfg(test)]
mod tests {
    pub use crate::aes_fun::Key;
    use crate::cryptopal_util::current_unix_timestamp;
    use crate::mersenne_twister::TheirMersenneTwister;
    use crate::{aes_fun, cryptopal_util, mersenne_twister};
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
        let encrypted_bytes = cryptopal_util::b64_to_bytes(encrypted.to_string()).unwrap();
        let key_bytes = cryptopal_util::ascii_to_bytes(key).unwrap();
        let decrypted_bytes =
            aes_fun::ctr::decrypt(encrypted_bytes.as_slice(), Key(key_bytes.as_slice()), 0)
                .unwrap();
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
        let mut rng = mersenne_twister::MersenneTwister::new(seed);

        let mut system_rng = TheirMersenneTwister::new(seed);
        // start grabbing randomness from rng...
        for i in 0..1800 {
            println!("{}", i);
            let system_rand = system_rng.extract_number();
            let rng_rand = rng.extract_number();
            assert_eq!(system_rand, rng_rand);
        }
    }

    #[test]
    fn s3c22_crack_mt19937_seed() {
        // Crack an MT19937 seed
        // Make sure your MT19937 accepts an integer seed value. Test it (verify that you're getting the same sequence of outputs given a seed).
        //
        // Write a routine that performs the following operation:
        //
        // Wait a random number of seconds between, I don't know, 40 and 1000.
        // Seeds the RNG with the current Unix timestamp
        // Waits a random number of seconds again.
        // Returns the first 32 bit output of the RNG.
        // You get the idea. Go get coffee while it runs. Or just simulate the passage of time, although you're missing some of the fun of this exercise if you do that.
        //
        // From the 32 bit RNG output, discover the seed.
        let mut current_unix = current_unix_timestamp();
        // wait a random number of seconds between 40 and 1000
        current_unix += rand::random::<u32>() % 960 + 40;
        let original_seed = current_unix;
        let mut rng = mersenne_twister::MersenneTwister::new(current_unix);
        // wait a random number of seconds again
        current_unix += rand::random::<u32>() % 960 + 40;
        let first_output = rng.extract_number();
        let cracked_seed =
            mersenne_twister::crack_mersenne_seed_from_timestamp(current_unix, first_output);
        assert_eq!(cracked_seed, original_seed);
    }

    #[test]
    fn s3c23_clone_mt19937_rng() {
        // create an rng
        let seed = rand::random::<u32>();
        let mut rng = mersenne_twister::MersenneTwister::new(seed);
        // make 624 outputs
        let mut outputs: Vec<u32> = Vec::new();
        for _ in 0..624 {
            outputs.push(rng.extract_number());
        }
        // clone the rng
        let mut cloned_rng = mersenne_twister::reconstruct_mersenne_state(outputs.as_slice());
        //check that they're synced <3
        for _ in 0..1000 {
            assert_eq!(rng.extract_number(), cloned_rng.extract_number());
        }
    }

    #[test]
    fn s3c24_create_mt19937_stream_cipher_and_break_it() {
        let (key, ciphertext) = mersenne_twister::oracle_smallkey();
        assert_eq!(
            mersenne_twister::mersenne_stream_cipher_crack_smallkey(&ciphertext),
            key
        );
        let mut current_unix = current_unix_timestamp();
        let (key, ciphertext) = mersenne_twister::oracle_timekey(current_unix);
        current_unix += rand::random::<u32>() % 960 + 40;
        assert_eq!(
            mersenne_twister::mersenne_stream_cipher_crack_timekey(current_unix, &ciphertext),
            key
        );
    }
}

#![feature(bigint_helper_methods)]

pub mod aes_fun;
pub mod cryptopal_util;
pub mod englishness;
mod mersenne_twister;
pub mod pkcs7;
mod silly_webserver_for_challenge_13;
mod silly_webserver_for_challenge_16;
mod silly_webserver_for_challenge_17;

fn main() {
    println!("Hello, world! try running the tests :)");
}

#[cfg(test)]
mod tests {
    use crate::aes_fun::{crack_challenge_12_oracle, crack_challenge_14_oracle, is_ecb};
    use crate::mersenne_twister::MersenneTwister;
    use crate::silly_webserver_for_challenge_13::challenge_13_attack;
    use crate::silly_webserver_for_challenge_16::challenge_16_attack;
    use crate::{aes_fun, cryptopal_util, englishness, pkcs7};
    use rand_mt::Mt19937GenRand32;

    #[test]
    fn s1c1_hex_to_b64() {
        let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        let bytes = cryptopal_util::hex_to_bytes(input.to_string()).unwrap();
        let my_output = cryptopal_util::bytes_to_b64(&bytes);
        assert_eq!(my_output, output);
    }

    #[test]
    fn s1c2_fixed_xor() {
        // 1c0111001f010100061a024b53535009181c
        // ... after hex decoding, and when XOR'd against:
        //
        // 686974207468652062756c6c277320657965
        // ... should produce:
        //
        // 746865206b696420646f6e277420706c6179
        let input1 = "1c0111001f010100061a024b53535009181c";
        let input2 = "686974207468652062756c6c277320657965";
        let output = "746865206b696420646f6e277420706c6179";
        let bytes1 = cryptopal_util::hex_to_bytes(input1.to_string()).unwrap();
        let bytes2 = cryptopal_util::hex_to_bytes(input2.to_string()).unwrap();
        let my_output = cryptopal_util::bytes_to_hex(&cryptopal_util::fixed_xor(&bytes1, &bytes2));
        assert_eq!(my_output, output);
    }

    #[test]
    fn s1c3_single_byte_xor() {
        let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let output = "Cooking MC's like a pound of bacon";
        let input_bytes = cryptopal_util::hex_to_bytes(input.to_string()).unwrap();
        let (_, cracked, _) = englishness::find_best_fixed_xor(input_bytes);
        assert_eq!(cryptopal_util::bytes_to_ascii(cracked).unwrap(), output);
    }

    #[test]
    fn s1c4_detect_single_byte_xor() {
        let filename = "./data/4.txt";
        let lines = cryptopal_util::read_lines_from_file(filename.to_string()).unwrap();
        let (_, _, decoded_bytes) = englishness::find_which_is_fixed_xor(
            lines
                .iter()
                .map(|hex| cryptopal_util::hex_to_bytes(hex.to_string()).unwrap())
                .collect(),
        );
        let decoded_string = cryptopal_util::bytes_to_ascii(decoded_bytes).unwrap();
        assert_eq!(decoded_string, "Now that the party is jumping\n");
    }

    #[test]
    fn s1c5_repeating_key_xor() {
        let input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let key = "ICE";
        let output = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        let input_bytes = cryptopal_util::ascii_to_bytes(input).unwrap();
        let key_bytes = cryptopal_util::ascii_to_bytes(key).unwrap();
        let my_output = cryptopal_util::bytes_to_hex(&cryptopal_util::repeating_key_xor(
            &input_bytes,
            &key_bytes,
        ));
        assert_eq!(my_output, output);
    }

    #[test]
    fn s1c6_break_repeating_key_xor() {
        let filename = "./data/6.txt";
        let bytes = cryptopal_util::read_bytes_from_b64_file(filename.to_string()).unwrap();
        let (my_key, my_output) = englishness::break_repeating_key_xor(bytes);
        println!("{}", cryptopal_util::bytes_to_ascii(my_output).unwrap());
        assert_eq!(
            cryptopal_util::bytes_to_ascii(my_key).unwrap(),
            "Terminator X: Bring the noise"
        );
    }

    #[test]
    fn s1c7_aes_ecb_mode() {
        let filename = "./data/7.txt";
        let bytes = cryptopal_util::read_bytes_from_b64_file(filename.to_string()).unwrap();
        let key = cryptopal_util::ascii_to_bytes("YELLOW SUBMARINE").unwrap();
        let my_output = cryptopal_util::bytes_to_ascii(
            aes_fun::aes_ecb_mode_decrypt(&bytes, key.as_slice()).unwrap(),
        )
        .unwrap();
        assert_eq!(&my_output[..33], "I'm back and I'm ringin' the bell")
    }

    #[test]
    fn s1c8_aes_ecb_detection() {
        let filename = "./data/8.txt";
        let lines = cryptopal_util::read_lines_from_file(filename.to_string()).unwrap();
        let binary_lines = lines
            .iter()
            .map(|hex| cryptopal_util::hex_to_bytes(hex.to_string()).unwrap())
            .collect();
        let my_output = aes_fun::find_aes_ecb_ciphertexts(binary_lines);
        assert_eq!(my_output.len(), 1);
    }

    #[test]
    fn s2c9_implement_pkcs7() {
        let input = "YELLOW SUBMARINE";
        let output = "YELLOW SUBMARINE\x04\x04\x04\x04";
        let input_bytes = cryptopal_util::ascii_to_bytes(input).unwrap();
        let my_output = cryptopal_util::bytes_to_ascii(pkcs7::pkcs7_pad(&input_bytes, 20)).unwrap();
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
        let my_output = cryptopal_util::bytes_to_ascii(
            aes_fun::cbc_decrypt(data.as_slice(), key.as_slice(), iv.as_slice()).unwrap(),
        )
        .unwrap();
        assert_eq!(&my_output[..33], "I'm back and I'm ringin' the bell");
        let re_encrypt =
            aes_fun::cbc_encrypt(my_output.as_bytes(), key.as_slice(), iv.as_slice()).unwrap();
        assert_eq!(re_encrypt, data);
    }

    #[test]
    fn s2c11_ecb_cbc_detection_oracle() {
        for _ in 0..=30 {
            let oracle_input = [b'a'; 70];
            let (was_ecb, oracle_output) = aes_fun::ecb_cbc_encryption_oracle(&oracle_input);
            assert_eq!(is_ecb(oracle_output.as_slice()), was_ecb);
        }
    }

    #[test]
    fn s2c12_byte_at_a_time_ecb_decryption() {
        // I JUST WANT YOU ALL TO KNOW THAT I GOT THIS ON THE FIRST GODDAMN TRY!!!!!!! GET FUCKED LMAOOOOFDSAJKLFDSJAKLFJDSKLA
        let oh_my_god_i_cant_believe_i_got_this_in_one_run =
            cryptopal_util::bytes_to_ascii(crack_challenge_12_oracle()).unwrap();
        assert_eq!("Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n", oh_my_god_i_cant_believe_i_got_this_in_one_run);
    }

    #[test]
    fn s2c13_ecb_cutnpaste() {
        assert!(challenge_13_attack().unwrap());
    }

    #[test]
    fn s2c14_byte_at_a_time_ecb_decryption_harder() {
        let whoop = cryptopal_util::bytes_to_ascii(crack_challenge_14_oracle()).unwrap();
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
        assert!(challenge_16_attack().unwrap());
    }

    #[test]
    fn s3c17_cbc_padding_oracle() {
        unimplemented!();
    }

    #[test]
    fn s3c18_implement_ctr() {
        unimplemented!();
    }

    #[test]
    fn s3c19_break_fixednonce_ctr_substitution() {
        unimplemented!();
    }

    #[test]
    fn s3c20_break_fixednonce_ctr_statistically() {
        unimplemented!();
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

    #[test]
    fn s4c25_break_randomaccess_readwrite() {
        unimplemented!();
    }

    #[test]
    fn s4c26_break_ctr_bitflipping() {
        unimplemented!();
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

    #[test]
    fn s5c33_implement_diffie_hellman() {
        unimplemented!();
    }

    #[test]
    fn s5c34_implement_mitm_key_fixing_attack_on_diffie_hellman() {
        unimplemented!();
    }

    #[test]
    fn s5c35_implement_dh_with_negotiated_groups_and_break_with_malicious_g_parameters() {
        unimplemented!();
    }

    #[test]
    fn s5c36_implement_srp() {
        unimplemented!();
    }

    #[test]
    fn s5c37_break_srp_with_zero_key() {
        unimplemented!();
    }

    #[test]
    fn s5c38_offline_dictionary_attack_on_simplified_srp() {
        unimplemented!();
    }

    #[test]
    fn s5c39_implement_rsa() {
        unimplemented!();
    }

    #[test]
    fn s5c40_implement_e_3_rsa_broadcast_attack() {
        unimplemented!();
    }

    #[test]
    fn s6c41_implement_unpadded_message_recovery_oracle() {
        unimplemented!();
    }

    #[test]
    fn s6c42_bleichenbacher_rsa_attack() {
        unimplemented!();
    }

    #[test]
    fn s6c43_dsa_key_recovery_from_nonce() {
        unimplemented!();
    }

    #[test]
    fn s6c44_dsa_nonce_recovery_from_repeated_nonce() {
        unimplemented!();
    }

    #[test]
    fn s6c45_dsa_parameter_tampering() {
        unimplemented!();
    }

    #[test]
    fn s6c46_rsa_parity_oracle() {
        unimplemented!();
    }

    #[test]
    fn s6c47_bleichenbacher_pkcs_15_padding_oracle_simple_case() {
        unimplemented!();
    }

    #[test]
    fn s6c48_bleichenbacher_pkcs_15_padding_oracle_complete_case() {
        unimplemented!();
    }

    #[test]
    fn s7c49_cbc_mac_message_forgery() {
        unimplemented!();
    }

    #[test]
    fn s7c50_hashing_with_cbc_mac() {
        unimplemented!();
    }

    #[test]
    fn s7c51_compression_ratio_side_channel_attacks() {
        unimplemented!();
    }

    #[test]
    fn s7c52_iterated_hash_function_multicollisions() {
        unimplemented!();
    }

    #[test]
    fn s7c53_kelsey_and_schneier_expandable_messages() {
        unimplemented!();
    }

    #[test]
    fn s7c54_kelsey_and_kohno_nostradamus_attack() {
        unimplemented!();
    }

    #[test]
    fn s7c55_md4_collisions() {
        unimplemented!();
    }

    #[test]
    fn s7c56_rc4_single_byte_biases() {
        unimplemented!();
    }

    #[test]
    fn s8c57_diffie_hellman_small_subgroup_confinement() {
        unimplemented!();
    }

    #[test]
    fn s8c58_pollards_method_for_catching_kangaroos() {
        unimplemented!();
    }

    #[test]
    fn s8c59_elliptic_curve_diffie_hellman_and_invalid_curve_attacks() {
        unimplemented!();
    }

    #[test]
    fn s8c60_single_coordinate_ladders_and_insecure_twists() {
        unimplemented!();
    }

    #[test]
    fn s8c61_duplicate_signature_key_selection_in_ecdsa_and_rsa() {
        unimplemented!();
    }

    #[test]
    fn s8c62_key_recovery_attacks_on_ecdsa_with_biased_nonces() {
        unimplemented!();
    }

    #[test]
    fn s8c63_key_recovery_attacks_on_gcm_with_repeated_nonces() {
        unimplemented!();
    }

    #[test]
    fn s8c64_key_recovery_attacks_on_gcm_with_a_truncated_mac() {
        unimplemented!();
    }

    #[test]
    fn s8c65_truncated_mac_gcm_revisited_improving_the_key_recovery_attack_via_ciphertext_length_extension(
    ) {
        unimplemented!();
    }

    #[test]
    fn s8c66_exploiting_implementation_errors_in_diffie_hellman() {
        unimplemented!();
    }
}

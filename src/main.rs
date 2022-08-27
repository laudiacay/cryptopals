pub mod aes_fun;
pub mod cryptopal_util;
pub mod englishness;
pub mod pkcs7;

fn main() {
    println!("Hello, world! try running the tests :)");
}

#[cfg(test)]
mod tests {
    use crate::aes_fun::{crack_challenge_12_oracle, crack_challenge_14_oracle, is_ecb};
    use crate::{aes_fun, cryptopal_util, englishness, pkcs7};

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
        let my_output = cryptopal_util::bytes_to_ascii(aes_fun::cbc_decrypt(
            data.as_slice(),
            iv.as_slice(),
            key.as_slice(),
        ))
        .unwrap();
        assert_eq!(&my_output[..33], "I'm back and I'm ringin' the bell")
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
        unimplemented!()
    }

    #[test]
    fn s2c14_byte_at_a_time_ecb_decryption_harder() {
        let whoop = cryptopal_util::bytes_to_ascii(crack_challenge_14_oracle()).unwrap();
        assert_eq!("Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n", whoop);
    }


}

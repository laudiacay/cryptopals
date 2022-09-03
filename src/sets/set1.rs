#[cfg(test)]
mod tests {
    use crate::{aes_fun, cryptopal_util, englishness};

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
        assert_eq!(cryptopal_util::bytes_to_ascii(&cracked).unwrap(), output);
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
        let decoded_string = cryptopal_util::bytes_to_ascii(&decoded_bytes).unwrap();
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
        println!("{}", cryptopal_util::bytes_to_ascii(&my_output).unwrap());
        assert_eq!(
            cryptopal_util::bytes_to_ascii(&my_key).unwrap(),
            "Terminator X: Bring the noise"
        );
    }

    #[test]
    fn s1c7_aes_ecb_mode() {
        let filename = "./data/7.txt";
        let bytes = cryptopal_util::read_bytes_from_b64_file(filename.to_string()).unwrap();
        let key = cryptopal_util::ascii_to_bytes("YELLOW SUBMARINE").unwrap();
        let my_output =
            cryptopal_util::bytes_to_ascii(&aes_fun::ecb::decrypt(&bytes, key.as_slice()).unwrap())
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
        let my_output = aes_fun::ecb::find_aes_ecb_ciphertexts(binary_lines);
        assert_eq!(my_output.len(), 1);
    }
}

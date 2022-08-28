use crate::aes_fun::ecb;
use crate::cryptopal_util;
use crate::random_things::MY_RANDOM_KEY;
use std::collections::HashMap;

fn oracle(my_input: &[u8]) -> Vec<u8> {
    let base64_thing_to_append = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let bytes_to_append = cryptopal_util::b64_to_bytes(base64_thing_to_append).unwrap();
    // AES-128-ECB(your-string || unknown-string, random-key)
    let mut my_input = my_input.to_vec();
    my_input.extend(bytes_to_append);
    ecb::encrypt(&my_input, &MY_RANDOM_KEY)
}

fn compute_block_size() -> usize {
    let mut my_input = Vec::new();
    let mut last_ciphertext = oracle(&my_input);
    for i in 1..100 {
        my_input.push(b'a');
        let my_ciphertext = oracle(&my_input);
        if my_ciphertext[0..16] == last_ciphertext[0..16] {
            return i - 1;
        }
        last_ciphertext = my_ciphertext;
    }
    panic!("it's over 100??");
}

pub fn attack() -> Vec<u8> {
    // Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the block size of the cipher. You know it, but do this step anyway.
    let block_size = compute_block_size();
    assert_eq!(block_size, 16);
    //    Detect that the function is using ECB. You already know, but do this step anyways.
    assert!(ecb::is_ecb(&oracle(&[b'A'; 16 * 3])));

    // let's find the length.
    let initial_length = oracle(&[]).len();
    // let's figure out how much padding is going on.
    let mut i = 0;
    let number_of_is_it_takes_to_fill_a_block = {
        loop {
            let my_input = vec![b'A'; i];
            let my_ciphertext = oracle(&my_input);
            if my_ciphertext.len() != initial_length {
                break i;
            }
            i += 1;
        }
    };
    let length = initial_length - number_of_is_it_takes_to_fill_a_block;

    let mut text_string: Vec<u8> = Vec::new();
    //    Knowing the block size, craft an input block that is exactly 1 byte short (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about what the oracle function is going to put in that last byte position.
    for _ in 0..length {
        // want to position the target byte at the end of the block
        // for the 0th byte, that's 15 A's.
        // for the 1th, that's 14.
        // for the 2ne, that's 13.
        // for the 15, that's 0.
        // for the 16th, new block, that's 15.
        // 15 - (N % 16)
        let aaaa_for_offset = vec![b'A'; 15 - (text_string.len() % 16)];
        let mut plaintext_up_to_known = vec![];
        plaintext_up_to_known.append(&mut aaaa_for_offset.clone());
        plaintext_up_to_known.append(&mut text_string.clone());
        assert_eq!(plaintext_up_to_known.len() % 16, 15);
        let ciphertext = oracle(&aaaa_for_offset);

        let target_cipher_block_offset = plaintext_up_to_known.len() - 15;
        let target_cipher_block =
            &ciphertext[target_cipher_block_offset..target_cipher_block_offset + 16];

        let target_plaintext_block_prefix = &plaintext_up_to_known[target_cipher_block_offset..];
        assert_eq!(target_plaintext_block_prefix.len(), 15);

        //    Make a dictionary of every possible last byte by feeding different strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.
        let target_block_dictionary = (0..255)
            .map(|i| {
                let mut my_input = [b'A'; 16];
                my_input[..15].clone_from_slice(target_plaintext_block_prefix);
                my_input[15] = i as u8;
                (oracle(&my_input)[..16].to_vec(), i)
            })
            .collect::<HashMap<Vec<u8>, u8>>();
        //    Match the output of the one-byte-short input to one of the entries in your dictionary. You've now discovered the first byte of unknown-string.
        text_string.push(target_block_dictionary[&target_cipher_block.to_vec()]);
        //    Repeat for the next byte.
    }
    text_string
}

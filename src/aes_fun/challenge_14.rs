use crate::aes_fun::ecb;
use crate::cryptopal_util;
use crate::random_things::MY_RANDOM_KEY;
use rand::distributions::Standard;
use rand::Rng;
use std::collections::HashMap;

lazy_static::lazy_static! {
    static ref CHALLENGE_14_RANDOM_PREFIX: Vec<u8> = {
        let prefix_length = rand::thread_rng().gen_range(0..60);
        rand::thread_rng().sample_iter(Standard).take(prefix_length).collect()
    };
}

fn oracle(my_input: &[u8]) -> Vec<u8> {
    let base64_thing_to_append = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let bytes_to_append = cryptopal_util::b64_to_bytes(base64_thing_to_append).unwrap();
    // AES-128-ECB(your-string || unknown-string, random-key)
    let mut my_new_input = CHALLENGE_14_RANDOM_PREFIX.to_vec();
    my_new_input.extend(my_input);
    my_new_input.extend(bytes_to_append);
    ecb::encrypt(&my_new_input, &MY_RANDOM_KEY)
}

fn compute_prefix_length() -> usize {
    let my_input = Vec::new();
    let with_no_input = oracle(&my_input);
    let with_one_letter_input = oracle(&[b'a'; 1]);

    // find first differing block between no_input and one_letter_input
    // if first differing block is block i, then the prefix ends around block i.
    let mut i = 0;
    let first_differing_block = loop {
        if with_no_input[i * 16..(i + 1) * 16] != with_one_letter_input[i * 16..(i + 1) * 16] {
            break i;
        }
        i += 1;
    };

    // now we know which block the prefix ends in, and we have to figure out exactly which byte it is
    // so let's make something that, when we have sufficient offset, we'll get two identical blocks subsequently at the same spot for the first time with both 'a' and 'b' and 'c'.
    // gotta use 3 because what if the prefix and suffix start/end with a and b ?
    let mut giant_a_input = vec![b'a'; 16 * 2];
    let mut giant_b_input = vec![b'b'; 16 * 2];
    let mut giant_c_input = vec![b'c'; 16 * 2];
    let mut i = 0;
    // now loop until you see two identical blocks with a b and c starting at either first_differing_block or first_differing_block + 1
    let prefix_length = loop {
        let with_giant_a_input = oracle(giant_a_input.as_slice());
        let with_giant_b_input = oracle(giant_b_input.as_slice());
        let with_giant_c_input = oracle(giant_c_input.as_slice());
        if with_giant_a_input[first_differing_block * 16..(first_differing_block + 1) * 16]
            == with_giant_a_input
                [(first_differing_block + 1) * 16..(first_differing_block + 2) * 16]
        {
            if with_giant_b_input[first_differing_block * 16..(first_differing_block + 1) * 16]
                == with_giant_b_input
                    [(first_differing_block + 1) * 16..(first_differing_block + 2) * 16]
                && with_giant_c_input[first_differing_block * 16..(first_differing_block + 1) * 16]
                    == with_giant_c_input
                        [(first_differing_block + 1) * 16..(first_differing_block + 2) * 16]
            {
                // ok, we found two repeating blocks for the first time at index first_differing_block and first_differing_block + 1
                assert_eq!(i, 0);
                // therefore the prefix was block-aligned!
                break first_differing_block * 16;
            }
        } else if with_giant_a_input
            [(first_differing_block + 1) * 16..(first_differing_block + 2) * 16]
            == with_giant_a_input
                [(first_differing_block + 2) * 16..(first_differing_block + 3) * 16]
            && with_giant_b_input
                [(first_differing_block + 1) * 16..(first_differing_block + 2) * 16]
                == with_giant_b_input
                    [(first_differing_block + 2) * 16..(first_differing_block + 3) * 16]
            && with_giant_c_input
                [(first_differing_block + 1) * 16..(first_differing_block + 2) * 16]
                == with_giant_c_input
                    [(first_differing_block + 2) * 16..(first_differing_block + 3) * 16]
        {
            // ok then it took i a's to push us out of first_differing_block.
            break first_differing_block * 16 + (16 - i);
        }
        i += 1;
        giant_a_input.push(b'a');
        giant_b_input.push(b'b');
        giant_c_input.push(b'c');
        // if i gets too big we've screwed up somewhere?
        assert!(i < 16);
    };
    prefix_length
}

pub fn attack() -> Vec<u8> {
    let prefix_length = compute_prefix_length();

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
    let length = initial_length - number_of_is_it_takes_to_fill_a_block - prefix_length;

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
        let aaaa_for_prefix = vec![b'A'; prefix_length];
        let aaaa_for_prefix_padding = vec![b'A'; 16 - (prefix_length % 16)];
        let aaaa_for_offset = vec![b'A'; 15 - (text_string.len() % 16)];
        assert_eq!(
            (aaaa_for_prefix.len() + aaaa_for_prefix_padding.len()) % 16,
            0
        );
        let mut plaintext_up_to_known = vec![];
        plaintext_up_to_known.extend_from_slice(&aaaa_for_prefix);
        plaintext_up_to_known.extend_from_slice(&aaaa_for_prefix_padding);
        let prefix_plus_padding_offset = plaintext_up_to_known.len();
        assert_eq!(prefix_plus_padding_offset % 16, 0);
        plaintext_up_to_known.extend_from_slice(&aaaa_for_offset);
        plaintext_up_to_known.extend_from_slice(&text_string);
        assert_eq!(plaintext_up_to_known.len() % 16, 15);

        let mut build_challenge = vec![];
        build_challenge.extend_from_slice(&aaaa_for_prefix_padding);
        build_challenge.extend_from_slice(&aaaa_for_offset);
        let ciphertext = oracle(&build_challenge);

        let target_cipher_block_offset = plaintext_up_to_known.len() - 15;
        let target_cipher_block =
            &ciphertext[target_cipher_block_offset..target_cipher_block_offset + 16];

        let target_plaintext_block_prefix = &plaintext_up_to_known[target_cipher_block_offset..];
        assert_eq!(target_plaintext_block_prefix.len(), 15);

        //    Make a dictionary of every possible last byte by feeding different strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.
        let target_block_dictionary = (0..255)
            .map(|i| {
                let mut my_input = vec![];
                my_input.extend_from_slice(&aaaa_for_prefix_padding);
                my_input.extend_from_slice(target_plaintext_block_prefix);
                my_input.extend_from_slice(&[i as u8; 1]);
                (
                    oracle(&my_input)[prefix_plus_padding_offset..prefix_plus_padding_offset + 16]
                        .to_vec(),
                    i,
                )
            })
            .collect::<HashMap<Vec<u8>, u8>>();
        //    Match the output of the one-byte-short input to one of the entries in your dictionary. You've now discovered the first byte of unknown-string.
        text_string.push(target_block_dictionary[&target_cipher_block.to_vec()]);
        //    Repeat for the next byte.
    }
    text_string
}

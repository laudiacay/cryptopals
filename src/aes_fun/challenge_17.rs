//This is the best-known attack on modern block-cipher cryptography.
//
// Combine your padding code and your CBC code to write two functions.
//
// The first function should select at random one of the following 10 strings:
// ... generate a random AES key (which it should save for all future encryptions), pad the string out to the 16-byte AES block size and CBC-encrypt it under that key, providing the caller the ciphertext and IV.
//
// The second function should consume the ciphertext produced by the first function, decrypt it, check its padding, and return true or false depending on whether the padding is valid.

use crate::pkcs7::pkcs7_unpad;
use crate::random_things::{MY_RANDOM_IV, MY_RANDOM_KEY};
use crate::{aes_fun, cryptopal_util};
use aes_fun::{Iv, Key};
use anyhow::Result;
use lazy_static::lazy_static;

lazy_static! {
    pub static ref STRINGS: Vec<String> = vec![
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=".to_string(),
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=".to_string(),
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==".to_string(),
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==".to_string(),
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl".to_string(),
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==".to_string(),
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==".to_string(),
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=".to_string(),
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=".to_string(),
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93".to_string(),
    ];
}

// pick a string at random
fn encryption_oracle() -> Result<Vec<u8>> {
    // pick a random string from STRINGS
    let random_string = &STRINGS[rand::random::<usize>() % STRINGS.len()];
    // decode the string
    let decoded_string = cryptopal_util::b64_to_bytes(random_string.to_string())?;
    // encrypt the string
    aes_fun::cbc::encrypt(&decoded_string, Key(&MY_RANDOM_KEY), Iv(&MY_RANDOM_IV))
}

fn decryption_oracle(ciphertext: &[u8]) -> Result<()> {
    let _ = aes_fun::cbc::decrypt(ciphertext, Key(&MY_RANDOM_KEY), Iv(&MY_RANDOM_IV))?;
    Ok(())
}

pub fn challenge_17_attack() -> Result<Vec<u8>> {
    // get our encrypted string
    let ciphertext = encryption_oracle()?;
    let n_blocks = ciphertext.len() / 16;
    assert!(n_blocks > 1);
    let mut decryption_vec = vec![];
    for i in 0..n_blocks {
        let attack_block = if i > 0 {
            ciphertext[(i - 1) * 16..(i) * 16].to_vec()
        } else {
            MY_RANDOM_IV.to_vec()
        };
        let target_block = ciphertext[(i) * 16..(i + 1) * 16].to_vec();
        let mut decrypted = [0u8; 16];
        let mut blank_it_out = [0u8; 16];
        for byte in (0..16).rev() {
            for change in 0..=255 {
                let mut new_ciphertext = attack_block.clone();
                new_ciphertext[byte] = change;
                // set the rest of the block after byte to decrypted ^ target_length
                for byte_to_set in (byte + 1)..=15 {
                    new_ciphertext[byte_to_set] = blank_it_out[byte_to_set] ^ (16 - byte) as u8;
                }
                new_ciphertext.extend_from_slice(&target_block);
                if decryption_oracle(&new_ciphertext).is_ok() {
                    // If the padding is correct, the attacker now knows that the last byte of
                    // D_{K}(C_{2}) ^  C_{1}' is 0x01, the last two bytes are 0x02, the last three bytes are 0x03, …,
                    // or the last eight bytes are 0x08. The attacker can modify the second-last byte (flip any bit) to ensure that the last byte is 0x01.
                    if byte != 0 {
                        // if we're working on byte = 15, we get 1 and 2, if we're working on byte = 14, we get 2 and 3, etc.
                        let padding_val: u8 = (16 - byte) as u8;
                        new_ciphertext[byte - 1] ^= 1;
                        if decryption_oracle(&new_ciphertext).is_ok() {
                            blank_it_out[byte] = padding_val ^ (change as u8);
                            decrypted[byte] = blank_it_out[byte] ^ attack_block[byte];
                            break;
                        }
                    } else {
                        blank_it_out[byte] = 16 ^ (change as u8);
                        decrypted[byte] = blank_it_out[byte] ^ attack_block[byte];
                        break;
                    }
                }
            }
        }
        decryption_vec.extend_from_slice(&decrypted);
    }
    pkcs7_unpad(&decryption_vec)
}

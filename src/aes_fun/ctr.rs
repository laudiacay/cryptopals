use crate::cryptopal_util;
use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use anyhow::Result;

//The string:
//
// L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==
// ... decrypts to something approximating English in CTR mode, which is an AES block cipher mode that turns AES into a stream cipher, with the following parameters:
//
//       key=YELLOW SUBMARINE
//       nonce=0
//       format=64 bit unsigned little endian nonce,
//              64 bit little endian block count (byte count / 16)
// CTR mode is very simple.
//
// Instead of encrypting the plaintext, CTR mode encrypts a running counter, producing a 16 byte block of keystream, which is XOR'd against the plaintext.
//
// For instance, for the first 16 bytes of a message with these parameters:
//
// keystream = AES("YELLOW SUBMARINE",
//                 "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
// ... for the next 16 bytes:
//
// keystream = AES("YELLOW SUBMARINE",
//                 "\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00")
// ... and then:
//
// keystream = AES("YELLOW SUBMARINE",
//                 "\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00")
// CTR mode does not require padding; when you run out of plaintext, you just stop XOR'ing keystream and stop generating keystream.
//
// Decryption is identical to encryption. Generate the same keystream, XOR, and recover the plaintext.
//
// Decrypt the string at the top of this function, then use your CTR function to encrypt and decrypt other things.

/// returns new_iv, keystream
fn keystream(key: &[u8], nonce: u64, start_iv: u64, bytes_to_produce: usize) -> (u64, Vec<u8>) {
    // round up bytes_to_produce
    let bytes_to_produce = (bytes_to_produce + 15) / 16 * 16;
    let mut keystream = vec![0_u8; bytes_to_produce];
    // how many blocks?
    let blocks_to_produce = bytes_to_produce / 16;
    let mut iv = start_iv;
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut buf = [0_u8; 16];
    for i in 0..blocks_to_produce {
        // write nonce to buf
        buf[0..8].copy_from_slice(&nonce.to_le_bytes());
        // write little endian iv to buf
        buf[8..].clone_from_slice(&iv.to_le_bytes());
        println!("{:?}", buf);
        cipher.encrypt_block(GenericArray::from_mut_slice(&mut buf));
        keystream[i * 16..(i + 1) * 16].copy_from_slice(&buf);
        iv += 1;
    }
    (iv, keystream)
}

pub fn decrypt(ciphertext: &[u8], key: &[u8], nonce: u64) -> Result<Vec<u8>> {
    let (_, keystream) = keystream(key, nonce, 0, ciphertext.len());
    let plaintext = cryptopal_util::fixed_xor(ciphertext, &keystream);
    Ok(plaintext)
}

pub fn encrypt(input: &[u8], key: &[u8], nonce: u64) -> Vec<u8> {
    let (_, keystream) = keystream(key, nonce, 0, input.len());
    cryptopal_util::fixed_xor(input, &keystream)
}

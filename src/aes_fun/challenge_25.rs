//Back to CTR. Encrypt the recovered plaintext from this file (the ECB exercise) under CTR with a random key
// (for this exercise the key should be unknown to you, but hold on to it).
//
// Now, write the code that allows you to "seek" into the ciphertext, decrypt, and re-encrypt with different plaintext.
// Expose this as a function, like, "edit(ciphertext, key, offset, newtext)".
//
// Imagine the "edit" function was exposed to attackers by means of an API call that didn't reveal the key or the original plaintext;
// the attacker has the ciphertext and controls the offset and "new text".
//
// Recover the original plaintext.

use crate::aes_fun::ctr;
use crate::cryptopal_util;
use crate::random_things::MY_RANDOM_KEY;
use anyhow::Result;
use std::iter;

pub fn encrypt(plaintext: &[u8]) -> Vec<u8> {
    ctr::encrypt(plaintext, &MY_RANDOM_KEY, 0)
}

pub fn edit(ciphertext: &[u8], key: &[u8], offset: usize, newtext: &[u8]) -> Result<Vec<u8>> {
    let mut plaintext = ctr::decrypt(ciphertext, key, 0)?;
    for (i, newbyte) in newtext.iter().enumerate() {
        plaintext[offset + i] = *newbyte;
    }
    Ok(ctr::encrypt(&plaintext, key, 0))
}

pub fn edit_api(ciphertext: &[u8], offset: usize, newtext: &[u8]) -> Result<Vec<u8>> {
    edit(ciphertext, &MY_RANDOM_KEY, offset, newtext)
}

pub fn attack(ciphertext: &[u8]) -> Result<Vec<u8>> {
    let res = edit_api(
        ciphertext,
        0,
        &iter::repeat(0u8)
            .take(ciphertext.len())
            .collect::<Vec<u8>>(),
    )?;
    Ok(cryptopal_util::fixed_xor(&res, ciphertext))
}

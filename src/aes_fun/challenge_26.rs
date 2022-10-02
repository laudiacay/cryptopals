use crate::random_things::MY_RANDOM_KEY;
use crate::{aes_fun, cryptopal_util};
use aes_fun::Key;
use anyhow::Result;

// The first function should take an arbitrary input string, prepend the string:
//
// "comment1=cooking%20MCs;userdata="
// .. and append the string:
//
// ";comment2=%20like%20a%20pound%20of%20bacon"
// The function should quote out the ";" and "=" characters.
//
// The function should then pad out the input to the 16-byte AES block length and encrypt it under the random AES key.
fn oracle(input_string: String) -> Result<Vec<u8>> {
    let quoted_out = input_string.replace(';', "%3B").replace('=', "%3D");
    let mut output = "comment1=cooking%20MCs;userdata=".to_string();
    output.push_str(&quoted_out);
    output.push_str(";comment2=%20like%20a%20pound%20of%20bacon");
    let output_bytes = cryptopal_util::ascii_to_bytes(&output)?;
    Ok(aes_fun::ctr::encrypt(
        &output_bytes,
        aes_fun::Key(&MY_RANDOM_KEY),
        0,
    ))
}

// The second function should decrypt the string and look for the characters ";admin=true;" (or, equivalently, decrypt, split the string on ";", convert each resulting string into 2-tuples, and look for the "admin" tuple).
//
// Return true or false based on whether the string exists.
fn target(input_bytes: &[u8]) -> Result<bool> {
    // decrypt the string
    let decrypted_bytes = aes_fun::ctr::decrypt(input_bytes, Key(&MY_RANDOM_KEY), 0)?;
    let decrypted_string = unsafe { String::from_utf8_unchecked(decrypted_bytes) };
    // return whether it contains the characters ";admin=true;"
    Ok(decrypted_string.contains(";admin=true;"))
}

//
// If you've written the first function properly, it should not be possible to provide user input to it that will generate the string the second function is looking for. We'll have to break the crypto to do that.
//
// Instead, modify the ciphertext (without knowledge of the AES key) to accomplish this.
//
// You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext block:
//
// Completely scrambles the block the error occurs in
// Produces the identical 1-bit error(/edit) in the next ciphertext block.

pub fn attack() -> Result<bool> {
    let length_1 = "comment1=cooking%20MCs;userdata=".len();
    let output = [b'A'; 16 * 8];
    let mut encrypted = oracle(cryptopal_util::bytes_to_ascii(&output)?)?;
    let jokes_and_tricks = cryptopal_util::fixed_xor(
        &cryptopal_util::ascii_to_bytes(";admin=true;")?,
        &cryptopal_util::ascii_to_bytes("AAAAAAAAAAAA")?,
    );
    // round length_1 up to a multiple of 16
    let length_1_rounded = (length_1 + 15) / 16 * 16 + 16;
    // xor the block starting at length_1_rounded with jokes_and_tricks
    for i in 0..jokes_and_tricks.len() {
        encrypted[length_1_rounded + i] ^= jokes_and_tricks[i];
    }

    target(&encrypted)
}

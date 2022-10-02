use crate::random_things::{MY_RANDOM_IV, MY_RANDOM_KEY};
use crate::{aes_fun, cryptopal_util};
use aes_fun::{Iv, Key};
use anyhow::{anyhow, Result};

fn oracle(input_bytes: &[u8]) -> Result<Vec<u8>> {
    // ensure the input is ascii
    let _ = cryptopal_util::bytes_to_ascii(input_bytes)?;
    aes_fun::cbc::encrypt(input_bytes, Key(&MY_RANDOM_KEY), Iv(&MY_RANDOM_IV))
}

fn target(input_bytes: &[u8]) -> Result<bool> {
    // decrypt the string
    let decrypted_bytes =
        aes_fun::cbc::decrypt_no_unpad(input_bytes, Key(&MY_RANDOM_KEY), Iv(&MY_RANDOM_IV));
    let decrypted_string = unsafe { String::from_utf8_unchecked(decrypted_bytes) };
    if decrypted_string.is_ascii() {
        // return whether it contains the characters ";admin=true;"
        Ok(decrypted_string.contains(";admin=true;"))
    } else {
        Err(anyhow!(decrypted_string))
    }
}

pub fn attack() -> Result<()> {
    // Use your code to encrypt a message that is at least 3 blocks long:
    //
    // AES-CBC(P_1, P_2, P_3) -> C_1, C_2, C_3
    // Modify the message (you are now the attacker):
    //
    // C_1, C_2, C_3 -> C_1, 0, C_1
    // Decrypt the message (you are now the receiver) and raise the appropriate error if high-ASCII is found.
    //
    // As the attacker, recovering the plaintext from the error, extract the key:
    //
    // P'_1 XOR P'_3
    let p_1 = [b'A'; 16];
    let p_2 = [b'B'; 16];
    let p_3 = [b'C'; 16];
    // string them all together
    let mut input_bytes = p_1.to_vec();
    input_bytes.extend_from_slice(&p_2);
    input_bytes.extend_from_slice(&p_3);
    let encrypted_bytes = oracle(&input_bytes)?;
    // now we have the encrypted bytes, we need to modify them
    let mut modified_bytes = encrypted_bytes.clone();
    // C_1, C_2, C_3 -> C_1, 0, C_1
    modified_bytes[16..32].copy_from_slice(&[0; 16]);
    modified_bytes[32..48].copy_from_slice(&encrypted_bytes[0..16]);
    // now we have the modified bytes, we need to decrypt them
    match target(&modified_bytes) {
        Ok(_) => Err(anyhow!("should have failed")),
        Err(decrypted_bytes_error) => {
            let dec_bytes_string = decrypted_bytes_error.to_string();
            let dec_bytes = dec_bytes_string.as_bytes();
            println!("decrypted bytes: {:?}", dec_bytes);
            // now we have the decrypted bytes, we need to extract the key
            let p_1_prime = &dec_bytes[0..16];
            let p_3_prime = &dec_bytes[32..48];
            let key = cryptopal_util::fixed_xor(p_1_prime, p_3_prime);
            println!("key: {:?}", key);
            // copy my_random_key into a buffer
            let mut my_random_key_buffer = [0; 16];
            my_random_key_buffer.copy_from_slice(&MY_RANDOM_KEY);
            println!("MY_RANDOM_KEY: {:?}", my_random_key_buffer);
            // now we have the key, we need to decrypt the original bytes
            let decrypted_bytes = aes_fun::cbc::decrypt(&encrypted_bytes, Key(&key), Iv(&key))?;
            // now we have the decrypted bytes, we need to check if they contain ";admin=true;"
            assert_eq!(decrypted_bytes, input_bytes);
            Ok(())
        }
    }
}

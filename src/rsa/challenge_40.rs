// Implement an E=3 RSA Broadcast attack
// Assume you're a Javascript programmer. That is, you're using a naive handrolled RSA to encrypt without padding.
//
// Assume you can be coerced into encrypting the same plaintext three times, under three different public keys. You can; it's happened.

use crate::rsa::RsaPubKey;
use crate::{cryptopal_util, rsa};
use anyhow::{anyhow, Result};
use num::BigUint;

fn oracle(message: String) -> Result<(Vec<u8>, RsaPubKey)> {
    let key = rsa::RsaKey::new(512);
    Ok((key.encrypt_string(&message)?, key.get_public_key()))
}

pub fn attack() -> Result<()> {
    // Get three ciphertexts
    // Capturing any 3 of the ciphertexts and their corresponding pubkeys
    let (c_1, n_1) = oracle("i love doggsss".to_string())?;
    let (c_2, n_2) = oracle("i love doggsss".to_string())?;
    let (c_3, n_3) = oracle("i love doggsss".to_string())?;
    // Using the CRT to solve for the number represented by the three ciphertexts (which are residues mod their respective pubkeys)
    let m_s_1 = n_2.modulus.clone() * n_3.modulus.clone();
    let m_s_2 = n_1.modulus.clone() * n_3.modulus.clone();
    let m_s_3 = n_1.modulus.clone() * n_2.modulus.clone();
    let n_0_1_2 = n_1.modulus.clone() * n_2.modulus.clone() * n_3.modulus.clone();

    let c_1 = BigUint::from_bytes_be(&c_1);
    let c_2 = BigUint::from_bytes_be(&c_2);
    let c_3 = BigUint::from_bytes_be(&c_3);

    let first_inverse =
        rsa::invmod(m_s_1.clone(), n_1.modulus).ok_or_else(|| anyhow!("Failed to get inverse"))?;
    let second_inverse =
        rsa::invmod(m_s_2.clone(), n_2.modulus).ok_or_else(|| anyhow!("Failed to get inverse"))?;
    let third_inverse =
        rsa::invmod(m_s_3.clone(), n_3.modulus).ok_or_else(|| anyhow!("Failed to get inverse"))?;

    let term_1 = c_1 * m_s_1 * first_inverse;
    let term_2 = c_2 * m_s_2 * second_inverse;
    let term_3 = c_3 * m_s_3 * third_inverse;

    let m = (term_1 + term_2 + term_3) % n_0_1_2;
    // take the cube root
    let cube_root = m.cbrt();
    // convert to string
    let bytes = cryptopal_util::biguint_to_bytes(&cube_root);
    let message = cryptopal_util::bytes_to_ascii(&bytes)?;
    assert_eq!(message, "i love doggsss");
    Ok(())
}

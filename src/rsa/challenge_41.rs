// Implement unpadded message recovery oracle
// Nate Lawson says we should stop calling it "RSA padding" and start calling it "RSA armoring".
// Here's why.
//
// Imagine a web application, again with the Javascript encryption, taking RSA-encrypted messages
// which (again: Javascript) aren't padded before encryption at all.
//
// You can submit an arbitrary RSA blob and the server will return plaintext. But you can't submit
// the same message twice: let's say the server keeps hashes of previous messages for some liveness
// interval, and that the message has an embedded timestamp:
//
// {
//   time: 1356304276,
//   social: '555-55-5555',
//}

use crate::rsa::{RsaKey, RsaPubKey};
use crate::sha1::sha1;
use crate::{cryptopal_util, rsa};
use anyhow::{anyhow, Result};
use num::BigUint;
use std::collections::HashSet;

struct WebserverState {
    previous_messages: HashSet<Vec<u8>>,
    key: RsaKey,
}
impl WebserverState {
    fn new() -> Self {
        WebserverState {
            previous_messages: HashSet::new(),
            key: RsaKey::new(512),
        }
    }
    fn oracle(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let hash_ciphertext = sha1(ciphertext).to_vec();
        if self.previous_messages.contains(&hash_ciphertext) {
            return Err(anyhow!("Message already seen"));
        }
        self.previous_messages.insert(hash_ciphertext);
        let ciphertext_uint = cryptopal_util::bytes_to_biguint(ciphertext);
        Ok(cryptopal_util::biguint_to_bytes(
            &self.key.decrypt(&ciphertext_uint)?,
        ))
    }
    fn intercept(&mut self) -> Result<(Vec<u8>, RsaPubKey)> {
        let plaintext = "hi mom".to_string();
        let ciphertext = self.key.encrypt_string(&plaintext)?;
        let _ = self.oracle(&ciphertext)?;
        Ok((ciphertext, self.key.get_public_key()))
    }
}

pub fn attack() -> Result<()> {
    let mut state = WebserverState::new();
    // Capture the ciphertext C
    // Let N and E be the public modulus and exponent respectively
    // Let S be a random number > 1 mod N. Doesn't matter what.
    let (intercepted_ciphertext, intercepted_pubkey) = state.intercept()?;
    let my_random_number = BigUint::from(42_u32);
    let ciphertext_bigint = cryptopal_util::bytes_to_biguint(&intercepted_ciphertext);

    // C' = ((S**E mod N) C) mod N
    let s_to_the_e_mod_n = cryptopal_util::modular_exponentiation(
        &my_random_number,
        &intercepted_pubkey.public_exponent,
        &intercepted_pubkey.modulus,
    );

    let c_times_s_to_the_e_mod_n =
        (&ciphertext_bigint * &s_to_the_e_mod_n) % &intercepted_pubkey.modulus;
    let c_times_s_to_the_e_mod_n_bytes =
        cryptopal_util::biguint_to_bytes(&c_times_s_to_the_e_mod_n);

    // Submit C', which appears totally different from C, to the server, recovering P', which appears
    // totally different from P
    let p_prime_bytes = state.oracle(&c_times_s_to_the_e_mod_n_bytes)?;
    let p_prime = cryptopal_util::bytes_to_biguint(&p_prime_bytes);

    // Now:
    //           P'
    //     P = -----  mod N
    //           S
    // Oops!
    let p = p_prime
        * rsa::invmod(my_random_number, intercepted_pubkey.modulus.clone())
            .ok_or_else(|| anyhow!("No inverse"))?
        % &intercepted_pubkey.modulus;

    let recovered_plaintext = cryptopal_util::biguint_to_bytes(&p);
    let plaintext_string = cryptopal_util::bytes_to_ascii(&recovered_plaintext)?;
    assert_eq!(plaintext_string, "hi mom");
    Ok(())
}

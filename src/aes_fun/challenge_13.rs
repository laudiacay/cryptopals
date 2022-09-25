use crate::pkcs7::pkcs7_pad;
use crate::random_things::MY_RANDOM_KEY;
use crate::{aes_fun, cryptopal_util};
use anyhow::Result;
use std::collections::HashMap;
use aes_fun::Key;

// Write a k=v parsing routine, as if for a structured cookie. The routine should take:
//
// foo=bar&baz=qux&zap=zazzle
// ... and produce:
//
// {
//   foo: 'bar',
//   baz: 'qux',
//   zap: 'zazzle'
// }
fn parse_kv(input: &str) -> Result<HashMap<String, String>> {
    let mut output = HashMap::new();
    let mut key = String::new();
    let mut value = String::new();
    let mut in_key = true;
    for c in input.chars() {
        if in_key {
            if c == '=' {
                in_key = false;
            } else {
                key.push(c);
            }
        } else if c == '&' {
            output.insert(key, value);
            key = String::new();
            value = String::new();
            in_key = true;
        } else {
            value.push(c);
        }
    }
    output.insert(key, value);
    Ok(output)
}

fn encode_profile(input: &HashMap<String, String>) -> String {
    let mut output = String::new();
    output.push_str("email=");
    output.push_str(&input["email"]);
    output.push_str("&uid=");
    output.push_str(&input["uid"]);
    output.push_str("&role=");
    output.push_str(&input["role"]);
    output
}

// Now write a function that encodes a user profile in that format, given an email address. You should have something like:
//
// profile_for("foo@bar.com")
// ... and it should produce:
//
// {
//   email: 'foo@bar.com',
//   uid: 10,
//   role: 'user'
// }
// ... encoded as:
//
// email=foo@bar.com&uid=10&role=user
// Your "profile_for" function should not allow encoding metacharacters (& and =). Eat them, quote them, whatever you want to do, but don't let people set their email address to "foo@bar.com&role=admin".
fn profile_for(email: &str) -> HashMap<String, String> {
    let email = email.replace('&', "").replace('=', "");
    let mut h = HashMap::new();
    h.insert("email".to_string(), email);
    h.insert("uid".to_string(), "10".to_string());
    h.insert("role".to_string(), "user".to_string());
    h
}

// Now, two more easy functions. Generate a random AES key, then:
//
// Encrypt the encoded user profile under the key; "provide" that to the "attacker".
// Decrypt the encoded user profile and parse it.
// Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts) and the ciphertexts themselves, make a role=admin profile.
fn encrypt_user_profile_and_return(email: String) -> Result<Vec<u8>> {
    let key = MY_RANDOM_KEY.as_slice();
    let input = profile_for(email.as_str());
    let encoded_input = encode_profile(&input);
    let output = aes_fun::ecb::encrypt(&cryptopal_util::ascii_to_bytes(&encoded_input)?, Key(key));
    Ok(output)
}

fn decrypt_user_profile_return_if_admin(ciphertext: Vec<u8>) -> Result<bool> {
    let key = MY_RANDOM_KEY.as_slice();
    let output = aes_fun::ecb::decrypt(&ciphertext, Key(key))?;
    let output = cryptopal_util::bytes_to_ascii(&output)?;
    let profile = parse_kv(&output)?;
    if profile.get("role").unwrap() == "admin" {
        Ok(true)
    } else {
        Ok(false)
    }
}

pub fn attack() -> Result<bool> {
    // "email=????????????&uid=10&role=admin"
    // want to get it so "role=user" ends up on a block border. then we can chop it off and replace it with admin.
    // "email=" is 6 characters long
    // "&uid=10&role=" is 13 characters long
    // padding email= up to the block border
    let mut attack1 = vec![b'A'; 16 - 6];
    // and making a new admin block
    let admin_cute_string = pkcs7_pad(&cryptopal_util::ascii_to_bytes("admin")?, 16);
    attack1.extend_from_slice(&admin_cute_string);
    attack1.extend_from_slice("psh".as_bytes());
    let encrypted_user_profile =
        encrypt_user_profile_and_return(cryptopal_util::bytes_to_ascii(&attack1)?)?;
    let admin_suffix = &encrypted_user_profile[16..32];
    let mut attack2 = encrypted_user_profile[0..16].to_vec();
    attack2.extend_from_slice(&encrypted_user_profile[32..(32 + 16)]);
    attack2.extend_from_slice(admin_suffix);
    decrypt_user_profile_return_if_admin(attack2)
}

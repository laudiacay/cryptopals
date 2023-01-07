// To understand SRP, look at how you generate an AES key from DH; now, just observe you can do the
// "opposite" operation an generate a numeric parameter from a hash. Then:
//
// Replace A and B with C and S (client & server)
//

// You're going to want to do this at a REPL of some sort; it may take a couple tries.
//
// It doesn't matter how you go from integer to string or string to integer (where things are going
// in or out of SHA256) as long as you do it consistently. I tested by using the ASCII decimal
// representation of integers as input to SHA256, and by converting the hexdigest to an integer when
// processing its output.
//
// This is basically Diffie Hellman with a tweak of mixing the password into the public keys. The
// server also takes an extra step to avoid storing an easily crackable password-equivalent.

use crate::hashes::sha256::{hmac_sha256, sha256};
use anyhow::Result;
use num::BigUint;
use rand::random;

const G: u32 = 2;
const K: u32 = 3;

// get a bigint from a hex string hash
fn get_bigint_from_hash(hash: &str) -> BigUint {
    BigUint::parse_bytes(hash.as_bytes(), 16).unwrap()
}

struct S {
    salt: u32,
    v: Option<BigUint>,
    secret_b: BigUint,
    big_b: Option<BigUint>,
    s: Option<BigUint>,
    k: Option<String>,
}

struct C {
    secret_a: BigUint,
    big_a: Option<BigUint>,
    s: Option<BigUint>,
    k: Option<String>,
}

impl C {
    fn new() -> C {
        C {
            secret_a: (random::<u64>()).into(),
            big_a: None,
            s: None,
            k: None,
        }
    }
}

impl S {
    fn new() -> S {
        S {
            salt: random(),
            v: None,
            secret_b: (random::<u64>()).into(),
            big_b: None,
            s: None,
            k: None,
        }
    }
}

pub fn do_srp(_email: String, password: String) -> Result<()> {
    // C & S
    // Agree on N=[NIST Prime], g=2, k=3, I (email), P (password)
    let mut s = S::new();
    let mut c = C::new();
    let n = crate::diffie_hellman::P.clone();

    // S
    // Generate salt as random integer
    // Generate string xH=SHA256(salt|password)
    let server_x_h = sha256(format!("{}{}", s.salt, password).as_bytes());
    // Convert xH to integer x somehow (put 0x on hexdigest)
    let server_x = get_bigint_from_hash(&server_x_h);
    // Generate v=g**x % N
    let v = BigUint::from(G).modpow(&server_x, &n);
    // Save everything but x, xH
    s.v = Some(v);

    // C->S
    // Send I, A=g**a % N (a la Diffie Hellman)
    c.big_a = Some(BigUint::from(G).modpow(&c.secret_a, &n));

    // S->C
    // Send salt, B=kv + g**b % N
    s.big_b = Some(K * s.v.as_ref().unwrap() + BigUint::from(G).modpow(&s.secret_b, &n));

    // S, C
    // Compute string u_h = SHA256(A|B), u = integer of u_h
    let u_h =
        sha256(format!("{}{}", c.big_a.as_ref().unwrap(), s.big_b.as_ref().unwrap()).as_bytes());
    let u = get_bigint_from_hash(&u_h);

    // C
    // Generate string xH=SHA256(salt|password)
    let client_x_h = sha256(format!("{}{}", s.salt, password).as_bytes());
    // Convert xH to integer x somehow (put 0x on hexdigest)
    let client_x = get_bigint_from_hash(&client_x_h);
    // Generate S = (B - k * g**x)**(a + u * x) % N
    c.s = Some(
        (s.big_b.as_ref().unwrap() - K * BigUint::from(G).modpow(&client_x, &n))
            .modpow(&(c.secret_a + &u * client_x), &n),
    );
    // Generate K = SHA256(S)
    c.k = Some(sha256(&c.s.unwrap().to_bytes_be()));

    // S
    // Generate S = (A * v**u) ** b % N
    s.s = Some((c.big_a.unwrap() * s.v.as_ref().unwrap().modpow(&u, &n)).modpow(&s.secret_b, &n));
    // Generate K = SHA256(S)
    s.k = Some(sha256(&s.s.unwrap().to_bytes_be()));

    // C->S
    // Send HMAC-SHA256(K, salt)
    let c_hmac = hmac_sha256(c.k.unwrap().as_bytes(), s.salt.to_string().as_bytes());
    // S->C
    // Send "OK" if HMAC-SHA256(K, salt) validates
    let s_hmac = hmac_sha256(s.k.unwrap().as_bytes(), s.salt.to_string().as_bytes());
    assert_eq!(c_hmac, s_hmac);

    Ok(())
}

// Implement Diffie-Hellman
// For one of the most important algorithms in cryptography this exercise couldn't be a whole lot easier.
//
// Set a variable "p" to 37 and "g" to 5. This algorithm is so easy I'm not even going to explain it. Just do what I do.
//
// Generate "a", a random number mod 37. Now generate "A", which is "g" raised to the "a" power mode 37 --- A = (g**a) % p.
//
// Do the same for "b" and "B".
//
// "A" and "B" are public keys. Generate a session key with them; set "s" to "B" raised to the "a" power mod 37 --- s = (B**a) % p.
//
// Do the same with A**b, check that you come up with the same "s".
//
// To turn "s" into a key, you can just hash it to create 128 bits of key material (or SHA256 it to create a key for encrypting and a key for a MAC).
//
// Ok, that was fun, now repeat the exercise with bignums like in the real world. Here are parameters NIST likes:
//
// p:
// ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
// e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
// 3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
// 6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
// 24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
// c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
// bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
// fffffffffffff
//
// g: 2
// This is very easy to do in Python or Ruby or other high-level languages that auto-promote fixnums to bignums, but it isn't "hard" anywhere.
//
// Note that you'll need to write your own modexp (this is blackboard math, don't freak out), because you'll blow out your bignum library raising "a" to the 1024-bit-numberth power. You can find modexp routines on Rosetta Code for most languages.

use num::bigint::ToBigInt;
use num::{BigInt, One, Zero};
lazy_static::lazy_static! {
pub static ref P : BigInt = "fffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
fffffffffffff".parse().unwrap();
    pub static ref G : BigInt = 2.to_bigint().unwrap();
}

// The modular_exponentiation() function takes three identical types
// (which get cast to BigInt), and returns a BigInt:
fn modular_exponentiation<T: ToBigInt>(n: &T, e: &T, m: &T) -> BigInt {
    // Convert n, e, and m to BigInt:
    let n = n.to_bigint().unwrap();
    let e = e.to_bigint().unwrap();
    let m = m.to_bigint().unwrap();

    // Sanity check:  Verify that the exponent is not negative:
    assert!(e >= Zero::zero());

    // As most modular exponentiations do, return 1 if the exponent is 0:
    if e == Zero::zero() {
        return One::one();
    }

    // Now do the modular exponentiation algorithm:
    let mut result: BigInt = One::one();
    let mut base = n % &m;
    let mut exp = e;

    // Loop until we can return out result:
    loop {
        if &exp % 2 == One::one() {
            result *= &base;
            result %= &m;
        }

        if exp == One::one() {
            return result;
        }

        exp /= 2;
        base *= base.clone();
        base %= &m;
    }
}

pub fn diffie_hellman(p: BigInt, g: BigInt, a: BigInt, b: BigInt) -> BigInt {
    let a_exp = modular_exponentiation(&g, &a, &p);
    let b_exp = modular_exponentiation(&g, &b, &p);
    let s1 = modular_exponentiation(&b_exp, &a, &p);
    let s2 = modular_exponentiation(&a_exp, &b, &p);
    assert_eq!(s1, s2);
    s1
}

// Implement RSA
use num_primes::Generator;

// There are two annoying things about implementing RSA. Both of them involve key generation; the actual encryption/decryption in RSA is trivial.
//
// The second is that you need an "invmod" operation (the multiplicative inverse), which is not an
// operation that is wired into your language. The algorithm is just a couple lines, but I always
// lose an hour getting it to work.
//
// I recommend you not bother with primegen, but do take the time to get your own EGCD and invmod algorithm working.
//
// Now:
//
// Generate 2 random primes. We'll use small numbers to start, so you can just pick them out of a
// prime table. Call them "p" and "q".
// Let n be p * q. Your RSA math is modulo n.
// Let et be (p-1)*(q-1) (the "totient"). You need this value only for keygen.
// Let e be 3.
// Compute d = invmod(e, et). invmod(17, 3120) is 2753.
// Your public key is [e, n]. Your private key is [d, n].
// To encrypt: c = m**e%n. To decrypt: m = c**d%n
// Test this out with a number, like "42".
// Repeat with bignum primes (keep e=3).
// Finally, to encrypt a string, do something cheesy, like convert the string to hex and put "0x" on the front of it to turn it into a number. The math cares not how stupidly you feed it strings.

use crate::cryptopal_util::modular_exponentiation;
use num::{BigUint, One, Zero, BigInt};

pub struct RsaKey {
    p: BigUint,
    q: BigUint,
    pub modulus: BigUint,
    pub public_exponent: BigUint,
    private_exponent: BigUint,
}

impl RsaKey {
    fn gen_prime(bits: usize) -> BigUint {
        let prime = Generator::new_prime(bits);
        let prime_string = prime.to_string();
        let prime_biguint = BigUint::parse_bytes(prime_string.as_bytes(), 10).unwrap();
        prime_biguint
    }

    fn new(bits: usize) -> Self {
        let p = RsaKey::gen_prime(bits);
        let q = RsaKey::gen_prime(bits);
        let n = &p * &q;
        let et = (&p - 1u32) * (&q - 1u32);
        let e = BigUint::from(3u32);
        let d = invmod(e.clone(), et);
        RsaKey {
            p,
            q,
            modulus: n,
            public_exponent: e,
            private_exponent: d,
        }
    }

    fn encrypt(&self, m: &BigUint) -> BigUint {
        modular_exponentiation(m, &self.public_exponent, &self.modulus)
    }

    fn decrypt(&self, c: &BigUint) -> BigUint {
        modular_exponentiation(c, &self.private_exponent, &self.modulus)
    }
}

fn egcd(a: &BigUint, b: &BigUint) -> (BigUint, BigUint, BigUint) {
    if b == &BigUint::zero() {
        return (a.clone(), BigUint::one(), BigUint::zero());
    }
    let (g, y, x) = egcd(b, &(a % b));
    (g, x.clone(), y - (a / b) * x)
}

fn invmod(a: BigUint, m: BigUint) -> BigUint {
    //function extended_gcd(a, b)
    //     s := 0;    old_s := 1
    //     r := b;    old_r := a
    //
    //     while r ≠ 0 do
    //         quotient := old_r div r
    //         (old_r, r) := (r, old_r − quotient × r)
    //         (old_s, s) := (s, old_s − quotient × s)
    //
    //     if b ≠ 0 then
    //         bezout_t := (old_r − old_s × a) div b
    //     else
    //         bezout_t := 0
    //
    //     output "Bézout coefficients:", (old_s, bezout_t)
    //     output "greatest common divisor:", old_r
    let m_int = BigInt::from(m);
    let mut mn: (BigInt, BigInt) = (m_int.clone(), a.into());
    let mut xy: (BigInt, BigInt) = (Zero::zero(), One::one());

    while mn.1 != Zero::zero() {
        xy = (xy.1.clone(), xy.0 - (mn.0.clone() / mn.1.clone()) * xy.1);
        mn = (mn.1.clone(), mn.0 % mn.1);
    }

    while xy.0 < Zero::zero() {
        xy.0 += m_int.clone();
    }

    xy.0.try_into().unwrap()
}

#[cfg(test)]
mod test_rsa {
    use num::BigUint;

    #[test]
    fn test_invmod() {
        //invmod(17, 3120) is 2753
        let a = BigUint::from(17u64);
        let m = BigUint::from(3120u64);
        let inv = super::invmod(a, m);
        assert_eq!(inv, BigUint::from(2753u64));
    }

    #[test]
    fn test_rsa() {
        let m = BigUint::from(42u64);
        for _ in 0..30 {
            let key = super::RsaKey::new(32);
            let c = key.encrypt(&m);
            let m2 = key.decrypt(&c);
            assert_eq!(m, m2);
        }
    }
}

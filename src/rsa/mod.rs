// Implement RSA
use num::bigint::ToBigUint;
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
use num::{BigInt, BigUint, One, Zero};

#[derive(Debug)]
pub struct RsaKey {
    _p: BigUint,
    _q: BigUint,
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
        loop {
            let p = RsaKey::gen_prime(bits);
            let q = RsaKey::gen_prime(bits);
            let n = &p * &q;
            let totient_n = (&p - 1u32) * (&q - 1u32);
            let e = BigUint::from(3u32);
            let d = invmod(e.clone(), totient_n);
            if let Some(d) = d {
                return RsaKey {
                    _p: p,
                    _q: q,
                    modulus: n,
                    public_exponent: e,
                    private_exponent: d,
                };
            }
        }
    }

    fn encrypt(&self, m: &BigUint) -> BigUint {
        modular_exponentiation(m, &self.public_exponent, &self.modulus)
            .to_biguint()
            .unwrap()
    }

    fn decrypt(&self, c: &BigUint) -> BigUint {
        modular_exponentiation(c, &self.private_exponent, &self.modulus)
            .to_biguint()
            .unwrap()
    }
}

fn egcd(a: &BigUint, b: &BigUint) -> (BigUint, BigInt, BigInt) {
    println!("egcd({}, {})", a, b);
    let (mut old_r, mut r): (BigInt, BigInt) = (a.clone().into(), b.clone().into());
    let (mut old_s, mut s) = (BigInt::one(), BigInt::zero());
    let (mut old_t, mut t) = (BigInt::zero(), BigInt::one());

    while r != BigInt::zero() {
        let quotient = &old_r / &r;
        let (new_r, new_s, new_t) = (
            &old_r - &quotient * &r,
            &old_s - &quotient * &s,
            &old_t - &quotient * &t,
        );
        old_r = r;
        old_s = s;
        old_t = t;
        r = new_r;
        s = new_s;
        t = new_t;
    }

    (BigUint::try_from(old_r).unwrap(), old_s, old_t)
}

fn invmod(a: BigUint, m: BigUint) -> Option<BigUint> {
    let (g, x, _y) = egcd(&a, &m);
    println!("g: {}, x: {}, y: {}", g, x, _y);
    if g != BigUint::one() {
        return None;
    }
    let bigint_modulo = BigInt::try_from(m).unwrap();
    Some(if x < Zero::zero() {
        BigUint::try_from(x + bigint_modulo).unwrap()
    } else {
        BigUint::try_from(x).unwrap()
    })
}

#[cfg(test)]
mod test_rsa {
    use num::{BigInt, BigUint};

    #[test]
    fn test_invmod() {
        //invmod(17, 3120) is 2753
        let a = BigUint::from(17u64);
        let m = BigUint::from(3120u64);
        let inv = super::invmod(a, m).unwrap();
        assert_eq!(inv, BigUint::from(2753u64));
    }

    #[test]
    fn test_egcd() {
        //egcd(240,46) = (2, -9, 47)
        let a = BigUint::from(240u64);
        let b = BigUint::from(46u64);
        let (g, x, y) = super::egcd(&a, &b);
        assert_eq!(g, BigUint::from(2u64));
        assert_eq!(x, BigInt::from(-9i64));
        assert_eq!(y, BigInt::from(47i64));
    }

    use crate::rsa::RsaKey;
    #[test]
    fn test_rsa() {
        let m = BigUint::from(2u64);
        let key = RsaKey {
            p: BigUint::from(3u64),
            q: BigUint::from(11u64),
            modulus: BigUint::from(33u64),
            public_exponent: BigUint::from(7u64),
            private_exponent: BigUint::from(3u64),
        };
        let c = key.encrypt(&m);
        assert_eq!(c, BigUint::from(29u64));
        let m2 = key.decrypt(&c);
        assert_eq!(m2, m);
        for i in 0..30 {
            println!("iteration {}!", i);
            let key = RsaKey::new(10);
            println!("key: {:?}", key);
            let c = key.encrypt(&m);
            let m2 = key.decrypt(&c);
            assert_eq!(m, m2);
        }
    }
}

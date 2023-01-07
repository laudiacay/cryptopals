// Implement DH with negotiated groups, and break with malicious "g" parameters

use crate::aes_fun::{
    cbc::{decrypt, encrypt},
    Iv, Key,
};
use crate::diffie_hellman::{G, P};
use crate::hashes::sha1::sha1;
use crate::random_things::sixteen_random_bytes;
use num::bigint::ToBigUint;

use crate::aes_fun::cbc;
use crate::cryptopal_util;
use num::bigint::RandBigInt;
use num::{BigUint, One, Zero};

struct A {
    p: BigUint,
    g: BigUint,
    secret_a: BigUint,
    big_a: BigUint,
    big_b: Option<BigUint>,
    s: Option<BigUint>,
}
impl A {
    fn new(g: BigUint) -> A {
        let p = P.clone();

        let rng = &mut rand::thread_rng();
        let secret_a = rng.gen_biguint_below(&p);
        let big_a = cryptopal_util::modular_exponentiation(&g, &secret_a, &p);
        A {
            p,
            g,
            secret_a,
            big_a,
            big_b: None,
            s: None,
        }
    }

    fn get_handshake(&mut self, big_b: BigUint) {
        self.big_b = Some(big_b.clone());
        self.s = Some(cryptopal_util::modular_exponentiation(
            &big_b,
            &self.secret_a.clone(),
            &self.p.clone(),
        ));
    }

    fn send_msg_to_b(&self, msg: &[u8]) -> Vec<u8> {
        match (&self.big_b, &self.s) {
            (Some(_), Some(s)) => {
                // AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
                let key = sha1(&s.to_bytes_be())[..16].to_vec();
                // make some random bytes for the iv
                let iv = sixteen_random_bytes();
                let encrypted = cbc::encrypt(msg, Key(&key), Iv(&iv)).unwrap();
                let mut res = encrypted;
                res.extend_from_slice(&iv);
                res
            }
            (_, _) => panic!("didn't do the handshake, looks like..."),
        }
    }

    fn decrypt_msg_from_b(&self, enc_msg: &[u8]) -> String {
        match (&self.big_b, &self.s) {
            (Some(_), Some(_)) => (),
            (_, _) => panic!("didn't do the handshake, looks like..."),
        }
        // AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
        let s_bytes = self.s.as_ref().unwrap().to_bytes_be();
        let key = sha1(&s_bytes)[..16].to_vec();
        // make some random bytes for the iv
        let (encrypted, iv) = enc_msg.split_at(enc_msg.len() - 16);
        let msg = decrypt(encrypted, Key(&key), Iv(iv)).unwrap();
        let msg = String::from_utf8(msg).unwrap();
        println!("A got message: {msg}");
        msg
    }
}

struct B {
    _secret_b: BigUint,
    big_b: BigUint,
    s: BigUint,
}
impl B {
    fn new(p: BigUint, g: BigUint, big_a: BigUint) -> B {
        let rng = &mut rand::thread_rng();
        let secret_b = rng.gen_biguint_below(&p);
        let big_b = cryptopal_util::modular_exponentiation(&g, &secret_b, &p);
        let s = cryptopal_util::modular_exponentiation(&big_a, &secret_b, &p);
        B {
            _secret_b: secret_b,
            big_b: big_b.to_biguint().unwrap(),
            s: s.to_biguint().unwrap(),
        }
    }

    fn send_b(&self) -> BigUint {
        self.big_b.clone()
    }

    fn decrypt_and_send_msg_to_a(&self, enc_msg: &[u8]) -> (String, Vec<u8>) {
        let key = sha1(&(self.s.to_bytes_be()))[..16].to_vec();
        let (encrypted, iv) = enc_msg.split_at(enc_msg.len() - 16);
        let msg = decrypt(encrypted, Key(&key), Iv(iv)).unwrap();
        let msg_str = String::from_utf8(msg.clone()).unwrap();
        println!("B got message: {msg_str}");
        // re encrypt
        // AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
        let iv = sixteen_random_bytes();
        let encrypted = encrypt(&msg, Key(&key), Iv(&iv)).unwrap();
        let mut res = encrypted;
        res.extend_from_slice(&iv);
        (msg_str, res)
    }
}

pub fn normal_diffie_hellman_message_exchange() {
    // Use the code you just worked out to build a protocol and an "echo" bot. You don't actually have
    // to do the network part of this if you don't want; just simulate that.
    // (In other words, derive an AES key from DH with SHA1, use it in both directions, and do CBC with
    // random IVs appended or prepended to the message).

    // A->B
    // Send "p", "g", "A"
    let mut a_guy = A::new(G.clone());
    // B->A
    // Send "B"
    let b_guy = B::new(a_guy.p.clone(), a_guy.g.clone(), a_guy.big_a.clone());
    a_guy.get_handshake(b_guy.send_b());
    // A->B
    // Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
    let msg = b"hello, world!";
    let enc_msg = a_guy.send_msg_to_b(msg.as_slice());
    // B->A
    // Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
    let (a_msg_decrypted_by_b, enc_msg_b) = b_guy.decrypt_and_send_msg_to_a(&enc_msg);
    let b_msg_decrypted_by_a = a_guy.decrypt_msg_from_b(&enc_msg_b);
    assert_eq!(a_msg_decrypted_by_b, b_msg_decrypted_by_a);
    assert_eq!(
        a_msg_decrypted_by_b,
        String::from_utf8(msg.to_vec()).unwrap()
    );
}

fn badguy_decrypt(enc_msg: &[u8], a_s: BigUint) -> String {
    let key = sha1(&a_s.to_bytes_be())[..16].to_vec();
    let (encrypted, iv) = enc_msg.split_at(enc_msg.len() - 16);
    let msg = decrypt(encrypted, Key(&key), Iv(iv)).unwrap();
    String::from_utf8(msg).unwrap()
}

pub fn evil_diffie_hellman_message_exchange() {
    // when g = 1, s = 1. so the key is just SHA1(1)[0:16]
    let mut a_guy = A::new(BigUint::one());
    let p = a_guy.p.clone();
    let b_guy = B::new(p, BigUint::one(), a_guy.big_a.clone());
    let big_b = b_guy.send_b();
    a_guy.get_handshake(big_b);
    assert_eq!(b_guy.s, BigUint::one());
    assert_eq!(a_guy.s, Some(BigUint::one()));
    let msg = b"hello, world!";
    let enc_msg_a = a_guy.send_msg_to_b(msg.as_slice());

    let (a_msg_decrypted_by_b, enc_msg_b) = b_guy.decrypt_and_send_msg_to_a(&enc_msg_a);
    let b_msg_decrypted_by_a = a_guy.decrypt_msg_from_b(&enc_msg_b);

    assert_eq!(a_msg_decrypted_by_b, b_msg_decrypted_by_a);
    assert_eq!(
        a_msg_decrypted_by_b,
        String::from_utf8(msg.to_vec()).unwrap()
    );
    assert_eq!(
        a_msg_decrypted_by_b,
        badguy_decrypt(&enc_msg_b, BigUint::one())
    );
    // when g = p, s = 0. so the key is just SHA1(0)[0:16]
    let mut a_guy = A::new(P.clone());
    let p = a_guy.p.clone();
    let b_guy = B::new(p, a_guy.g.clone(), a_guy.big_a.clone());
    let big_b = b_guy.send_b();
    a_guy.get_handshake(big_b);
    assert_eq!(a_guy.s, Some(BigUint::zero()));
    assert_eq!(b_guy.s, BigUint::zero());
    let msg = b"hello, world!";
    let enc_msg_a = a_guy.send_msg_to_b(msg.as_slice());

    let (a_msg_decrypted_by_b, enc_msg_b) = b_guy.decrypt_and_send_msg_to_a(&enc_msg_a);
    let b_msg_decrypted_by_a = a_guy.decrypt_msg_from_b(&enc_msg_b);

    assert_eq!(a_msg_decrypted_by_b, b_msg_decrypted_by_a);
    assert_eq!(
        a_msg_decrypted_by_b,
        String::from_utf8(msg.to_vec()).unwrap()
    );
    assert_eq!(
        a_msg_decrypted_by_b,
        badguy_decrypt(&enc_msg_a, BigUint::zero())
    );

    // when g = p - 1, s = (p-1)^ab = p^ab + x_1 p ^(ab-1) + ... + x_i p ^2 + x_j plus/minus 1
    //      all of these mod p are zero except for the last one, which is +- 1. so the key is just SHA1(1)[0:16]
    //      so the key is just SHA1(p - 1)[0:16] if ab is odd, and SHA1(1)[0:16] if ab is even, i think?
    let mut a_guy = A::new(P.clone() - BigUint::one());
    let p = a_guy.p.clone();
    let b_guy = B::new(p, a_guy.g.clone(), a_guy.big_a.clone());
    let big_b = b_guy.send_b();
    a_guy.get_handshake(big_b);
    assert_eq!(a_guy.s, Some(BigUint::one()));
    assert_eq!(b_guy.s, BigUint::one());
    let msg = b"hello, world!";
    let enc_msg_a = a_guy.send_msg_to_b(msg.as_slice());

    let (a_msg_decrypted_by_b, enc_msg_b) = b_guy.decrypt_and_send_msg_to_a(&enc_msg_a);
    let b_msg_decrypted_by_a = a_guy.decrypt_msg_from_b(&enc_msg_b);

    assert_eq!(a_msg_decrypted_by_b, b_msg_decrypted_by_a);
    assert_eq!(
        a_msg_decrypted_by_b,
        String::from_utf8(msg.to_vec()).unwrap()
    );
    assert_eq!(
        a_msg_decrypted_by_b,
        badguy_decrypt(&enc_msg_a, BigUint::one())
    );
}

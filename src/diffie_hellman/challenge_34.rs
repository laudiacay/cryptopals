// Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection

use crate::aes_fun::{
    cbc::{decrypt, encrypt},
    Iv, Key,
};
use crate::diffie_hellman::{modular_exponentiation, G, P};
use crate::random_things::sixteen_random_bytes;
use crate::sha1::sha1;

use crate::aes_fun::cbc;
use num::bigint::RandBigInt;
use num::{BigUint, Zero};

struct A {
    p: BigUint,
    g: BigUint,
    secret_a: BigUint,
    big_a: BigUint,
    big_b: Option<BigUint>,
    s: Option<BigUint>,
}
impl A {
    fn new(p: BigUint, g: BigUint) -> A {
        let rng = &mut rand::thread_rng();
        let secret_a = rng.gen_biguint_below(&p);
        let big_a = modular_exponentiation(&g, &secret_a, &p);
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
        self.s = Some(modular_exponentiation(
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
        println!("A got message: {}", msg);
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
        let big_b = modular_exponentiation(&g, &secret_b, &p);
        let s = modular_exponentiation(&big_a, &secret_b, &p);
        B {
            _secret_b: secret_b,
            big_b,
            s,
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
        println!("B got message: {}", msg_str);
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
    let mut a_guy = A::new(P.clone(), G.clone());
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

// the secret is that a just encrypts with s=0 and b just encrypts with s=0
// this happens because p ^ x mod p == 0 always lol
//
fn badguy_decrypt_a_to_b(enc_msg: &[u8], a_s: BigUint) -> String {
    let key = sha1(&a_s.to_bytes_be())[..16].to_vec();
    let (encrypted, iv) = enc_msg.split_at(enc_msg.len() - 16);
    let msg = decrypt(encrypted, Key(&key), Iv(iv)).unwrap();
    String::from_utf8(msg).unwrap()
}

fn badguy_decrypt_b_to_a(enc_msg: &[u8], b_s: BigUint) -> String {
    let key = sha1(&b_s.to_bytes_be())[..16].to_vec();
    let (encrypted, iv) = enc_msg.split_at(enc_msg.len() - 16);
    let msg = decrypt(encrypted, Key(&key), Iv(iv)).unwrap();
    String::from_utf8(msg).unwrap()
}

pub fn evil_diffie_hellman_message_exchange() {
    // M should be able to decrypt the messages. "A" and "B" in the protocol --- the public keys, over
    // the wire --- have been swapped out with "p". Do the DH math on this quickly to see what that does
    // to the predictability of the key.
    //
    // Decrypt the messages from M's vantage point as they go by.
    //
    // Note that you don't actually have to inject bogus parameters to make this attack work; you could
    // just generate Ma, MA, Mb, and MB as valid DH parameters to do a generic MITM attack. But do the
    // parameter injection attack; it's going to come up again.

    // A->M
    // Send "p", "g", "A"
    let mut a_guy = A::new(P.clone(), G.clone());
    let p = a_guy.p.clone();
    // M->B
    // Send "p", "g", "p"
    let b_guy = B::new(p.clone(), a_guy.g.clone(), p.clone());
    // B->M
    // Send "B"
    let _big_b = b_guy.send_b();
    // M->A
    // Send "p"
    a_guy.get_handshake(p);
    assert_eq!(a_guy.s, Some(BigUint::zero()));
    assert_eq!(b_guy.s, BigUint::zero());
    // A->M
    // Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
    let msg = b"hello, world!";
    let enc_msg_a = a_guy.send_msg_to_b(msg.as_slice());

    // M->B
    // Relay that to B
    // B->M
    // Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
    let (a_msg_decrypted_by_b, enc_msg_b) = b_guy.decrypt_and_send_msg_to_a(&enc_msg_a);
    // M->A
    // Relay that to A
    let b_msg_decrypted_by_a = a_guy.decrypt_msg_from_b(&enc_msg_b);

    assert_eq!(a_msg_decrypted_by_b, b_msg_decrypted_by_a);
    assert_eq!(
        a_msg_decrypted_by_b,
        String::from_utf8(msg.to_vec()).unwrap()
    );
    assert_eq!(
        a_msg_decrypted_by_b,
        badguy_decrypt_a_to_b(&enc_msg_a, BigUint::zero())
    );
    assert_eq!(
        b_msg_decrypted_by_a,
        badguy_decrypt_b_to_a(&enc_msg_b, BigUint::zero())
    );
}

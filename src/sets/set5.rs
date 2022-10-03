#[cfg(test)]
mod tests {
    use crate::rsa::RsaKey;
    use crate::{diffie_hellman, rsa};
    use num::BigUint;

    #[test]
    fn s5c33_implement_diffie_hellman() {
        // Set a variable "p" to 37 and "g" to 5. This algorithm is so easy I'm not even going to explain it. Just do what I do.
        //
        // Generate "a", a random number mod 37. Now generate "A", which is "g" raised to the "a" power mode 37 --- A = (g**a) % p.
        //
        // Do the same for "b" and "B".
        //
        // "A" and "B" are public keys. Generate a session key with them; set "s" to "B" raised to the "a" power mod 37 --- s = (B**a) % p.
        //
        // Do the same with A**b, check that you come up with the same "s".
        diffie_hellman::diffie_hellman(37_u32.into(), 5_u32.into(), 18_u32.into(), 17_u32.into());
    }

    #[test]
    fn s5c34_implement_mitm_key_fixing_attack_on_diffie_hellman() {
        diffie_hellman::challenge_34::normal_diffie_hellman_message_exchange();
        diffie_hellman::challenge_34::evil_diffie_hellman_message_exchange();
    }

    #[test]
    fn s5c35_implement_dh_with_negotiated_groups_and_break_with_malicious_g_parameters() {
        diffie_hellman::challenge_35::normal_diffie_hellman_message_exchange();
        diffie_hellman::challenge_35::evil_diffie_hellman_message_exchange();
    }

    #[test]
    fn s5c36_implement_srp() {
        unimplemented!();
    }

    #[test]
    fn s5c37_break_srp_with_zero_key() {
        unimplemented!();
    }

    #[test]
    fn s5c38_offline_dictionary_attack_on_simplified_srp() {
        unimplemented!();
    }

    #[test]
    fn s5c39_implement_rsa() {
        let m = BigUint::from(2u64);
        let key = RsaKey {
            _p: BigUint::from(3u64),
            _q: BigUint::from(11u64),
            modulus: BigUint::from(33u64),
            public_exponent: BigUint::from(7u64),
            private_exponent: BigUint::from(3u64),
        };
        let c = key.encrypt(&m).unwrap();
        assert_eq!(c, BigUint::from(29u64));
        let m2 = key.decrypt(&c).unwrap();
        assert_eq!(m2, m);
        for i in 0..30 {
            println!("iteration {}!", i);
            let key = RsaKey::new(20);
            println!("key: {:?}", key);
            let c = key.encrypt(&m).unwrap();
            let m2 = key.decrypt(&c).unwrap();
            assert_eq!(m, m2);
        }
    }

    #[test]
    fn s5c40_implement_e_3_rsa_broadcast_attack() {
        rsa::challenge_40::attack().unwrap()
    }
}

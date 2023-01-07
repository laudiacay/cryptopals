use hmac::{Hmac, Mac};
use sha2::Digest;
use sha2::Sha256;

pub fn sha256(msg: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(msg);
    hasher
        .finalize()
        .to_vec()
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 20] {
    let mut hmaccer = Hmac::<Sha256>::new_from_slice(key).unwrap();
    hmaccer.update(msg);
    hmaccer.finalize().into_bytes()[..20].try_into().unwrap()
}

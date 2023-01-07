use sha1_smol;

pub fn sha1(msg: &[u8]) -> [u8; 20] {
    let mut hasher = sha1_smol::Sha1::new();
    hasher.update(msg);
    hasher.digest().bytes()
}

pub fn mac(key: &[u8], msg: &[u8]) -> [u8; 20] {
    let mut hasher = sha1_smol::Sha1::new();
    hasher.update(key);
    hasher.update(msg);
    hasher.digest().bytes()
}

pub fn verify_mac(key: &[u8], msg: &[u8], mac: &[u8]) -> bool {
    let mut hasher = sha1_smol::Sha1::new();
    hasher.update(key);
    hasher.update(msg);
    hasher.digest().bytes() == mac
}

pub fn hmac_sha1(key: &[u8], msg: &[u8]) -> [u8; 20] {
    let mut hasher = sha1_smol::Sha1::new();
    let key = match key.len() {
        ..=63 => {
            let mut new_key = vec![0; 64];
            new_key[..key.len()].copy_from_slice(key);
            new_key
        }
        64.. => {
            // create a vec from the hash of the key
            let mut key_vec = vec![0; 20];
            key_vec.copy_from_slice(&sha1(key));
            key_vec
        }
        _ => panic!("key length is weird"),
    };
    let o_key_pad = key.iter().map(|&x| x ^ 0x5c).collect::<Vec<_>>();
    let i_key_pad = key.iter().map(|&x| x ^ 0x36).collect::<Vec<_>>();
    hasher.update(&i_key_pad);
    hasher.update(msg);
    let inner_hash = hasher.digest().bytes();
    hasher.reset();
    hasher.update(&o_key_pad);
    hasher.update(&inner_hash);
    hasher.digest().bytes()
}

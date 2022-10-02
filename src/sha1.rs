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

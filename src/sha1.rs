use sha1_smol;

pub fn sha1(msg: &[u8]) -> [u8; 20] {
    let mut hasher = sha1_smol::Sha1::new();
    hasher.update(msg);
    hasher.digest().bytes()
}

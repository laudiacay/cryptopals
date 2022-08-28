use rand::Rng;

// Generate a random AES key.
lazy_static::lazy_static! {
    pub static ref MY_RANDOM_KEY: Vec<u8> = {
        let mut key = [0u8; 16];
        rand::thread_rng().fill(&mut key);
        key.to_vec()
    };

    pub static ref MY_RANDOM_IV: Vec<u8> = {
        let mut key = [0u8; 16];
        rand::thread_rng().fill(&mut key);
        key.to_vec()
    };
}

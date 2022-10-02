use core::num::Wrapping;
use rand::Rng;
use rand_mt::Mt19937GenRand32;
use std::iter;

const N: usize = 624;
const M: u32 = 397;

const A: u32 = 0x9908B0DF;
const U: usize = 11;
const S: usize = 7;
const B: Wrapping<u32> = Wrapping(0x9D2C5680);
const T: usize = 15;
const C: Wrapping<u32> = Wrapping(0xEFC60000);
const L: usize = 18;
const F: Wrapping<u32> = Wrapping(1812433253);

const UPPER_MASK: Wrapping<u32> = Wrapping(0x8000_0000);
const LOWER_MASK: Wrapping<u32> = Wrapping(0x7fff_ffff);

pub struct TheirMersenneTwister(Mt19937GenRand32);

impl TheirMersenneTwister {
    pub fn new(seed: u32) -> Self {
        Self(Mt19937GenRand32::new(seed))
    }
    pub fn extract_number(&mut self) -> u32 {
        self.0.next_u32()
    }
}

pub struct MersenneTwister {
    index: usize,
    mt: [Wrapping<u32>; N],
}

impl MersenneTwister {
    pub fn reseed(&mut self, seed: u32) {
        self.index = N;
        self.mt[0] = Wrapping(seed);
        for i in 1..N {
            self.mt[i] = F * (self.mt[i - 1] ^ (self.mt[i - 1] >> 30)) + Wrapping(i as u32);
        }
    }

    pub fn new(seed: u32) -> MersenneTwister {
        let mut mt = MersenneTwister {
            index: N,
            mt: [Wrapping(0_u32); N],
        };
        //mt.seed(seed);
        mt.reseed(seed);
        mt
    }

    pub fn extract_number(&mut self) -> u32 {
        if self.index >= N {
            if self.index > N {
                panic!("Generator was never seeded");
            }
            self.twist();
        }
        let y = self.mt[self.index];
        let y1 = y ^ (y >> U);
        let y2 = y1 ^ ((y1 << S) & B);
        let y3 = y2 ^ ((y2 << T) & C);
        let y4 = y3 ^ (y3 >> L);
        self.index += 1;
        y4.0
    }
    fn twist(&mut self) {
        for i in 0..N {
            let x: Wrapping<u32> = (self.mt[i] & UPPER_MASK) + (self.mt[(i + 1) % N] & LOWER_MASK);
            let mut x_a = x >> 1;
            if (x % Wrapping(2_u32)) != Wrapping(0_u32) {
                x_a ^= A;
            }
            self.mt[i] = self.mt[((i + M as usize) % N) as usize] ^ x_a;
        }
        self.index = 0;
    }
    fn untemper(&self, y4: u32) -> u32 {
        let y4 = Wrapping(y4);
        let my_y3 = y4 ^ (y4 >> L);
        let my_y2 = my_y3 ^ ((my_y3 << T) & C);
        let maskie1: Wrapping<u32> = Wrapping(0b1111111);
        let ya = my_y2 ^ ((my_y2 << S) & B & (maskie1 << S));
        let yb = ya ^ ((ya << S) & B & (maskie1 << (S * 2)));
        let yc = yb ^ ((yb << S) & B & (maskie1 << (S * 3)));
        let my_y1 = yc ^ ((yc << S) & B & (maskie1 << (S * 4)));
        let maskie2: Wrapping<u32> = Wrapping(0b11111111111);
        let ya = my_y1 ^ ((my_y1 >> U) & (maskie2 << (U * 2)));
        let yb = ya ^ ((ya >> U) & (maskie2 << (U)));
        let my_y = yb ^ ((yb >> U) & maskie2);
        my_y.0
    }
}

pub fn reconstruct_mersenne_state(numbers: &[u32]) -> MersenneTwister {
    let mut mt = MersenneTwister {
        index: N,
        mt: [Wrapping(0_u32); N],
    };
    for (i, &y4) in numbers.iter().enumerate() {
        mt.mt[i] = Wrapping(mt.untemper(y4));
    }
    mt
}

pub fn crack_mersenne_seed_from_timestamp(now: u32, output: u32) -> u32 {
    let mut mt = MersenneTwister::new(0);
    for i in now - 10000..now {
        mt.reseed(i);
        if mt.extract_number() == output {
            return i;
        }
    }
    panic!("No seed found");
}

// Create the MT19937 stream cipher and break it
// You can create a trivial stream cipher out of any PRNG; use it to generate a sequence of 8 bit outputs and call those outputs a keystream. XOR each byte of plaintext with each successive byte of keystream.
//
// Write the function that does this for MT19937 using a 16-bit seed. Verify that you can encrypt and decrypt properly. This code should look similar to your CTR code.
pub fn mersenne_stream_cipher_encrypt(key: u16, plaintext: &[u8]) -> Vec<u8> {
    let mut mt = MersenneTwister::new(key as u32);
    let mut ciphertext = Vec::new();
    for plaintext_byte in plaintext.iter() {
        ciphertext.push(mt.extract_number() as u8 ^ plaintext_byte);
    }
    ciphertext
}

pub fn mersenne_stream_cipher_decrypt(key: u16, ciphertext: &[u8]) -> Vec<u8> {
    mersenne_stream_cipher_encrypt(key, ciphertext)
}

// Use your function to encrypt a known plaintext (say, 14 consecutive 'A' characters) prefixed by a random number of random characters.
pub fn oracle_smallkey() -> (u16, Vec<u8>) {
    let mut rng = rand::thread_rng();
    let key = rng.gen_range(0..0xffff);
    let plaintext_length = rng.gen_range(0..100);
    // generate plaintext_length bytes of random data
    let mut plaintext: Vec<u8> = Vec::new();
    for _ in 0..plaintext_length {
        plaintext.push(rng.gen_range(0..0xff));
    }
    plaintext.extend(iter::repeat(b'a').take(14));
    let ciphertext = mersenne_stream_cipher_encrypt(key, &plaintext);
    (key, ciphertext)
}
pub fn oracle_timekey(current_time: u32) -> (u16, Vec<u8>) {
    let key = current_time as u16;
    let mut rng = rand::thread_rng();
    let plaintext_length = rng.gen_range(0..100);
    // generate plaintext_length bytes of random data
    let mut plaintext: Vec<u8> = Vec::new();
    for _ in 0..plaintext_length {
        plaintext.push(rng.gen_range(0..0xff));
    }
    plaintext.extend(iter::repeat(b'a').take(14));
    let ciphertext = mersenne_stream_cipher_encrypt(key, &plaintext);
    (key, ciphertext)
}

//
// From the ciphertext, recover the "key" (the 16 bit seed).
//
// Use the same idea to generate a random "password reset token" using MT19937 seeded from the current time.
//
// Write a function to check if any given password token is actually the product of an MT19937 PRNG seeded with the current time.
pub fn mersenne_stream_cipher_crack_smallkey(ciphertext: &[u8]) -> u16 {
    for key in 0..=65535 {
        let plaintext = mersenne_stream_cipher_decrypt(key, ciphertext);
        if plaintext.iter().rev().take(14).all(|&x| x == b'a') {
            return key;
        }
    }
    panic!("No key found");
}
// Write a function to check if any given password token is actually the product of an MT19937 PRNG seeded with the current time.
pub fn mersenne_stream_cipher_crack_timekey(current_time: u32, ciphertext: &[u8]) -> u16 {
    for key in current_time - 10000..current_time {
        let plaintext = mersenne_stream_cipher_decrypt(key as u16, ciphertext);
        if plaintext.iter().rev().take(14).all(|&x| x == b'a') {
            return key as u16;
        }
    }
    panic!("No key found");
}

#[cfg(test)]
mod tests {
    use crate::mersenne_twister::{B, C, L, S, T, U};
    use rand::distributions::Standard;
    use rand::Rng;
    use std::num::Wrapping;

    //         let y1 = y ^ (y >> U);
    //         let y2 = y1 ^ ((y1 << S) & B);
    //         let y3 = y2 ^ ((y2 << T) & C);
    //         let y4 = y3 ^ (y3 >> L);
    #[test]
    fn recover_y3() {
        for y3 in rand::thread_rng()
            .sample_iter::<u32, Standard>(Standard)
            .take(10)
        {
            let y4 = y3 ^ (y3 >> L);
            let my_y3 = y4 ^ (y4 >> L);
            assert_eq!(y3, my_y3);
        }
    }
    #[test]
    fn recover_y2() {
        for y2 in rand::thread_rng()
            .sample_iter::<u32, Standard>(Standard)
            .take(10)
        {
            let y2 = Wrapping(y2);
            let y3 = y2 ^ ((y2 << T) & C);
            let my_y2 = y3 ^ ((y3 << T) & C);
            assert_eq!(y2, my_y2);
        }
    }
    #[test]
    fn recover_y1() {
        for y1 in rand::thread_rng()
            .sample_iter::<u32, Standard>(Standard)
            .take(10)
        {
            let y1 = Wrapping(y1);
            let y2 = y1 ^ ((y1 << S) & B);
            // scooch 7 bits at a time
            let maskie: Wrapping<u32> = Wrapping(0b1111111);
            let ya = y2 ^ ((y2 << S) & B & (maskie << S));
            let yb = ya ^ ((ya << S) & B & (maskie << (S * 2)));
            let yc = yb ^ ((yb << S) & B & (maskie << (S * 3)));
            let my_y1 = yc ^ ((yc << S) & B & (maskie << (S * 4)));
            assert_eq!(y1, my_y1);
        }
    }
    #[test]
    fn recover_y() {
        for y in rand::thread_rng()
            .sample_iter::<u32, Standard>(Standard)
            .take(10)
        {
            let y = Wrapping(y);
            let y1 = y ^ (y >> U);
            let maskie: Wrapping<u32> = Wrapping(0b11111111111);
            let ya = y1 ^ ((y1 >> U) & (maskie << (U * 2)));
            let yb = ya ^ ((ya >> U) & (maskie << (U)));
            let my_y = yb ^ ((yb >> U) & maskie);
            assert_eq!(my_y, y);
        }
    }
}

use core::num::Wrapping;

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
        let mut y = self.mt[self.index];
        y ^= y >> U;
        y ^= (y << S) & B;
        y ^= (y << T) & C;
        y ^= y >> L;
        self.index += 1;
        y.0
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
}

pub mod cbc;
pub mod ctr;
pub mod ecb;

pub mod challenge_11;
pub mod challenge_12;
pub mod challenge_13;
pub mod challenge_14;
pub mod challenge_16;
pub mod challenge_17;
pub mod challenge_19_and_20;
pub mod challenge_25;
pub mod challenge_26;

pub struct Key<'a>(pub &'a [u8]);
pub struct Iv<'a>(pub &'a [u8]);

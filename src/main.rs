#![feature(bigint_helper_methods)]
#![deny(unused_crate_dependencies)]

pub mod aes_fun;
pub mod cryptopal_util;
pub mod diffie_hellman;
pub mod englishness;
pub mod mersenne_twister;
pub mod pkcs7;
pub mod random_things;
pub mod rsa;
pub mod srp;

mod hashes;
mod sets;

fn main() {
    println!("Hello, world! try running the tests :)");
}

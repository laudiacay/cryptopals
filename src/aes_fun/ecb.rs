use crate::pkcs7::{pkcs7_pad, pkcs7_unpad};
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use anyhow::Result;
use std::collections::HashSet;

pub fn decrypt(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let mut plaintext = Vec::new();
    let block_size = 16;
    let key = GenericArray::from_slice(key);
    let cipher = Aes128::new(key);
    let mut block_spot = [0u8; 16];
    for chunk in ciphertext.chunks(block_size) {
        block_spot.clone_from_slice(chunk);
        let block = GenericArray::from_mut_slice(&mut block_spot);
        cipher.decrypt_block(block);
        plaintext.extend(block.as_slice());
    }
    Ok(pkcs7_unpad(plaintext.as_slice())?.to_vec())
}

pub fn encrypt(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    let ciphertext = pkcs7_pad(ciphertext, 16);
    let mut plaintext = Vec::new();
    let block_size = 16;
    let key = GenericArray::from_slice(key);
    let cipher = Aes128::new(key);
    let mut block_spot = [0u8; 16];
    for chunk in ciphertext.chunks(block_size) {
        block_spot.clone_from_slice(chunk);
        let block = GenericArray::from_mut_slice(&mut block_spot);
        cipher.encrypt_block(block);
        plaintext.extend(block.as_slice());
    }
    plaintext
}

pub fn is_ecb(ciphertext: &[u8]) -> bool {
    let hash_set_of_blocks = ciphertext
        .chunks(16)
        .map(|block| block.to_vec())
        .collect::<HashSet<Vec<u8>>>();
    hash_set_of_blocks.len() < ciphertext.len() / 16
}

pub fn find_aes_ecb_ciphertexts(ciphertexts: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    ciphertexts
        .iter()
        .filter(|ciphertext| is_ecb(ciphertext))
        .cloned()
        .collect()
}

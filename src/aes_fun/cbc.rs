use crate::pkcs7::{pkcs7_pad, pkcs7_unpad};
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use anyhow::Result;

pub fn encrypt(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let plaintext = pkcs7_pad(plaintext, 16);
    let mut ciphertext = Vec::new();
    let block_size = 16;
    let key = GenericArray::from_slice(key);
    let cipher = Aes128::new(key);
    let mut block_spot = [0u8; 16];
    let mut previous_block = iv.to_vec();
    for chunk in plaintext.chunks(block_size) {
        block_spot.clone_from_slice(chunk);
        block_spot
            .iter_mut()
            .zip(previous_block.iter())
            .for_each(|(b1, b2)| {
                *b1 ^= *b2;
            });
        let block = GenericArray::from_mut_slice(&mut block_spot);
        cipher.encrypt_block(block);
        previous_block = block.to_vec();
        ciphertext.extend(block.as_slice());
    }
    Ok(ciphertext)
}

pub fn decrypt_no_unpad(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut plaintext = Vec::new();
    let block_size = 16;
    let key = GenericArray::from_slice(key);
    let cipher = Aes128::new(key);
    let mut block_spot = [0u8; 16];
    let mut previous_block_spot = [0u8; 16];
    for i in 0..ciphertext.len() / block_size {
        if i == 0 {
            previous_block_spot.clone_from_slice(iv);
        } else {
            previous_block_spot.clone_from_slice(&ciphertext[(i - 1) * block_size..i * block_size]);
        }
        block_spot.clone_from_slice(&ciphertext[i * block_size..(i + 1) * block_size]);
        let block = GenericArray::from_mut_slice(&mut block_spot);
        cipher.decrypt_block(block);
        block
            .iter_mut()
            .zip(previous_block_spot.iter())
            .for_each(|(b1, b2)| {
                *b1 ^= *b2;
            });
        plaintext.extend(block.as_slice());
    }
    plaintext
}

pub fn decrypt(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let plaintext = decrypt_no_unpad(ciphertext, key, iv);
    pkcs7_unpad(plaintext.as_slice())
}

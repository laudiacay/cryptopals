use anyhow::Result;
use hex;
use std::fs::File;
use std::io::Read;

pub fn hex_to_bytes(hex_string: String) -> Result<Vec<u8>> {
    Ok(hex::decode(hex_string)?)
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn b64_to_bytes(b64_string: String) -> Result<Vec<u8>> {
    Ok(base64::decode(b64_string)?)
}

pub fn bytes_to_b64(bytes: &[u8]) -> String {
    base64::encode(bytes)
}

pub fn bytes_to_ascii(bytes: &[u8]) -> Result<String> {
    Ok(String::from_utf8(bytes.to_owned())?)
}

pub fn ascii_to_bytes(ascii_string: &str) -> Result<Vec<u8>> {
    Ok(ascii_string.as_bytes().to_vec())
}

pub fn fixed_xor(bytes1: &[u8], bytes2: &[u8]) -> Vec<u8> {
    if bytes1.len() <= bytes2.len() {
        // truncate bytes2 if it's too long
        bytes1
            .iter()
            .zip(bytes2.iter().take(bytes1.len()))
            .map(|(b1, b2)| b1 ^ b2)
            .collect()
    } else {
        // truncate bytes1 if it's too long
        bytes1
            .iter()
            .zip(bytes2.iter().take(bytes2.len()))
            .map(|(b1, b2)| b1 ^ b2)
            .collect()
    }
}

pub fn read_lines_from_file(filename: String) -> Result<Vec<String>> {
    let mut file = File::open(filename)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents.lines().map(|s| s.to_string()).collect())
}

pub fn read_bytes_from_b64_file(filename: String) -> Result<Vec<u8>> {
    let bytes = b64_to_bytes(read_lines_from_file(filename)?.join(""))?;
    Ok(bytes)
}

pub fn repeating_key_xor(input_bytes: &[u8], key_bytes: &[u8]) -> Vec<u8> {
    input_bytes
        .iter()
        .zip(key_bytes.iter().cycle())
        .map(|(b1, b2)| b1 ^ b2)
        .collect()
}

pub fn count_bits(byte: u8) -> usize {
    let mut count = 0;
    for i in 0..8 {
        if (byte >> i) & 1 == 1 {
            count += 1;
        }
    }
    count
}

pub fn hamming_distance(bytes1: &[u8], bytes2: &[u8]) -> usize {
    let mut distance = 0;
    for i in 0..bytes1.len() {
        distance += count_bits(bytes1[i] ^ bytes2[i]);
    }
    distance
}

pub fn current_unix_timestamp() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

#[cfg(test)]
mod tests {
    use crate::cryptopal_util::{ascii_to_bytes, hamming_distance};

    #[test]
    fn check_hamming_distance() {
        let input1 = "this is a test";
        let input2 = "wokka wokka!!!";
        let bytes1 = ascii_to_bytes(input1).unwrap();
        let bytes2 = ascii_to_bytes(input2).unwrap();
        let my_output = hamming_distance(&bytes1, &bytes2);
        assert_eq!(my_output, 37);
    }
}

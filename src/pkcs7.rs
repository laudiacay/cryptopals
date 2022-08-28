use anyhow::{anyhow, Result};

pub fn pkcs7_pad(input: &[u8], block_size: usize) -> Vec<u8> {
    let mut output = input.to_vec();
    let padding_size = block_size - (input.len() % block_size);
    for _ in 0..padding_size {
        output.push(padding_size as u8);
    }
    output
}

pub fn pkcs7_unpad(input: &[u8]) -> Result<Vec<u8>> {
    let padding_size = input[input.len() - 1] as usize;
    if padding_size > input.len() {
        return Err(anyhow!("Invalid padding"));
    }
    let mut output = input.to_vec();
    if output[output.len() - padding_size..].iter().any(|&b| b != padding_size as u8) {
        return Err(anyhow!("Invalid padding"));
    }
    output.truncate(output.len() - padding_size);
    Ok(output)
}

use crate::cryptopal_util;
use crate::englishness::break_repeating_key_xor_with_keysize;
use anyhow::Result;

pub fn attack() -> Result<Vec<u8>> {
    let lines = cryptopal_util::read_lines_from_file("./data/20.txt".to_string())?;
    let bytes = lines
        .iter()
        .map(|line| cryptopal_util::b64_to_bytes(line.to_string()))
        .collect::<Result<Vec<Vec<u8>>>>()?;
    // take minimum of all the bytes' lengths
    let min_len = bytes.iter().map(|b| b.len()).min().unwrap();
    // truncate all bytes to min_len and append them together
    let mut bytes_concat = Vec::new();
    for b in bytes {
        bytes_concat.extend_from_slice(&b[..min_len]);
    }
    let (_score, mut key, _decrypted) =
        break_repeating_key_xor_with_keysize(bytes_concat.clone(), min_len as u32);

    // ok now we got most of the thing decrypted. time to fix the random other bytes that are messed up...
    //"warnung,"
    key[0] ^= b'n' ^ b'I';
    key[5] ^= b'R' ^ b's';
    key[7] ^= b's' ^ b'u';
    key[8] ^= b'_' ^ b's';
    key[16] ^= b'l' ^ b'p';
    key[17] ^= b'e' ^ b' ';
    key[30] ^= b'u' ^ b'i';
    key[47] ^= b'`' ^ b'a';

    let dist_index = 0;
    //key[dist_index] = trial;
    let patched_decrypted = cryptopal_util::repeating_key_xor(&bytes_concat, &key);
    let patched_decrypted_chunks = patched_decrypted.chunks(53);
    for i in 25..53 {
        if i % 10 == 0 {
            print!("    {}", i / 10);
        } else {
            print!("     ");
        }
    }
    println!();
    for i in 25..53 {
        print!("    {}", i % 10);
    }
    println!();
    let mut dist = vec![];
    for chunk in patched_decrypted_chunks.take(30) {
        for (i, letter) in chunk[25..53].iter().enumerate() {
            if i == dist_index {
                dist.push(*letter)
            }
            print!("    {}", *letter as char);
        }
        println!();
    }
    let parse_dist = cryptopal_util::bytes_to_ascii(&dist)?;
    println!("DIST: {parse_dist}");
    println!(
        "{}",
        cryptopal_util::bytes_to_ascii(&patched_decrypted[..24 * 30])?
    );

    Ok(patched_decrypted)
}

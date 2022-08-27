use std::cmp::Ordering;

use crate::cryptopal_util::hamming_distance;
use std::collections::HashMap;

lazy_static::lazy_static! {
    pub static ref FREQUENCY_TABLE: HashMap<char, f32> = {
        let mut m = HashMap::new();
        //E	11.1607%	56.88	M	3.0129%	15.36
        // A	8.4966%	43.31	H	3.0034%	15.31
        // R	7.5809%	38.64	G	2.4705%	12.59
        // I	7.5448%	38.45	B	2.0720%	10.56
        // O	7.1635%	36.51	F	1.8121%	9.24
        // T	6.9509%	35.43	Y	1.7779%	9.06
        // N	6.6544%	33.92	W	1.2899%	6.57
        // S	5.7351%	29.23	K	1.1016%	5.61
        // L	5.4893%	27.98	V	1.0074%	5.13
        // C	4.5388%	23.13	X	0.2902%	1.48
        // U	3.6308%	18.51	Z	0.2722%	1.39
        // D	3.3844%	17.25	J	0.1965%	1.00
        // P	3.1671%	16.14	Q	0.1962%	(1)
        m.insert('E', 11.1607);
        m.insert('A', 8.4966);
        m.insert('R', 7.5809);
        m.insert('I', 7.5448);
        m.insert('O', 7.1635);
        m.insert('T', 6.9509);
        m.insert('N', 6.6544);
        m.insert('S', 5.7351);
        m.insert('L', 5.4893);
        m.insert('C', 4.5388);
        m.insert('U', 3.6308);
        m.insert('D', 3.3844);
        m.insert('P', 3.1671);
        m.insert('M', 3.0129);
        m.insert('H', 3.0034);
        m.insert('G', 2.4705);
        m.insert('B', 2.0720);
        m.insert('F', 1.8121);
        m.insert('Y', 1.7779);
        m.insert('W', 1.2899);
        m.insert('K', 1.1016);
        m.insert('V', 1.0074);
        m.insert('X', 0.2902);
        m.insert('Z', 0.2722);
        m.insert('J', 0.1965);
        m.insert('Q', 0.1962);
        m
    };

    // Digraph	Count	 	Digraph	Frequency
    // th	5532	 	th	1.52
    // he	4657	 	he	1.28
    // in	3429	 	in	0.94
    // er	3420	 	er	0.94
    // an	3005	 	an	0.82
    // re	2465	 	re	0.68
    // nd	2281	 	nd	0.63
    // at	2155	 	at	0.59
    // on	2086	 	on	0.57
    // nt	2058	 	nt	0.56
    // ha	2040	 	ha	0.56
    // es	2033	 	es	0.56
    // st	2009	 	st	0.55
    // en	2005	 	en	0.55
    // ed	1942	 	ed	0.53
    // to	1904	 	to	0.52
    // it	1822	 	it	0.50
    // ou	1820	 	ou	0.50
    // ea	1720	 	ea	0.47
    // hi	1690	 	hi	0.46
    // is	1660	 	is	0.46
    // or	1556	 	or	0.43
    // ti	1231	 	ti	0.34
    // as	1211	 	as	0.33
    // te	985	 	te	0.27
    // et	704	 	et	0.19
    // ng	668	 	ng	0.18
    // of	569	 	of	0.16
    // al	341	 	al	0.09
    // de	332	 	de	0.09
    // se	300	 	se	0.08
    // le	298	 	le	0.08
    // sa	215	 	sa	0.06
    // si	186	 	si	0.05
    // ar	157	 	ar	0.04
    // ve	148	 	ve	0.04
    // ra	137	 	ra	0.04
    // ld	64	 	ld	0.02
    // ur	60	 	ur	0.02
    pub static ref DIGRAPH_FREQUENCY : HashMap<(char, char) , f32> = {
        let mut m = HashMap::new();
        m.insert(('t', 'h'), 1.52);
        m.insert(('h', 'e'), 1.28);
        m.insert(('i', 'n'), 0.94);
        m.insert(('e', 'r'), 0.94);
        m.insert(('a', 'n'), 0.82);
        m.insert(('r', 'e'), 0.68);
        m.insert(('n', 'd'), 0.63);
        m.insert(('a', 't'), 0.59);
        m.insert(('o', 'n'), 0.57);
        m.insert(('n', 't'), 0.56);
        m.insert(('h', 'a'), 0.56);
        m.insert(('e', 's'), 0.56);
        m.insert(('s', 't'), 0.55);
        m.insert(('e', 'n'), 0.55);
        m.insert(('e', 'd'), 0.53);
        m.insert(('t', 'o'), 0.52);
        m.insert(('i', 't'), 0.50);
        m.insert(('o', 'u'), 0.50);
        m.insert(('e', 'a'), 0.47);
        m.insert(('h', 'i'), 0.46);
        m.insert(('i', 's'), 0.46);
        m.insert(('o', 'r'), 0.43);
        m.insert(('t', 'i'), 0.34);
        m.insert(('a', 's'), 0.33);
        m.insert(('t', 'e'), 0.27);
        m.insert(('e', 't'), 0.19);
        m.insert(('n', 'g'), 0.18);
        m.insert(('o', 'f'), 0.16);
        m.insert(('a', 'l'), 0.09);
        m.insert(('d', 'e'), 0.09);
        m.insert(('s', 'e'), 0.08);
        m.insert(('l', 'e'), 0.08);
        m.insert(('s', 'a'), 0.06);
        m.insert(('s', 'i'), 0.05);
        m.insert(('a', 'r'), 0.04);
        m.insert(('v', 'e'), 0.04);
        m.insert(('r', 'a'), 0.04);
        m.insert(('l', 'd'), 0.02);
        m.insert(('u', 'r'), 0.02);
        m
    };
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EnglishnessScores {
    text_freq_score: f32,
    digraph_freq_score: f32,
    lowercase_score: f32,
}

// the more you see a letter, the higher its number should be... just return -1 for anything that is not ascii.
fn score_text_freq(text: &[u8]) -> f32 {
    let mut score = 0.0;
    for c in text.iter() {
        let char = *c as char;
        if char.is_alphabetic() {
            score += FREQUENCY_TABLE
                .get(&char.to_ascii_uppercase())
                .unwrap_or(&0.0);
        }
        if !char.is_ascii() {
            return -1.0;
        }
    }
    score
}

fn score_text_digraph(text: &[u8]) -> f32 {
    let mut score = 0.0;
    for i in 0..text.len() - 1 {
        let chars = (text[i] as char, text[i + 1] as char);
        if !chars.0.is_alphabetic() || !chars.1.is_alphabetic() {
            continue;
        }
        if !chars.0.is_ascii() || !chars.1.is_ascii() {
            continue;
        }
        let upper = (chars.0.to_ascii_lowercase(), chars.1.to_ascii_lowercase());
        score += DIGRAPH_FREQUENCY.get(&upper).unwrap_or(&0.0);
    }
    score
}

// most english text is mostly lowercase, so this is a good metric for english text.
fn score_percent_lowercase(text: &[u8]) -> f32 {
    let mut score = 0.0;
    for c in text.iter() {
        if *c >= b'a' && *c <= b'z' {
            score += 1.0;
        }
    }
    score / text.len() as f32
}

fn score_text(text: &[u8]) -> EnglishnessScores {
    let text_freq_score = score_text_freq(text);
    let digraph_freq_score = score_text_digraph(text);
    let lowercase_score = score_percent_lowercase(text);
    EnglishnessScores {
        text_freq_score,
        digraph_freq_score,
        lowercase_score,
    }
}

pub fn compute_fixed_xor(bytes: &[u8], key: u8) -> Vec<u8> {
    let mut xor_bytes = Vec::new();
    for b in bytes.iter() {
        xor_bytes.push(b ^ key);
    }
    xor_bytes
}

impl PartialOrd for EnglishnessScores {
    // are we within a tolerance of the best score? time for digraph test. then lowercase test.
    fn partial_cmp(&self, other: &EnglishnessScores) -> Option<Ordering> {
        Some({
            if self.text_freq_score < other.text_freq_score * 0.8 {
                Ordering::Less
            } else if self.text_freq_score > other.text_freq_score * 1.2 {
                Ordering::Greater
            } else if self.digraph_freq_score < other.digraph_freq_score * 0.9 {
                Ordering::Less
            } else if self.digraph_freq_score > other.digraph_freq_score * 1.1 {
                Ordering::Greater
            } else if self.lowercase_score < other.lowercase_score {
                Ordering::Less
            } else if self.lowercase_score > other.lowercase_score {
                Ordering::Greater
            } else {
                Ordering::Equal
            }
        })
    }
}

impl Default for EnglishnessScores {
    fn default() -> EnglishnessScores {
        EnglishnessScores {
            text_freq_score: 0.0,
            digraph_freq_score: 0.0,
            lowercase_score: 0.0,
        }
    }
}

pub fn find_best_fixed_xor(bytes: Vec<u8>) -> (u8, Vec<u8>, EnglishnessScores) {
    let mut best_score = EnglishnessScores::default();
    let mut best_bytes = Vec::new();
    let mut best_key = 0;
    for key in 0..=255 {
        let xor_bytes = compute_fixed_xor(&bytes, key);
        let score = score_text(xor_bytes.as_slice());
        if score > best_score {
            best_score = score;
            best_bytes = xor_bytes;
            best_key = key;
        };
    }
    (best_key, best_bytes, best_score)
}

pub fn find_which_is_fixed_xor(byteses: Vec<Vec<u8>>) -> (Vec<u8>, u8, Vec<u8>) {
    let mut best_score = EnglishnessScores::default();
    let mut best_key = 0;
    let mut best_og = Vec::new();
    let mut best_bytes = Vec::new();
    for bytes in byteses {
        let (key, xor_bytes, score) = find_best_fixed_xor(bytes.clone());
        if score > best_score {
            best_score = score;
            best_key = key;
            best_og = bytes;
            best_bytes = xor_bytes;
        }
    }
    (best_og, best_key, best_bytes)
}

pub fn compute_normalized_keysize_distance(bytes: &[u8], keysize: u32) -> f32 {
    let mut distance = 0.0;
    let first_keysize_bytes = bytes.chunks(keysize as usize).next().unwrap();
    for chunk in bytes.chunks(keysize as usize).take(10) {
        let this_chunk_edit_distance = hamming_distance(first_keysize_bytes, chunk);
        distance += this_chunk_edit_distance as f32 / keysize as f32;
    }
    distance / 10.0
}

pub fn get_top_3_normalized_distance_keysizes(bytes: &[u8], max_keysize: u32) -> Vec<u32> {
    let mut keysizes = Vec::new();
    for keysize in 2..max_keysize {
        let normalized_distance = compute_normalized_keysize_distance(bytes, keysize);
        keysizes.push((keysize, normalized_distance));
    }
    keysizes.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
    keysizes.iter().map(|&(k, _)| k).take(3).collect()
}

fn transpose_bytes(bytes: &[u8], keysize: u32) -> Vec<Vec<u8>> {
    let vecs_to_transpose: Vec<Vec<u8>> = bytes
        .chunks(keysize as usize)
        .map(|chunk| chunk.to_vec())
        .collect();
    let mut transposed_bytes = Vec::new();
    for i in 0..keysize as usize {
        let mut transposed_vec = Vec::new();
        for vec in vecs_to_transpose.iter() {
            if vec.len() > i {
                transposed_vec.push(vec[i]);
            } else {
                break;
            }
        }
        transposed_bytes.push(transposed_vec);
    }
    transposed_bytes
}

fn untranspose_bytes(bytes: &[Vec<u8>], keysize: u32) -> Vec<u8> {
    let mut untransposed_bytes = Vec::new();
    for i in 0..keysize {
        for vec in bytes.iter() {
            untransposed_bytes.push(vec[i as usize]);
        }
    }
    untransposed_bytes
}

fn break_repeating_key_xor_with_keysize(
    bytes: Vec<u8>,
    keysize: u32,
) -> (EnglishnessScores, Vec<u8>, Vec<u8>) {
    let mut key = Vec::new();
    let transposed = transpose_bytes(&bytes, keysize);
    let mut transposed_decrypted = Vec::new();
    // break each transposed chunk into a single byte key
    for thing_to_break in transposed.iter() {
        let (key_byte, output, _englishness) = find_best_fixed_xor(thing_to_break.clone());
        key.push(key_byte);
        transposed_decrypted.push(output);
    }
    let untransposed = untranspose_bytes(&transposed_decrypted, keysize);
    let score = score_text(untransposed.as_slice());
    (score, key, untransposed)
}

/// returns (key, plaintext)
pub fn break_repeating_key_xor(bytes: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    let keysizes = get_top_3_normalized_distance_keysizes(bytes.as_slice(), 40);

    let mut best_score = EnglishnessScores::default();
    let mut best_key = Vec::new();
    let mut best_plaintext = Vec::new();
    for key_size in keysizes {
        let (score, key_bytes, plaintext) =
            break_repeating_key_xor_with_keysize(bytes.clone(), key_size);
        if score > best_score {
            best_score = score;
            best_key = key_bytes;
            best_plaintext = plaintext;
        }
    }
    (best_key, best_plaintext)
}

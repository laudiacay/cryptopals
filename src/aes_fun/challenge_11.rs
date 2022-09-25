use crate::aes_fun::{cbc, ecb, Iv, Key};
use crate::pkcs7::pkcs7_pad;
use rand::distributions::Standard;
use rand::Rng;

// returns was_ecb, ciphertext
pub fn oracle(my_input: &[u8]) -> (bool, Vec<u8>) {
    let mut rng = rand::thread_rng();

    let random_number_of_bytes_to_prepend = rng.gen_range(5..10);
    let random_number_of_bytes_to_append = rng.gen_range(5..10);

    let random_bytes_to_prepend: Vec<u8> = (&mut rng)
        .sample_iter(Standard)
        .take(random_number_of_bytes_to_prepend)
        .collect();
    let random_bytes_to_append: Vec<u8> = (&mut rng)
        .sample_iter(Standard)
        .take(random_number_of_bytes_to_append)
        .collect();

    let mut my_padded_input = random_bytes_to_prepend;
    my_padded_input.extend(my_input);
    my_padded_input.extend(random_bytes_to_append);
    let my_padded_input = pkcs7_pad(&my_padded_input, 16);

    let random_key: Vec<u8> = (&mut rng).sample_iter(Standard).take(16).collect();

    let coin_flip = rand::thread_rng().gen_range(0..2);
    if coin_flip == 1 {
        let my_ciphertext = ecb::encrypt(&my_padded_input, Key(&random_key));
        (true, my_ciphertext)
    } else {
        let random_iv: Vec<u8> = (&mut rng).sample_iter(Standard).take(16).collect();
        let my_ciphertext = cbc::encrypt(&my_padded_input, Key(&random_key), Iv(&random_iv)).unwrap();
        (false, my_ciphertext)
    }
}

use std::io::Write;
use std::num::Wrapping;

const ROUNDS: usize = 32;

pub fn encrypt<W>(mut plain_text: Vec<u8>, key: &Vec<u8>, mut output: W) -> Result<(), String>
where
    W: Write,
{
    pad_plain_text(&mut plain_text);
    let key_schedule = gen_key_schedule(key)?;
    for block in plain_text.chunks(16) {
        let e_block = encrypt_block(block, &key_schedule);
        match output.write_all(&e_block) {
            Ok(_o) => (),
            Err(e) => return Err(format!("Error writing to file: {}", e)),
        }
    }
    Ok(())
}

pub fn decrypt<W>(cipher_text: Vec<u8>, key: &Vec<u8>, mut output: W) -> Result<(), String>
where
    W: Write,
{
    let key_schedule = gen_key_schedule(key)?;
    let num_blocks = cipher_text.len() / 16;
    for block in cipher_text.chunks(16).take(num_blocks - 1) {
        let d_block = decrypt_block(block, &key_schedule);
        match output.write_all(&d_block) {
            Ok(_o) => (),
            Err(e) => return Err(format!("Error writing to file: {}", e)),
        }
    }

    //Decrypt the last block
    //Strip off the last X bytes according to the last byte
    let d_block = decrypt_block(&cipher_text[cipher_text.len() - 16..], &key_schedule);
    let end_index = 16 - d_block[15];
    match output.write_all(&d_block[..(end_index as usize)]) {
        Ok(_o) => (),
        Err(e) => return Err(format!("Error writing to file: {}", e)),
    }

    Ok(())
}

fn pad_plain_text(plain_text: &mut Vec<u8>) {
    // Padding will be done as per PKCS#7
    // https://en.wikipedia.org/wiki/Padding_%28cryptography%29#Block_cipher_mode_of_operation
    let pad_bytes = 16 - (plain_text.len() % 16);
    let pad_bytes = pad_bytes as u8;
    for _i in 0..pad_bytes {
        plain_text.push(pad_bytes);
    }
}

fn gen_key_schedule(key: &Vec<u8>) -> Result<[u32; 132], String> {
    let full_key = pad_key(key)?;
    let full_key: [u32; 8] = transform_key_word(full_key)?;

    let mut key_sched = [0; 132];

    //First 8 words come from user key
    &key_sched[..8].copy_from_slice(&full_key[..]);

    //Flesh out the remaining key schedule
    for i in full_key.len()..key_sched.len() {
        key_sched[i] = hash((key_sched[i - 8] ^ key_sched[i - 1]) + (i as u32));
    }
    Ok(key_sched)
}

fn pad_key(key: &Vec<u8>) -> Result<Vec<u8>, String> {
    if key.len() == 0 {
        Err(format!(
            "Key must be > 0 bits length! length given is {}",
            key.len() * 8
        ))
    } else if key.len() < 32 {
        //If key is not full length repeat it to get 256 bits
        Ok(key.iter().cloned().cycle().take(32).collect())
    } else if key.len() == 32 {
        Ok(key.clone())
    } else {
        Err(format!(
            "Key must be <= 256 bits length! length given is {}",
            key.len() * 8
        ))
    }
}

fn transform_key_word(key: Vec<u8>) -> Result<[u32; 8], String> {
    if key.len() != 32 {
        return Err(format!(
            "Error padding key.  Key needs 32 bytes but has {} bytes.",
            key.len()
        ));
    }

    let mut new_key = [0; 8];
    for i in 0..new_key.len() {
        for j in 0..4 {
            new_key[i] |= (key[i * 4 + j] as u32) << (8 * (3 - j));
        }
    }
    Ok(new_key)
}

fn hash(word: u32) -> u32 {
    //Perfect bias u32 hash taken from Null Program:
    //https://nullprogram.com/blog/2018/07/31/
    let mut x = Wrapping(word);
    x ^= x >> 17;
    x *= Wrapping(0xed5ad4bb);
    x ^= x >> 11;
    x *= Wrapping(0xac4c1b51);
    x ^= x >> 15;
    x *= Wrapping(0x31848bab);
    x ^= x >> 14;
    x.0
}

fn inv_hash(word: u32) -> u32 {
    //Perfect bias u32 hash taken from Null Program:
    //https://nullprogram.com/blog/2018/07/31/
    let mut x = Wrapping(word);
    x ^= x >> 14 ^ x >> 28;
    x *= Wrapping(0x32b21703);
    x ^= x >> 15 ^ x >> 30;
    x *= Wrapping(0x469e0db1);
    x ^= x >> 11 ^ x >> 22;
    x *= Wrapping(0x79a85073);
    x ^= x >> 17;
    x.0
}

fn encrypt_block(block: &[u8], key_sched: &[u32; 132]) -> [u8; 16] {
    let block = u8_to_u32(block);
    let mut block = mix_keys(block, &key_sched[..4]);

    for i in 0..ROUNDS {
        block = avalanche(block);
        block = mix_keys(block, &key_sched[4 * (i + 1)..4 * (i + 2)]);
    }

    u32_to_u8(block)
}

fn decrypt_block(block: &[u8], key_sched: &[u32; 132]) -> [u8; 16] {
    let mut block = u8_to_u32(block);

    for i in (0..ROUNDS).rev() {
        block = mix_keys(block, &key_sched[4 * (i + 1)..4 * (i + 2)]);
        block = inv_avalanche(block);
    }

    block = mix_keys(block, &key_sched[..4]);

    u32_to_u8(block)
}

fn u8_to_u32(block: &[u8]) -> [u32; 4] {
    let mut new_block = [0; 4];
    for i in 0..4 {
        new_block[i] |= (block[i * 4] as u32) << 24;
        new_block[i] |= (block[i * 4 + 1] as u32) << 16;
        new_block[i] |= (block[i * 4 + 2] as u32) << 8;
        new_block[i] |= block[i * 4 + 3] as u32;
    }
    new_block
}

fn u32_to_u8(block: [u32; 4]) -> [u8; 16] {
    let mut new_block = [0; 16];
    for i in 0..16 {
        new_block[i] = ((block[i / 4] >> (8 * (3 - (i % 4)))) & 0xff) as u8;
    }
    new_block
}

fn mix_keys(block: [u32; 4], key_sched: &[u32]) -> [u32; 4] {
    let mut new_block = [0; 4];
    for i in 0..new_block.len() {
        new_block[i] = block[i] ^ key_sched[i];
    }
    new_block
}

fn avalanche(block: [u32; 4]) -> [u32; 4] {
    let x0 = block[1] ^ block[2] ^ block[3];
    let x1 = block[0] ^ block[2] ^ block[3];
    let x2 = block[0] ^ block[1] ^ block[3];
    let x3 = block[0] ^ block[1] ^ block[2];

    [hash(x0), hash(x1), hash(x2), hash(x3)]
}

fn inv_avalanche(block: [u32; 4]) -> [u32; 4] {
    let x0 = inv_hash(block[0]);
    let x1 = inv_hash(block[1]);
    let x2 = inv_hash(block[2]);
    let x3 = inv_hash(block[3]);

    let orig_x0 = x1 ^ x2 ^ x3;
    let orig_x1 = x0 ^ x2 ^ x3;
    let orig_x2 = x0 ^ x1 ^ x3;
    let orig_x3 = x0 ^ x1 ^ x2;

    [orig_x0, orig_x1, orig_x2, orig_x3]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_plain_text() {
        let mut plain_text_empty = vec![];
        let mut plain_text_1 = vec![0xdf];
        let mut plain_text_10 = vec![0xdf, 0x52, 0xd8, 0xda, 0x0c, 0xec, 0x98, 0x51, 0x8a, 0x74];
        let mut plain_text_16 = vec![
            0xdf, 0x52, 0xd8, 0xda, 0x0c, 0xec, 0x98, 0x51, 0x8a, 0x74, 0x7b, 0x8e, 0x40, 0x2f,
            0x39, 0x15,
        ];

        pad_plain_text(&mut plain_text_empty);
        pad_plain_text(&mut plain_text_1);
        pad_plain_text(&mut plain_text_10);
        pad_plain_text(&mut plain_text_16);

        assert_eq!(
            plain_text_empty,
            vec![16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16]
        );
        assert_eq!(
            plain_text_1,
            vec![0xdf, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15]
        );
        assert_eq!(
            plain_text_10,
            vec![0xdf, 0x52, 0xd8, 0xda, 0x0c, 0xec, 0x98, 0x51, 0x8a, 0x74, 6, 6, 6, 6, 6, 6]
        );
        assert_eq!(
            plain_text_16,
            vec![
                0xdf, 0x52, 0xd8, 0xda, 0x0c, 0xec, 0x98, 0x51, 0x8a, 0x74, 0x7b, 0x8e, 0x40, 0x2f,
                0x39, 0x15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16
            ]
        );
    }

    #[test]
    fn test_encrypt_block() {
        let key = vec![
            0xfc, 0xfe, 0x01, 0xee, 0xf9, 0x41, 0xeb, 0xd2, 0x3a, 0x90, 0xb8, 0xad, 0x7f, 0x79,
            0x17, 0x8e, 0xe8, 0x88, 0x02, 0x3a, 0x77, 0x11, 0xd9, 0x3f, 0xc6, 0xdd, 0xa6, 0xdb,
            0x74, 0x77, 0xca, 0x3c,
        ];
        let key_sched = gen_key_schedule(&key).unwrap();
        let block = [
            0x54, 0x34, 0x48, 0x43, 0xe4, 0xc9, 0x39, 0x6d, 0xc7, 0xfc, 0x16, 0x52, 0x29, 0x62,
            0x28, 0x73,
        ];

        let e_block = encrypt_block(&block, &key_sched);
        let d_block = decrypt_block(&e_block, &key_sched);

        assert_eq!(block, d_block);
    }

    #[test]
    fn test_u8_to_u32() {
        let block = [
            0x65, 0x66, 0x26, 0x02, 0x64, 0x53, 0x0e, 0x8d, 0x9d, 0xe9, 0xdc, 0x3a, 0x57, 0x1a,
            0xe4, 0x6f,
        ];

        let block_u32 = u8_to_u32(&block);
        let block_u8 = u32_to_u8(block_u32);

        assert_eq!(block, block_u8);
    }

    #[test]
    fn test_key_mix() {
        let key_sched = [0x069b3e6d, 0xbb5a1de3, 0x0a3d657e, 0xaf2aad1f];
        let block = [0x2ba2137b, 0xedc416b4, 0x5dc3673e, 0xaad94795];

        let block_mixed = mix_keys(block, &key_sched[..]);
        let block_unmixed = mix_keys(block_mixed, &key_sched[..]);

        assert_eq!(block, block_unmixed);
    }

    #[test]
    fn test_avalanche() {
        let block = [0x933542b8, 0xbfa30270, 0x61515053, 0x91390c5e];

        let av_block = avalanche(block);
        let inv_av_block = inv_avalanche(av_block);

        assert_eq!(block, inv_av_block);
    }

    #[test]
    fn test_hash() {
        let word = 0x65d5b951;

        assert_eq!(word, inv_hash(hash(word)));
    }

    #[test]
    fn test_pad_key() {
        let full_key = vec![
            0xbe, 0xec, 0x21, 0x4f, 0x4a, 0xdf, 0x26, 0x62, 0x96, 0x96, 0x72, 0x5e, 0xca, 0xd5,
            0x09, 0x92, 0x0b, 0xf0, 0x9d, 0xd3, 0x25, 0x61, 0xa3, 0x0b, 0x10, 0xa9, 0x8f, 0xde,
            0x54, 0xf8, 0xa0, 0xda,
        ];
        let half_key = vec![
            0x83, 0xda, 0xd1, 0xf2, 0x69, 0x9d, 0x0a, 0x90, 0xe8, 0x6b, 0xf6, 0x7a, 0xd7, 0x07,
            0xda, 0xb3,
        ];
        let empty_key = vec![];
        let huge_key = vec![
            0x07, 0x1d, 0x91, 0xeb, 0xa9, 0x6e, 0x9c, 0x3e, 0x45, 0x21, 0xc9, 0xea, 0xe7, 0x50,
            0x10, 0x35, 0xb0, 0xb1, 0xde, 0x5f, 0x36, 0x74, 0x77, 0x46, 0x91, 0x82, 0x91, 0xa6,
            0x1f, 0x35, 0xd0, 0x8c, 0x48,
        ];

        assert_eq!(Ok(full_key.clone()), pad_key(&full_key));
        assert_eq!(
            Ok(half_key.iter().cloned().cycle().take(32).collect()),
            pad_key(&half_key)
        );
        assert_eq!(false, pad_key(&empty_key).is_ok());
        assert_eq!(false, pad_key(&huge_key).is_ok());
    }

    #[test]
    fn test_transform_key_word() {
        let key = vec![
            0xe3, 0xc0, 0x49, 0xab, 0x38, 0xdd, 0x4f, 0xb5, 0x74, 0x3c, 0xfb, 0xc4, 0x5f, 0xc1,
            0xba, 0x16, 0xa2, 0xe5, 0xc7, 0x0b, 0x82, 0x89, 0xdf, 0xca, 0x01, 0xa1, 0xb4, 0x5c,
            0x48, 0x08, 0x10, 0x2b,
        ];
        let small_key = vec![0x80];

        assert_eq!(false, transform_key_word(small_key).is_ok());
        assert_eq!(
            [
                0xe3c049ab, 0x38dd4fb5, 0x743cfbc4, 0x5fc1ba16, 0xa2e5c70b, 0x8289dfca, 0x01a1b45c,
                0x4808102b
            ],
            transform_key_word(key).unwrap()
        );
    }

    #[test]
    fn test_gen_key_schedule() {
        let key = vec![
            0x25, 0xf6, 0xf8, 0x59, 0x61, 0x10, 0x54, 0xb2, 0xcb, 0xef, 0xfb, 0x94, 0xc0, 0x7a,
            0xd1, 0x67, 0x94, 0xed, 0x78, 0x40, 0x11, 0xe2, 0xa3, 0xbc, 0xf5, 0xc6, 0x10, 0x99,
            0x88, 0xb3, 0x1a, 0x76,
        ];

        let full_key = pad_key(&key).unwrap();
        let first_8_keys = transform_key_word(full_key).unwrap();

        let key_sched = gen_key_schedule(&key).unwrap();

        assert_eq!(&first_8_keys[..], &key_sched[..8]);
    }
}

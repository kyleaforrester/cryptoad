use std::io::Write;

const S_BOX: [[u32; 16]; 8] = [
    [3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12],
    [15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4],
    [8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2],
    [0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14],
    [1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13],
    [15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1],
    [7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0],
    [1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6],
];

const INV_S_BOX: [[u32; 16]; 8] = [
    [13, 3, 11, 0, 10, 6, 5, 12, 1, 14, 4, 7, 15, 9, 8, 2],
    [5, 8, 2, 14, 15, 6, 12, 3, 11, 4, 7, 9, 1, 13, 10, 0],
    [12, 9, 15, 4, 11, 14, 1, 2, 0, 3, 6, 13, 5, 8, 10, 7],
    [0, 9, 10, 7, 11, 14, 6, 13, 3, 5, 12, 2, 4, 8, 15, 1],
    [5, 0, 8, 3, 10, 9, 7, 14, 2, 12, 11, 6, 4, 15, 13, 1],
    [8, 15, 2, 9, 4, 1, 13, 14, 11, 6, 5, 3, 7, 12, 10, 0],
    [15, 10, 1, 13, 5, 3, 6, 0, 4, 9, 14, 7, 2, 12, 8, 11],
    [3, 0, 6, 13, 9, 14, 15, 8, 5, 12, 11, 7, 10, 1, 4, 2],
];

const IP_TABLE: [usize; 128] = [
    0, 32, 64, 96, 1, 33, 65, 97, 2, 34, 66, 98, 3, 35, 67, 99, 4, 36, 68, 100, 5, 37, 69, 101, 6,
    38, 70, 102, 7, 39, 71, 103, 8, 40, 72, 104, 9, 41, 73, 105, 10, 42, 74, 106, 11, 43, 75, 107,
    12, 44, 76, 108, 13, 45, 77, 109, 14, 46, 78, 110, 15, 47, 79, 111, 16, 48, 80, 112, 17, 49,
    81, 113, 18, 50, 82, 114, 19, 51, 83, 115, 20, 52, 84, 116, 21, 53, 85, 117, 22, 54, 86, 118,
    23, 55, 87, 119, 24, 56, 88, 120, 25, 57, 89, 121, 26, 58, 90, 122, 27, 59, 91, 123, 28, 60,
    92, 124, 29, 61, 93, 125, 30, 62, 94, 126, 31, 63, 95, 127,
];

const FP_TABLE: [usize; 128] = [
    0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64, 68, 72, 76, 80, 84, 88, 92,
    96, 100, 104, 108, 112, 116, 120, 124, 1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57,
    61, 65, 69, 73, 77, 81, 85, 89, 93, 97, 101, 105, 109, 113, 117, 121, 125, 2, 6, 10, 14, 18,
    22, 26, 30, 34, 38, 42, 46, 50, 54, 58, 62, 66, 70, 74, 78, 82, 86, 90, 94, 98, 102, 106, 110,
    114, 118, 122, 126, 3, 7, 11, 15, 19, 23, 27, 31, 35, 39, 43, 47, 51, 55, 59, 63, 67, 71, 75,
    79, 83, 87, 91, 95, 99, 103, 107, 111, 115, 119, 123, 127,
];

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
    let padded_key: [u32; 8] = setup_key(key)?;
    let prekeys: [u32; 132] = gen_pre_keys(padded_key);
    Ok(s_box_prekeys(prekeys))
}

fn setup_key(key: &Vec<u8>) -> Result<[u32; 8], String> {
    if key.len() == 0 || key.len() > 32 {
        return Err(format!(
            "Given key length is {} bits but must be > 0 and <= 256",
            8 * key.len()
        ));
    }

    let mut neg_prekeys = [0; 8];

    //Convert [u8; 32] to [u32; 8]
    let mut ind = 0;
    for chunk in key.chunks(4) {
        for i in 0..chunk.len() {
            neg_prekeys[ind] |= (chunk[i] as u32) << (3 - i);
        }
        ind += 1;
    }

    if key.len() < 32 {
        //Pad a 1 bit to the left of the neg_prekeys
        for i in (1..8).rev() {
            neg_prekeys[i] = (neg_prekeys[i - 1] << 31) | (neg_prekeys[i] >> 1);
        }
        neg_prekeys[0] = (1u32 << 31) | (neg_prekeys[0] >> 1);
    }

    Ok(neg_prekeys)
}

fn gen_pre_keys(key: [u32; 8]) -> [u32; 132] {
    let mut ret_val = [0; 132];
    let mut pre_keys = [0; 140];

    &pre_keys[..8].copy_from_slice(&key[..]);

    for i in 8..pre_keys.len() {
        pre_keys[i] = (pre_keys[i - 8]
            ^ pre_keys[i - 5]
            ^ pre_keys[i - 3]
            ^ pre_keys[i - 1]
            ^ 0x9e3779b9
            ^ (i as u32))
            .rotate_left(11);
    }

    ret_val.copy_from_slice(&pre_keys[8..]);
    ret_val
}

fn s_box_prekeys(pre_keys: [u32; 132]) -> [u32; 132] {
    let mut s_box_ind = 3;
    let mut ret_val = [0; 132];

    for i in 0..pre_keys.len() {
        ret_val[i] = s_box_word(pre_keys[i], s_box_ind);
        if i % 4 == 3 {
            if s_box_ind == 0 {
                s_box_ind = 7;
            } else {
                s_box_ind -= 1;
            }
        }
    }
    ret_val
}

fn s_box_word(word: u32, s_box_ind: usize) -> u32 {
    let mut new_word = 0;
    for i in 0..8 {
        let bits_u4 = ((word >> (28 - 4 * i)) & 0xf) as usize;
        new_word |= S_BOX[s_box_ind][bits_u4] << (28 - 4 * i);
    }
    new_word
}

fn inv_s_box_word(word: u32, s_box_ind: usize) -> u32 {
    let mut new_word = 0;
    for i in 0..8 {
        let bits_u4 = ((word >> (28 - 4 * i)) & 0xf) as usize;
        new_word |= INV_S_BOX[s_box_ind][bits_u4] << (28 - 4 * i);
    }
    new_word
}

fn encrypt_block(block: &[u8], key_sched: &[u32; 132]) -> [u8; 16] {
    let mut e_block = permutate(u8_to_u32(block), IP_TABLE);

    for i in 0..ROUNDS - 1 {
        e_block = key_mix(e_block, &key_sched[4 * i..4 * (i + 1)]);
        e_block = s_box_block(e_block, i % 8);
        e_block = linear_transform(e_block);
    }
    e_block = key_mix(e_block, &key_sched[4 * (ROUNDS - 1)..4 * ROUNDS]);
    e_block = s_box_block(e_block, (ROUNDS - 1) % 8);
    e_block = key_mix(e_block, &key_sched[4 * ROUNDS..]);

    let e_block = u32_to_u8(permutate(e_block, FP_TABLE));
    e_block
}

fn decrypt_block(block: &[u8], key_sched: &[u32; 132]) -> [u8; 16] {
    let mut d_block = permutate(u8_to_u32(block), IP_TABLE);

    d_block = key_mix(d_block, &key_sched[4 * ROUNDS..]);
    d_block = inv_s_box_block(d_block, (ROUNDS - 1) % 8);
    d_block = key_mix(d_block, &key_sched[4 * (ROUNDS - 1)..4 * ROUNDS]);

    for i in (0..ROUNDS - 1).rev() {
        d_block = inv_linear_transform(d_block);
        d_block = inv_s_box_block(d_block, i % 8);
        d_block = key_mix(d_block, &key_sched[4 * i..4 * (i + 1)]);
    }

    let d_block = u32_to_u8(permutate(d_block, FP_TABLE));
    d_block
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

fn permutate(block: [u32; 4], table: [usize; 128]) -> [u32; 4] {
    let mut new_block = [0; 4];
    for new_ind in 0..4 {
        for i in 0..32 {
            let orig_ind = table[new_ind * 32 + i];
            let orig_value = (block[orig_ind / 32] >> (31 - orig_ind % 32)) & 0x1;
            new_block[new_ind] |= orig_value << (31 - i);
        }
    }
    new_block
}

fn key_mix(block: [u32; 4], key_sched: &[u32]) -> [u32; 4] {
    let mut new_block = [0; 4];
    for i in 0..4 {
        new_block[i] = block[i] ^ key_sched[i];
    }
    new_block
}

fn s_box_block(block: [u32; 4], s_box_ind: usize) -> [u32; 4] {
    let mut new_block = [0; 4];
    for i in 0..4 {
        new_block[i] = s_box_word(block[i], s_box_ind);
    }
    new_block
}

fn inv_s_box_block(block: [u32; 4], s_box_ind: usize) -> [u32; 4] {
    let mut new_block = [0; 4];
    for i in 0..4 {
        new_block[i] = inv_s_box_word(block[i], s_box_ind);
    }
    new_block
}

fn linear_transform(block: [u32; 4]) -> [u32; 4] {
    let mut new_block = [0; 4];
    let mut x0 = block[0];
    let mut x1 = block[1];
    let mut x2 = block[2];
    let mut x3 = block[3];

    x0 = x0.rotate_left(13);
    x2 = x2.rotate_left(3);
    x1 = x1 ^ x0 ^ x2;
    x3 = x3 ^ x2 ^ (x0 << 3);
    x1 = x1.rotate_left(1);
    x3 = x3.rotate_left(7);
    x0 = x0 ^ x1 ^ x3;
    x2 = x2 ^ x3 ^ (x1 << 7);
    x0 = x0.rotate_left(5);
    x2 = x2.rotate_left(22);

    new_block[0] = x0;
    new_block[1] = x1;
    new_block[2] = x2;
    new_block[3] = x3;

    new_block
}

fn inv_linear_transform(block: [u32; 4]) -> [u32; 4] {
    let mut new_block = [0; 4];
    let mut x0 = block[0];
    let mut x1 = block[1];
    let mut x2 = block[2];
    let mut x3 = block[3];

    x2 = x2.rotate_right(22);
    x0 = x0.rotate_right(5);
    x2 = x2 ^ x3 ^ (x1 << 7);
    x0 = x0 ^ x1 ^ x3;
    x3 = x3.rotate_right(7);
    x1 = x1.rotate_right(1);
    x3 = x3 ^ x2 ^ (x0 << 3);
    x1 = x1 ^ x0 ^ x2;
    x2 = x2.rotate_right(3);
    x0 = x0.rotate_right(13);

    new_block[0] = x0;
    new_block[1] = x1;
    new_block[2] = x2;
    new_block[3] = x3;

    new_block
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
    fn test_s_box_word() {
        let word = 0x43c48814;

        for i in 0..S_BOX.len() {
            let new_word = s_box_word(word, i);
            let new_word = inv_s_box_word(new_word, i);
            assert_eq!(word, new_word);
        }
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
    fn test_permutate() {
        let block = [0x0ff1f329, 0xb5b1351e, 0x57ff7387, 0x3739aedb];

        let block_ip = permutate(block, IP_TABLE);
        let block_fp = permutate(block_ip, FP_TABLE);

        assert_eq!(block, block_fp);
    }

    #[test]
    fn test_key_mix() {
        let key_sched = [0x069b3e6d, 0xbb5a1de3, 0x0a3d657e, 0xaf2aad1f];
        let block = [0x2ba2137b, 0xedc416b4, 0x5dc3673e, 0xaad94795];

        let block_mixed = key_mix(block, &key_sched[..]);
        let block_unmixed = key_mix(block_mixed, &key_sched[..]);

        assert_eq!(block, block_unmixed);
    }

    #[test]
    fn test_s_box_block() {
        let block = [0x793ff332, 0x259105b3, 0xd24a2080, 0x866714eb];

        for i in 0..8 {
            let block_s_box = s_box_block(block, i);
            let block_inv = inv_s_box_block(block_s_box, i);
            assert_eq!(block, block_inv);
        }
    }

    #[test]
    fn test_linear_transform() {
        let block = [0x12003b77, 0x363225d7, 0xa5832a18, 0xf3092c68];

        let block_trans = linear_transform(block);
        let block_inv = inv_linear_transform(block_trans);

        assert_eq!(block, block_inv);
    }
}

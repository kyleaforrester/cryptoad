// Algorithm specification can be found here:
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

use std::io::Write;

const S_BOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const INV_S_BOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

pub fn encrypt<W>(mut plain_text: Vec<u8>, key: &Vec<u8>, mut output: W) -> Result<(), String>
where
    W: Write,
{
    let num_rounds = validate_key(key)?;
    pad_plain_text(&mut plain_text);
    let key_schedule = gen_key_schedule(key, num_rounds);
    for block in plain_text.chunks(16) {
        let e_block = encrypt_block(block, &key_schedule, num_rounds);
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
    //Note that the cipher_text must be a multiple of 128 bytes
    //The Rijndael/AES encryption should have padded it so.
    let num_rounds = validate_key(key)?;
    let key_schedule = gen_key_schedule(key, num_rounds);
    //We must process the last block separately to strip out any padding
    let num_blocks = cipher_text.len() / 16;
    for block in cipher_text.chunks(16).take(num_blocks - 1) {
        let d_block = decrypt_block(block, &key_schedule, num_rounds);
        match output.write_all(&d_block) {
            Ok(_o) => (),
            Err(e) => return Err(format!("Error writing to file: {}", e)),
        }
    }

    //Decrypt the last block
    //Strip off the last X bytes according to the last byte
    let d_block = decrypt_block(
        &cipher_text[cipher_text.len() - 16..],
        &key_schedule,
        num_rounds,
    );
    let end_index = 16 - d_block[15];
    match output.write_all(&d_block[..(end_index as usize)]) {
        Ok(_o) => (),
        Err(e) => return Err(format!("Error writing to file: {}", e)),
    }
    Ok(())
}

fn validate_key(key: &Vec<u8>) -> Result<usize, String> {
    match key.len() {
        16 => Ok(10),
        24 => Ok(12),
        32 => Ok(14),
        _ => Err(format!(
            "Key must be 128, 192, or 256 bits long for Rijndael. Given key length is {}",
            key.len() * 8
        )),
    }
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

fn gen_key_schedule(key: &Vec<u8>, nr: usize) -> Vec<[u8; 4]> {
    let nk = match nr {
        10 => 4,
        12 => 6,
        _ => 8,
    };
    let mut key_sched = Vec::new();
    for i in 0..nk {
        let array = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
        key_sched.push(array);
    }

    let mut r_con = 1u8;

    for i in nk..4 * (nr + 1) {
        let mut temp = key_sched[i - 1];
        if i % nk == 0 {
            temp = sub_word(rot_word(temp));
            temp[0] ^= r_con;
            r_con = gf_mult(r_con, 2);
        } else if nk > 6 && i % nk == 4 {
            temp = sub_word(temp);
        }
        key_sched.push(xor_words(key_sched[i - nk], temp));
    }
    key_sched
}

fn sub_word(word: [u8; 4]) -> [u8; 4] {
    let mut new_word = [0; 4];
    for i in 0..4 {
        new_word[i] = S_BOX[word[i] as usize];
    }
    new_word
}

fn rot_word(word: [u8; 4]) -> [u8; 4] {
    [word[1], word[2], word[3], word[0]]
}

fn xor_words(word_a: [u8; 4], word_b: [u8; 4]) -> [u8; 4] {
    let mut new_word = [0; 4];
    for i in 0..4 {
        new_word[i] = word_a[i] ^ word_b[i];
    }
    new_word
}

fn encrypt_block(block: &[u8], key_sched: &Vec<[u8; 4]>, nr: usize) -> [u8; 16] {
    let mut state = [0; 16];
    state.copy_from_slice(block);
    state = add_round_key(state, &key_sched[0..4]);

    for r in 1..nr {
        state = sub_bytes(state);
        state = shift_rows(state);
        state = mix_columns(state);
        state = add_round_key(state, &key_sched[r * 4..(r + 1) * 4]);
    }

    state = sub_bytes(state);
    state = shift_rows(state);
    state = add_round_key(state, &key_sched[nr * 4..(nr + 1) * 4]);
    state
}

fn sub_bytes(state: [u8; 16]) -> [u8; 16] {
    let mut new_state = [0; 16];
    for i in 0..16 {
        new_state[i] = S_BOX[state[i] as usize];
    }
    new_state
}

fn shift_rows(state: [u8; 16]) -> [u8; 16] {
    let mut new_state = [0; 16];
    new_state[0] = state[0];
    new_state[1] = state[5];
    new_state[2] = state[10];
    new_state[3] = state[15];
    new_state[4] = state[4];
    new_state[5] = state[9];
    new_state[6] = state[14];
    new_state[7] = state[3];
    new_state[8] = state[8];
    new_state[9] = state[13];
    new_state[10] = state[2];
    new_state[11] = state[7];
    new_state[12] = state[12];
    new_state[13] = state[1];
    new_state[14] = state[6];
    new_state[15] = state[11];
    new_state
}

fn mix_columns(state: [u8; 16]) -> [u8; 16] {
    // Note that multiplying by 3 in a GF is equal to
    // GF_Multiplying by 2 and then XORing with itself
    // Note that GF_Multiply by 2 is a left shift followed
    // By a 0x1b XOR if the high bit is set
    let mut new_state = [0; 16];
    for i in 0..4 {
        let c = i * 4;
        new_state[c] =
            gf_mult(state[c], 2) ^ gf_mult(state[c + 1], 3) ^ state[c + 2] ^ state[c + 3];
        new_state[c + 1] =
            state[c] ^ gf_mult(state[c + 1], 2) ^ gf_mult(state[c + 2], 3) ^ state[c + 3];
        new_state[c + 2] =
            state[c] ^ state[c + 1] ^ gf_mult(state[c + 2], 2) ^ gf_mult(state[c + 3], 3);
        new_state[c + 3] =
            gf_mult(state[c], 3) ^ state[c + 1] ^ state[c + 2] ^ gf_mult(state[c + 3], 2);
    }
    new_state
}

fn gf_mult(byte: u8, amount: u8) -> u8 {
    match amount {
        1 => return byte,
        2 => {
            let mut new_byte = byte << 1;
            if byte & 0x80 > 0 {
                new_byte ^= 0x1b;
            }
            return new_byte;
        }
        3 => return gf_mult(byte, 2) ^ byte,
        4 => return gf_mult(gf_mult(byte, 2), 2),
        8 => return gf_mult(gf_mult(byte, 4), 2),
        //Now list out all the Inverse Mix Columns multiply amounts
        0x09 => return gf_mult(byte, 8) ^ byte,
        0x0b => return gf_mult(byte, 8) ^ gf_mult(byte, 3),
        0x0d => return gf_mult(byte, 8) ^ gf_mult(byte, 4) ^ byte,
        0x0e => return gf_mult(byte, 8) ^ gf_mult(byte, 4) ^ gf_mult(byte, 2),
        _ => panic!(
            "Not a Rijndael supported GF Multiplication amount: {}",
            amount
        ),
    }
}

fn add_round_key(state: [u8; 16], key_sched: &[[u8; 4]]) -> [u8; 16] {
    let mut new_state = [0; 16];
    for i in 0..4 {
        for j in 0..4 {
            new_state[i * 4 + j] = state[i * 4 + j] ^ key_sched[i][j];
        }
    }
    new_state
}

fn decrypt_block(block: &[u8], key_sched: &Vec<[u8; 4]>, nr: usize) -> [u8; 16] {
    let mut state = [0; 16];
    state.copy_from_slice(block);
    state = add_round_key(state, &key_sched[nr * 4..(nr + 1) * 4]);

    for r in (1..nr).rev() {
        state = inv_shift_rows(state);
        state = inv_sub_bytes(state);
        state = add_round_key(state, &key_sched[r * 4..(r + 1) * 4]);
        state = inv_mix_columns(state);
    }

    state = inv_shift_rows(state);
    state = inv_sub_bytes(state);
    state = add_round_key(state, &key_sched[0..4]);
    state
}

fn inv_shift_rows(state: [u8; 16]) -> [u8; 16] {
    let mut new_state = [0; 16];
    new_state[0] = state[0];
    new_state[1] = state[13];
    new_state[2] = state[10];
    new_state[3] = state[7];
    new_state[4] = state[4];
    new_state[5] = state[1];
    new_state[6] = state[14];
    new_state[7] = state[11];
    new_state[8] = state[8];
    new_state[9] = state[5];
    new_state[10] = state[2];
    new_state[11] = state[15];
    new_state[12] = state[12];
    new_state[13] = state[9];
    new_state[14] = state[6];
    new_state[15] = state[3];
    new_state
}

fn inv_sub_bytes(state: [u8; 16]) -> [u8; 16] {
    let mut new_state = [0; 16];
    for i in 0..16 {
        new_state[i] = INV_S_BOX[state[i] as usize];
    }
    new_state
}

fn inv_mix_columns(state: [u8; 16]) -> [u8; 16] {
    // Note that multiplying by 3 in a GF is equal to
    // GF_Multiplying by 2 and then XORing with itself
    // Note that GF_Multiply by 2 is a left shift followed
    // By a 0x1b XOR if the high bit is set
    let mut new_state = [0; 16];
    for i in 0..4 {
        let c = i * 4;
        new_state[c] = gf_mult(state[c], 0x0e)
            ^ gf_mult(state[c + 1], 0x0b)
            ^ gf_mult(state[c + 2], 0x0d)
            ^ gf_mult(state[c + 3], 0x09);
        new_state[c + 1] = gf_mult(state[c], 0x09)
            ^ gf_mult(state[c + 1], 0x0e)
            ^ gf_mult(state[c + 2], 0x0b)
            ^ gf_mult(state[c + 3], 0x0d);
        new_state[c + 2] = gf_mult(state[c], 0x0d)
            ^ gf_mult(state[c + 1], 0x09)
            ^ gf_mult(state[c + 2], 0x0e)
            ^ gf_mult(state[c + 3], 0x0b);
        new_state[c + 3] = gf_mult(state[c], 0x0b)
            ^ gf_mult(state[c + 1], 0x0d)
            ^ gf_mult(state[c + 2], 09)
            ^ gf_mult(state[c + 3], 0x0e);
    }
    new_state
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
    fn test_gen_key_schedule() {
        //TODO: Test 192 and 256 bit keys as well
        let key_128 = vec![
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];

        let key_sched_128 = gen_key_schedule(&key_128, 10);

        //For 128 bits only test last 4 words
        assert_eq!(key_sched_128.len(), 44);
        assert_eq!(key_sched_128[40], [0xd0, 0x14, 0xf9, 0xa8]);
        assert_eq!(key_sched_128[41], [0xc9, 0xee, 0x25, 0x89]);
        assert_eq!(key_sched_128[42], [0xe1, 0x3f, 0x0c, 0xc8]);
        assert_eq!(key_sched_128[43], [0xb6, 0x63, 0x0c, 0xa6]);
    }

    #[test]
    fn test_sub_word() {
        assert_eq!(sub_word([0xb9, 0x21, 0x2a, 0x68]), [0x56, 0xfd, 0xe5, 0x45]);
    }

    #[test]
    fn test_gf_mult() {
        assert_eq!(gf_mult(0x57, 0x01), 0x57);
        assert_eq!(gf_mult(0x57, 0x02), 0xae);
        assert_eq!(gf_mult(0x57, 0x03), 0x57 ^ 0xae);
        assert_eq!(gf_mult(0x57, 0x04), 0x47);
        assert_eq!(gf_mult(0x57, 0x08), 0x8e);
    }

    #[test]
    fn test_sub_bytes() {
        let bytes = [
            0x0e, 0xb5, 0xa2, 0x7d, 0xff, 0x1c, 0xcb, 0x27, 0xe8, 0x1e, 0xf0, 0x3f, 0xe3, 0x74,
            0xb4, 0xdf,
        ];
        assert_eq!(
            sub_bytes(bytes),
            [
                0xab, 0xd5, 0x3a, 0xff, 0x16, 0x9c, 0x1f, 0xcc, 0x9b, 0x72, 0x8c, 0x75, 0x11, 0x92,
                0x8d, 0x9e
            ]
        );
    }

    #[test]
    fn test_shift_rows() {
        let state = [
            0xd4, 0x27, 0x11, 0xae, 0xe0, 0xbf, 0x98, 0xf1, 0xb8, 0xb4, 0x5d, 0xe5, 0x1e, 0x41,
            0x52, 0x30,
        ];
        assert_eq!(
            shift_rows(state),
            [
                0xd4, 0xbf, 0x5d, 0x30, 0xe0, 0xb4, 0x52, 0xae, 0xb8, 0x41, 0x11, 0xf1, 0x1e, 0x27,
                0x98, 0xe5
            ]
        );
    }

    #[test]
    fn test_mix_columns() {
        let state = [
            0xd4, 0xbf, 0x5d, 0x30, 0xe0, 0xb4, 0x52, 0xae, 0xb8, 0x41, 0x11, 0xf1, 0x1e, 0x27,
            0x98, 0xe5,
        ];
        assert_eq!(
            mix_columns(state),
            [
                0x04, 0x66, 0x81, 0xe5, 0xe0, 0xcb, 0x19, 0x9a, 0x48, 0xf8, 0xd3, 0x7a, 0x28, 0x06,
                0x26, 0x4c
            ]
        );
    }

    #[test]
    fn test_add_round_key() {
        let state = [
            0x04, 0x66, 0x81, 0xe5, 0xe0, 0xcb, 0x19, 0x9a, 0x48, 0xf8, 0xd3, 0x7a, 0x28, 0x06,
            0x26, 0x4c,
        ];
        let round_key = [
            [0xa0, 0xfa, 0xfe, 0x17],
            [0x88, 0x54, 0x2c, 0xb1],
            [0x23, 0xa3, 0x39, 0x39],
            [0x2a, 0x6c, 0x76, 0x05],
        ];
        let answer = [
            0xa4, 0x9c, 0x7f, 0xf2, 0x68, 0x9f, 0x35, 0x2b, 0x6b, 0x5b, 0xea, 0x43, 0x02, 0x6a,
            0x50, 0x49,
        ];
        assert_eq!(add_round_key(state, &round_key[..]), answer);
    }

    #[test]
    fn test_encrypt_block() {
        let block = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
            0x07, 0x34,
        ];
        let key = vec![
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let key_sched = gen_key_schedule(&key, 10);
        let e_block = encrypt_block(&block, &key_sched, 10);

        assert_eq!(
            e_block,
            [
                0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a,
                0x0b, 0x32
            ]
        );
    }

    #[test]
    fn test_decrypt_block() {
        let block = [
            0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a,
            0x0b, 0x32,
        ];
        let key = vec![
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let key_sched = gen_key_schedule(&key, 10);
        let d_block = decrypt_block(&block, &key_sched, 10);

        assert_eq!(
            d_block,
            [
                0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
                0x07, 0x34
            ]
        );
    }
}

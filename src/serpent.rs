use std::io::Write;

pub fn encrypt<W>(mut plain_text: Vec<u8>, key: &Vec<u8>, output: W) -> Result<(), String>
where
    W: Write,
{
    pad_plain_text(&mut plain_text);
    let key_schedule = gen_key_schedule(key);
    for block in plain_text.chunks(16) {
        let e_block = encrypt_block(block, &key_schedule);
        match output.write_all(&e_block) {
            Ok(_o) => (),
            Err(e) => return Err(format!("Error writing to file: {}", e)),
        }
    }
    Ok(())
}

pub fn decrypt<W>(_cipher_text: Vec<u8>, _key: &Vec<u8>, _output: W) -> Result<(), String>
where
    W: Write,
{
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

fn gen_key_schedule(key: &Vec<u8>) -> [[u32; 4]; 33] {
    let padded_key = pad_key(key);
    

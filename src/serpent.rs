use std::io::{self, Write};

pub fn encrypt<W>(plain_text: Vec<u8>, key: &Vec<u8>, output: W) -> io::Result<()>
where W: Write {
    Ok(())
}

pub fn decrypt<W>(cipher_text: Vec<u8>, key: &Vec<u8>, output: W) -> io::Result<()>
where W: Write {
    Ok(())
}

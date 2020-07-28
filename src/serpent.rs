use std::io::Write;

pub fn encrypt<W>(_plain_text: Vec<u8>, _key: &Vec<u8>, _output: W) -> Result<(), String>
where
    W: Write,
{
    Ok(())
}

pub fn decrypt<W>(_cipher_text: Vec<u8>, _key: &Vec<u8>, _output: W) -> Result<(), String>
where
    W: Write,
{
    Ok(())
}

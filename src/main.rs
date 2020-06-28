use std::env;
use std::io::{self, Write, Read};
use std::fs::File;
use std::path::Path;
use std::fmt;

mod twofish;
mod rijndael;
mod serpent;
mod pontifex;

enum ArgState {
    Begin,
    ReceiveKey,
    ReceiveFiles,
    ReceiveAlgorithm,
}

enum Algorithm {
    Twofish,
    Rijndael,
    Serpent,
    Pontifex,
}

enum Direction {
    Encrypt,
    Decrypt,
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Algorithm::Twofish => write!(f, "twofish"),
            Algorithm::Rijndael => write!(f, "rijndael"),
            Algorithm::Serpent => write!(f, "serpent"),
            Algorithm::Pontifex => write!(f, "pontifex"),
        }
    }
}


fn main() {
    let (algorithm, files, key, direction) = parse_args();

    let algorithm = algorithm.expect("Error! -a option for algorithm must be defined. Use -h or --help for full options.");
    let key = key.expect("Error! -k option for key must be defined. Use -h or --help for full options.");
    let direction = direction.expect("Error! -d or -e option for direction must be defined. Use -h or --help for full options.");

    let byte_key = convert_hex(&key);

    if files.len() == 0 {
        match direction {
            Direction::Encrypt => encrypt_stdin(&algorithm, &byte_key),
            Direction::Decrypt => decrypt_stdin(&algorithm, &byte_key),
        }
    }
    else {
        match direction {
            Direction::Encrypt => encrypt_files(&algorithm, &byte_key, files),
            Direction::Decrypt => decrypt_files(&algorithm, &byte_key, files),
        }
    }
}

fn encrypt(plain_text: Vec<u8>, algorithm: &Algorithm, key: &Vec<u8>) -> Vec<u8> {
    let cipher_text = match algorithm {
        Algorithm::Twofish => twofish::encrypt(plain_text, key),
        Algorithm::Rijndael => rijndael::encrypt(plain_text, key),
        Algorithm::Serpent => serpent::encrypt(plain_text, key),
        Algorithm::Pontifex => pontifex::encrypt(plain_text, key),
    };
    cipher_text
}

fn decrypt(cipher_text: Vec<u8>, algorithm: &Algorithm, key: &Vec<u8>) -> Vec<u8> {
    let plain_text = match algorithm {
        Algorithm::Twofish => twofish::decrypt(cipher_text, key),
        Algorithm::Rijndael => rijndael::decrypt(cipher_text, key),
        Algorithm::Serpent => serpent::decrypt(cipher_text, key),
        Algorithm::Pontifex => pontifex::decrypt(cipher_text, key),
    };
    plain_text
}

fn encrypt_files(algorithm: &Algorithm, key: &Vec<u8>, files: Vec<String>) {
    for file_str in &files {
        let path = Path::new(file_str);
        let mut plain_text: Vec<u8> = Vec::new();
        let mut file;
        match File::open(&path) {
            Ok(f) => file = f,
            Err(error) => {
                eprintln!("Could not open file {}! {}", path.display(), error);
                continue;
            }
        }

        match file.read_to_end(&mut plain_text) {
            Ok(_f) => (),
            Err(error) => {
                eprintln!("Could not read from file {}! {}", path.display(), error);
                continue;
            }
        }

        let cipher_text = encrypt(plain_text, algorithm, key);

        let output_file_name = format!("{}_{}", file_str, algorithm);
        let mut output_file;
        let output_path = Path::new(&output_file_name);
        match File::create(&output_path) {
            Ok(f) => output_file = f,
            Err(error) => {
                eprintln!("Could not open output file {}! {}", output_path.display(), error);
                continue;
            }
        }

        match output_file.write_all(&cipher_text) {
            Ok(_f) => (),
            Err(error) => {
                eprintln!("Unable to write to new file {}! {}", output_path.display(), error);
                continue;
            }
        }
    }
}

fn decrypt_files(algorithm: &Algorithm, key: &Vec<u8>, files: Vec<String>) {
    for file_str in &files {
        let path = Path::new(file_str);
        let mut cipher_text: Vec<u8> = Vec::new();
        let mut file;
        match File::open(&path) {
            Ok(f) => file = f,
            Err(error) => {
                eprintln!("Could not open file {}! {}", path.display(), error);
                continue;
            }
        }

        match file.read_to_end(&mut cipher_text) {
            Ok(_f) => (),
            Err(error) => {
                eprintln!("Could not read from file {}! {}", path.display(), error);
                continue;
            }
        }

        let plain_text = decrypt(cipher_text, algorithm, key);

        let mut output_file;
        let new_file = format!("{}_{}", file_str, "decrypted");
        let output_path = Path::new(&new_file);
        match File::create(&output_path) {
            Ok(f) => output_file = f,
            Err(error) => {
                eprintln!("Could not open output file {}! {}", output_path.display(), error);
                continue;
            }
        }

        match output_file.write_all(&plain_text) {
            Ok(_f) => (),
            Err(error) => {
                eprintln!("Unable to write to new file {}! {}", output_path.display(), error);
                continue;
            }
        }
    }
}

fn encrypt_stdin(algorithm: &Algorithm, key: &Vec<u8>) {
    let mut plain_text: Vec<u8> = Vec::new();
    match io::stdin().read_to_end(&mut plain_text) {
        Ok(n) => (),
        Err(error) => panic!("Could not read from stdin! Error: {}", error),
    }

    let cipher_text = encrypt(plain_text, algorithm, key);

    match io::stdout().write_all(&cipher_text) {
        Ok(n) => (),
        Err(error) => panic!("Could not write to stdout! Error: {}", error),
    }
}

fn decrypt_stdin(algorithm: &Algorithm, key: &Vec<u8>) {
    let mut cipher_text: Vec<u8> = Vec::new();
    match io::stdin().read_to_end(&mut cipher_text) {
        Ok(n) => (),
        Err(error) => panic!("Could not read from stdin! Error: {}", error),
    }

    let plain_text = decrypt(cipher_text, algorithm, key);

    match io::stdout().write_all(&plain_text) {
        Ok(n) => (),
        Err(error) => panic!("Could not write to stdout! Error: {}", error),
    }
}

fn convert_hex(string: &str) -> Vec<u8> {
    let mut bytes = Vec::new();

    for tuple in string.chars().step_by(2).zip(string.chars().skip(1).step_by(2)) {
        let mut byte = hex_char_to_byte(tuple.0);
        byte <<= 4;
        byte += hex_char_to_byte(tuple.1);
        bytes.push(byte);
    }
    bytes
}

fn hex_char_to_byte(hex: char) -> u8 {
    let ret_hex = match hex {
        '0' => Some(0x0),
        '1' => Some(0x1),
        '2' => Some(0x2),
        '3' => Some(0x3),
        '4' => Some(0x4),
        '5' => Some(0x5),
        '6' => Some(0x6),
        '7' => Some(0x7),
        '8' => Some(0x8),
        '9' => Some(0x9),
        'a' => Some(0xa),
        'b' => Some(0xb),
        'c' => Some(0xc),
        'd' => Some(0xd),
        'e' => Some(0xe),
        'f' => Some(0xf),
        _ => None,
    };
    return ret_hex.expect("Key must be given as a hexadecimal string!");
}



fn parse_args() -> (Option<Algorithm>, Vec<String>, Option<String>, Option<Direction>) {
    let mut arg_state = ArgState::Begin;
    let mut files: Vec<String> = Vec::new();
    let mut algorithm = None;
    let mut key = None;
    let mut direction = None;
    for argument in env::args().skip(1) {
        match argument.as_str() {
            "-k" | "--key" => arg_state = ArgState::ReceiveKey,
            "-f" | "--files" => arg_state = ArgState::ReceiveFiles,
            "-a" | "--algorithm" => arg_state = ArgState::ReceiveAlgorithm,
            "-d" | "--decrypt" => direction = Some(Direction::Decrypt),
            "-e" | "--encrypt" => direction = Some(Direction::Encrypt),
            "-h" | "--help" => help_args(),
            _ => {
                match arg_state {
                    ArgState::Begin => {
                        eprintln!("Error unknown argument {}! Expected argument flags -k, -f, -a, -d, -e, or -h.  Usage:", argument);
                        help_args();
                    },
                    ArgState::ReceiveKey => key = Some(argument),
                    ArgState::ReceiveFiles => files.push(argument),
                    ArgState::ReceiveAlgorithm => algorithm = match_algorithm(&argument),
                }
            }
        }
    }
    return (algorithm, files, key, direction);
}

fn match_algorithm(algorithm: &str) -> Option<Algorithm> {
    match algorithm {
        "Twofish" | "twofish" => return Some(Algorithm::Twofish),
        "Rijndael" | "rijndael" => return Some(Algorithm::Rijndael),
        "AES" | "aes" => return Some(Algorithm::Rijndael),
        "Serpent" | "serpent" => return Some(Algorithm::Serpent),
        "Pontifex" | "pontifex" => return Some(Algorithm::Pontifex),
        _ => return None,
    }
}


fn help_args() {
    println!("Help args... help yourself.");
    std::process::exit(0);
}

use std::env;
use std::io::{self, Write, Read};
use std::fs::File;
use std::path::Path;

use alg::twofish;
use alg::rijndael;
use alg::serpent;
use alg::pontifex;

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
    let (mut algorithm, files, mut key, direction) = parse_args();

    match algorithm {
        Some(x) => (),
        None => {
            eprintln!("Error! -a option for algorithm must be defined");
            help_args();
        }
    }

    match key {
        Some(x) => (),
        None => {
            eprintln!("Error! -k option for key must be defined");
            help_args();
        }
    }

    match direction {
        Some(x) => (),
        None => {
            eprintln!("Error! -d or -e option for direction must be defined");
            help_args();
        }
    }

    let byte_key = convert_hex(key);

    if files.len() == 0 {
        match direction {
            Direction::Encrypt => encrypt_stdin(algorithm, byte_key),
            Direction::Decrypt => decrypt_stdin(algorithm, byte_key),
        }
    }
    else {
        match direction {
            Direction::Encrypt => encrypt_files(algorithm, byte_key, files),
            Direction::Decrypt => decrypt_files(algorithm, byte_key, files),
        }
    }
}

fn encrypt(plain_text: Vec<u8>, algorithm: Algorithm, key: Vec<u8>) -> Vec<u8> {
    let cipher_text = match algorithm {
        Algorithm::Twofish => alg::twofish::encrypt(plain_text, key),
        Algorithm::Rijndael => alg::rijndael::encrypt(plain_text, key),
        Algorithm::Serpent => alg::serpent::encrypt(plain_text, key),
        Algorithm::Pontifex => alg::pontifex::encrypt(plain_text, key),
    }
    cipher_text
}

fn decrypt(cipher_text: Vec<u8>, algorithm: Algorithm, key: Vec<u8>) -> Vec<u8> {
    let plain_text = match algorithm {
        Algorithm::Twofish => alg::twofish::decrypt(cipher_text, key),
        Algorithm::Rijndael => alg::rijndael::decrypt(cipher_text, key),
        Algorithm::Serpent => alg::serpent::decrypt(cipher_text, key),
        Algorithm::Pontifex => alg::pontifex::decrypt(cipher_text, key),
    }
    plain_text
}

fn encrypt_files(algorithm: Algorithm, key: Vec<u8>, files: Vec<String>) {
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

        match file.read_to_end(&plain_text) {
            Ok(f) => (),
            Err(error) => {
                eprintln!("Could not read from file {}! {}", path.display(), error);
                continue;
            }
        }

        let cipher_text = encrypt(plain_text, algorithm, key);

        let mut output_file;
        let output_path = Path::new(format!("{}_{}", file_str, algorithm);
        match File::create(&output_path) {
            Ok(f) => output_file = f,
            Err(error) => {
                eprintln!("Could not open output file {}! {}", output_path.display(), error);
                continue;
            }
        }

        match output_file.write_all(cipher_text) {
            Ok() => (),
            Err(error) => {
                eprintln!("Unable to write to new file {}! {}", output_path.display(), error);
                continue;
            }
        }
    }
}

fn decrypt_files(algorithm: Algorithm, key: Vec<u8>, files: Vec<String>) {
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

        match file.read_to_end(&cipher_text) {
            Ok(f) => (),
            Err(error) => {
                eprintln!("Could not read from file {}! {}", path.display(), error);
                continue;
            }
        }

        let plain_text = decrypt(cipher_text, algorithm, key);

        let mut output_file;
        let output_path = Path::new(file_str.push_str("_decrypted"));
        match File::create(&output_path) {
            Ok(f) => output_file = f,
            Err(error) => {
                eprintln!("Could not open output file {}! {}", output_path.display(), error);
                continue;
            }
        }

        match output_file.write_all(plain_text) {
            Ok() => (),
            Err(error) => {
                eprintln!("Unable to write to new file {}! {}", output_path.display(), error);
                continue;
            }
        }
    }
}

fn encrypt_stdin(algorithm: Algorithm, key: Vec<u8>) {
    let mut plain_text: Vec<u8> = Vec::new();
    match io::stdin().read_to_end(plain_text) {
        Ok(n) => (),
        Err(error) => panic!("Could not read from stdin! Error: {}", error),
    }

    let cipher_text = encrypt(plain_text, algorithm, key);

    match io::stdout().write_all(cipher_text) {
        Ok(n) => (),
        Err(error) => panic!("Could not write to stdout! Error: {}", error),
    }
}

fn decrypt_stdin(algorithm: Algorithm, key: Vec<u8>) {
    let mut cipher_text: Vec<u8> = Vec::new();
    match io::stdin().read_to_end(cipher_text) {
        Ok(n) => (),
        Err(error) => panic!("Could not read from stdin! Error: {}", error),
    }

    let plain_text = decrypt(cipher_text, algorithm, key);

    match io::stdout().write_all(plain_text) {
        Ok(n) => (),
        Err(error) => panic!("Could not write to stdout! Error: {}", error),
    }
}

fn convert_hex(string: &str) -> Vec<u8> {
    let hex_vec = Vec::new();
    let key_length = string.chars().len();

    if key_length % 2 != 0 {
        panic!("Key bit length must be divisible by 8!");
    }

    for ind in (0..key_length).step_by(2) {
        let mut byte = 0;
        for add in 0..2 {
            match string[ind+add] {
                '0' => byte += 0x0,
                '1' => byte += 0x1,
                '2' => byte += 0x2,
                '3' => byte += 0x3,
                '4' => byte += 0x4,
                '5' => byte += 0x5,
                '6' => byte += 0x6,
                '7' => byte += 0x7,
                '8' => byte += 0x8,
                '9' => byte += 0x9,
                'a' => byte += 0xa,
                'b' => byte += 0xb,
                'c' => byte += 0xc,
                'd' => byte += 0xd,
                'e' => byte += 0xe,
                'f' => byte += 0xf,
                _ => panic!("Key contains non-hexadecimal character!"),
            }
            if add < 1 {
                byte <<= 4;
            }
        }
        hex_vec.push(byte);
    }
    hex_vec
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
                    ArgState::ReceiveAlgorithm => algorithm = match_algorithm(argument),
                }
            }
        }
    }
    return (algorithm, files, key);
}

fn match_algorithm(algorithm: &str) -> Option<Algorithm> {
    match algorithm {
        "Twofish" => return Some(Algorithm::Twofish),
        "Rijndael" => return Some(Algorithm::Rijndael),
        "AES" => return Some(Algorithm::Rijndael),
        "Serpent" => return Some(Algorithm::Serpent),
        "Pontifex" => return Some(Algorithm::Pontifex),
        _ => return None,
    }
    None
}


fn help_args() {
    println!("Help args... help yourself.");
    std::process::exit(0);
}

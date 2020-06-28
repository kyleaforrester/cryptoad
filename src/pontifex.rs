use std::fmt;

#[derive (PartialEq, Clone, Copy)]
enum Card {
    Basic(usize),
    JokerA,
    JokerB,
}

impl fmt::Display for Card {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Basic(i) => write!(f, "{}", i),
            Self::JokerA => write!(f, "JA"),
            Self::JokerB => write!(f, "JB"),
        }
    }
}


pub fn encrypt(plain_text: Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let deck = init_deck();
    let deck = key_deck(deck, key);
    let keystream = gen_keystream(deck, plain_text.len());

    let mut cipher_text = Vec::new();
    for i in 0..keystream.len() {
        cipher_text.push(keystream[i] ^ plain_text[i]);
    }
    cipher_text
}

pub fn decrypt(cipher_text: Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    Vec::new()
}

fn gen_keystream(mut deck: Vec<Card>, length: usize) -> Vec<u8> {
    let mut keystream = Vec::new();
    while keystream.len() < length {
        shift_joker_a(&mut deck);
        shift_joker_b(&mut deck);
        deck = triple_cut(deck);
        deck = count_cut(deck);
        match output_byte(&deck) {
            Some(b) => keystream.push(b),
            None => (),
        }
    }
    keystream
}

fn init_deck() -> Vec<Card> {
    let mut deck = Vec::new();
    for i in 1..257 {
        deck.push(Card::Basic(i));
    }
    deck.push(Card::JokerA);
    deck.push(Card::JokerB);
    deck
}

fn key_deck(mut deck: Vec<Card>, key: &Vec<u8>) -> Vec<Card> {
    for k in key {
        shift_joker_a(&mut deck);
        shift_joker_b(&mut deck);
        deck = triple_cut(deck);
        deck = count_cut(deck);
        deck = key_cut(deck, (*k as usize) + 1);
    }
    deck
}

fn triple_cut(deck: Vec<Card>) -> Vec<Card> {
    let joker_pos: Vec<(usize, &Card)> = deck.iter().enumerate().filter(|&x| *(x.1) == Card::JokerA || *(x.1) == Card::JokerB).collect();
    let first_j = joker_pos[0].0;
    let second_j = joker_pos[1].0;

    let mut new_deck = Vec::new();
    new_deck.extend_from_slice(&deck[second_j+1..]);
    new_deck.push(deck[first_j]);
    new_deck.extend_from_slice(&deck[first_j+1..second_j]);
    new_deck.push(deck[second_j]);
    new_deck.extend_from_slice(&deck[..first_j]);
    new_deck
}

fn count_cut(deck: Vec<Card>) -> Vec<Card> {
    let count = match deck[deck.len()-1] {
        Card::Basic(i) => i,
        _ => return deck,
    };
    let mut new_deck = Vec::new();
    new_deck.extend_from_slice(&deck[count..deck.len()-1]);
    new_deck.extend_from_slice(&deck[..count]);
    new_deck.push(deck[deck.len()-1]);
    new_deck
}

fn key_cut(deck: Vec<Card>, key_byte: usize) -> Vec<Card> {
    let mut new_deck = Vec::new();
    new_deck.extend_from_slice(&deck[key_byte..deck.len()-1]);
    new_deck.extend_from_slice(&deck[..key_byte]);
    new_deck.push(deck[deck.len()-1]);
    new_deck
}

fn output_byte(deck: &Vec<Card>) -> Option<u8> {
    let count_index = match deck[0] {
        Card::Basic(i) => i,
        _ => 257,
    };
    match deck[count_index] {
        Card::Basic(i) => return Some((i-1) as u8),
        _ => return None,
    }
}

fn shift_joker_a(deck: &mut Vec<Card>) {
    let joker_ind = deck.iter().position(|&x| x == Card::JokerA).unwrap();
    if joker_ind < deck.len()-1 {
        //JokerA not last card
        deck[joker_ind] = deck[joker_ind+1];
        deck[joker_ind+1] = Card::JokerA;
    }
    else {
        //JokerA is the last card!
        deck.pop();
        deck.insert(1, Card::JokerA);
    }
}

fn shift_joker_b(deck: &mut Vec<Card>) {
    let joker_ind = deck.iter().position(|&x| x == Card::JokerB).unwrap();
    if joker_ind < deck.len() - 2 {
        //Joker in the middle
        for i in 0..2 {
            deck[joker_ind+i] = deck[joker_ind+i+1];
        }
        deck[joker_ind+2] = Card::JokerB;
    }
    else {
        //Joker near the end
        let distance = deck.len() - joker_ind;
        deck.remove(joker_ind);
        deck.insert(3-distance, Card::JokerB);
    }
}

fn print_deck(deck: &Vec<Card>) {
    for c in deck.iter().enumerate() {
        print!("{}:{},", c.0, c.1);
    }
}

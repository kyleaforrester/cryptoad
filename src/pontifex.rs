use std::fmt;
use std::io::Write;

const PILES: usize = 6;

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


pub fn encrypt<W>(plain_text: Vec<u8>, key: &Vec<u8>, mut output: W) -> Result<(), String>
where W: Write {
    let mut deck = init_deck();
    deck = key_deck(deck, key);
    for i in 0..plain_text.len() {
        let (byte, new_deck) = gen_byte(deck);
        deck = new_deck;
        match output.write_all(&[plain_text[i] ^ byte]) {
            Ok(_a) => (),
            Err(e) => return Err(format!("Error writing to file: {}", e)),
        }
    }
    Ok(())
}

pub fn decrypt<W>(cipher_text: Vec<u8>, key: &Vec<u8>, output: W) -> Result<(), String>
where W: Write {
    encrypt(cipher_text, key, output)
}

fn gen_byte(mut deck: Vec<Card>) -> (u8, Vec<Card>) {
    loop {
        shift_joker_a(&mut deck);
        shift_joker_b(&mut deck);
        deck = triple_cut(deck);
        deck = count_cut(deck);
        match output_byte(&deck) {
            Some(b) => break (b, deck),
            None => (),
        }
    }
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
        for i in 0..8 {
            shift_joker_a(&mut deck);
            shift_joker_b(&mut deck);
            deck = triple_cut(deck);
            deck = count_cut(deck);
            if (k >> i) & 1 == 0 {
                deck = shuffle(deck);
            }
            else {
                deck = pile_shuffle(deck);
            }
        }
        deck = key_cut(deck, (*k as usize) + 1);
    }
    deck
}

fn shuffle(deck: Vec<Card>) -> Vec<Card> {
    let mut new_deck = Vec::new();
    let first_half = deck.iter().take(deck.len()/2);
    let second_half = deck.iter().skip(deck.len()/2);
    for pair in first_half.zip(second_half) {
        new_deck.push(*pair.0);
        new_deck.push(*pair.1);
    }
    new_deck
}

fn pile_shuffle(deck: Vec<Card>) -> Vec<Card> {
    // There are 258 cards in a deck.
    // Pile shuffle into 6 decks of 43 each.
    let mut new_deck = Vec::new();
    for i in 0..PILES {
        new_deck.extend(deck.iter().skip(i).step_by(PILES));
    }
    new_deck
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


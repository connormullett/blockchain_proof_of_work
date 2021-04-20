use data_encoding::HEXUPPER;
use rand::Rng;
use ring::digest::{Context, Digest, SHA256};
use std::io::{Read, Result};

#[allow(dead_code)]
struct Block {
    prev_hash: Digest,
    messages: Vec<String>,
    proof: Option<String>,
}

impl Block {
    fn new(prev_hash: Digest, messages: Vec<String>) -> Self {
        Self {
            prev_hash,
            messages,
            proof: None,
        }
    }

    fn to_string(&self) -> String {
        let mut block_vec = Vec::new();
        block_vec.push(HEXUPPER.encode(self.prev_hash.as_ref()));
        for mut message in self.messages.clone().into_iter() {
            message = message.replace(" ", "%20");
            block_vec.push(message.clone());
        }

        if let Some(value) = &self.proof {
            block_vec.push(HEXUPPER.encode(value.as_ref()));
        }

        block_vec.join(" ")
    }

    fn hash_hex_code(&self) -> String {
        let block_as_string = self.to_string();
        let digest = sha256_digest(block_as_string.as_bytes()).unwrap();
        HEXUPPER.encode(digest.as_ref())
    }
}

fn mine(hash: &[u8]) -> (u32, String) {
    let mut rng = rand::thread_rng();
    loop {
        let guess: u32 = rng.gen();
        let mut hash_cat = String::new();

        hash_cat.push_str(&HEXUPPER.encode(hash.as_ref()));
        hash_cat.push_str(&HEXUPPER.encode(&guess.to_be_bytes()));

        let new_hash = sha256_digest(hash_cat.as_bytes()).unwrap();
        println!("{}", HEXUPPER.encode(new_hash.as_ref()));
        let hexcode_hash = HEXUPPER.encode(new_hash.as_ref());

        if hexcode_hash.starts_with("00000") {
            return (guess, hexcode_hash);
        }
    }
}

fn verify(block_hash: &[u8], guess: u32) -> bool {
    let mut cat_hash = String::new();

    cat_hash.push_str(&HEXUPPER.encode(block_hash.as_ref()));
    cat_hash.push_str(&HEXUPPER.encode(&guess.to_be_bytes()));

    let hash = sha256_digest(cat_hash.as_bytes()).unwrap();
    HEXUPPER.encode(hash.as_ref()).starts_with("00000")
}

fn sha256_digest<R: Read>(mut reader: R) -> Result<Digest> {
    let mut context = Context::new(&SHA256);
    let mut buffer = [0; 1024];

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
    }

    Ok(context.finish())
}

fn main() -> Result<()> {
    let genesis_block = String::from("genesis");

    let genesis_hash = sha256_digest(genesis_block.as_bytes())?;

    let messages = vec!["block", "chain", "is cool"]
        .iter()
        .map(|&value| value.to_string())
        .collect();

    let mut block = Block::new(genesis_hash, messages);

    let block_hash = sha256_digest(block.to_string().as_bytes()).unwrap();

    let (guess, new_hash) = mine(block_hash.as_ref());
    println!("mined block {} {}", guess, new_hash);

    let result = verify(block_hash.as_ref(), guess);

    println!("hash verified {}", result);
    println!("block {}", HEXUPPER.encode(block_hash.as_ref()));

    block.proof = Some(new_hash);

    println!(
        "mined block hash with proof of work {}",
        block.hash_hex_code()
    );

    Ok(())
}

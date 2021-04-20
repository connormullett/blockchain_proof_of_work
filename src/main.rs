use data_encoding::HEXUPPER;
use ring::digest::{Context, Digest, SHA256};
use ring::rand::SecureRandom;
use ring::{hmac, rand};
use std::fs::File;
use std::io::{BufReader, Read, Result, Write};

struct Block {
    prev_hash: Digest,
    messages: Vec<String>,
    proof: Option<Digest>,
}

impl Block {
    fn new(prev_hash: Digest, messages: Vec<String>) -> Self {
        Self {
            prev_hash,
            messages,
            proof: None,
        }
    }
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

    let digest = sha256_digest(genesis_block.as_bytes())?;

    println!("digest {}", HEXUPPER.encode(digest.as_ref()));

    Ok(())
}

use ecc::ecdsa::PrivateKey;
use primitive_types::U256;
use utils::hash256::hash256;

mod base58;
mod ecc;
pub mod error;
mod script;
mod transactions;
mod utils;

fn main() {
    let e = U256::from(12345);
    let message = b"Programming Bitcoin!";
    let message_bytes = hash256(message);

    let z = U256::from_big_endian(&message_bytes);
    println!("{:?}", z);
    let private_key = PrivateKey::new(e);
    let signature = private_key.sign(z).unwrap();
    println!("{}", signature);

    let public_key = private_key.public_key();

    let is_valid = public_key.verify_signature(z, &signature);
    if is_valid {
        println!("verified correctly");
    }
}

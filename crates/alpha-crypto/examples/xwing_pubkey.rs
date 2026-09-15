//! cargo run -p alpha-crypto --example xwing_pubkey -- <32-byte seed hex>  → the 1216-byte public key, hex

fn main() {
    let seed = std::env::args().nth(1).expect("seed hex");
    let seed: [u8; 32] = hex::decode(seed).unwrap().try_into().unwrap();
    let key = alpha_crypto::PrivateKey::from_seed(seed);
    println!("{}", hex::encode(key.public().as_bytes()));
}

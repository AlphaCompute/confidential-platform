//! cargo run -p alpha-crypto --example xwing_pubkey -- <32-byte seed hex>  → the 1216-byte public key, hex

fn main() -> Result<(), String> {
    let seed = std::env::args()
        .nth(1)
        .ok_or("usage: xwing_pubkey <seed hex>")?;
    let seed = alpha_core::hex_bytes::<32>(&seed).ok_or("seed: 64 lowercase hex digits")?;
    let key = alpha_crypto::PrivateKey::from_seed(seed).map_err(|e| e.to_string())?;
    println!("{}", hex::encode(key.public().as_bytes()));
    Ok(())
}

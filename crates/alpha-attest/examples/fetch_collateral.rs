//! cargo run -p alpha-attest --example fetch_collateral -- <pccs-url> <quote.hex> > collateral.json

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), String> {
    let [pccs_url, quote_path] = std::env::args()
        .skip(1)
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| "usage: fetch_collateral <pccs-url> <quote.hex>")?;
    let text = std::fs::read_to_string(&quote_path).map_err(|e| format!("{quote_path}: {e}"))?;
    let quote = hex::decode(text.trim()).map_err(|e| format!("{quote_path}: {e}"))?;
    let collateral = alpha_attest::fetch_collateral(&pccs_url, &quote)
        .await
        .map_err(|e| e.to_string())?;
    println!(
        "{}",
        serde_json::to_string_pretty(&collateral).map_err(|e| e.to_string())?
    );
    Ok(())
}

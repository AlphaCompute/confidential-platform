//! cargo run -p alpha-attest --example fetch_collateral -- <pccs-url> <quote.hex> > collateral.json

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let [pccs_url, quote_path] = std::env::args()
        .skip(1)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let quote = hex::decode(std::fs::read_to_string(quote_path).unwrap().trim()).unwrap();
    let collateral = alpha_attest::fetch_collateral(&pccs_url, &quote)
        .await
        .unwrap();
    println!("{}", serde_json::to_string_pretty(&collateral).unwrap());
}

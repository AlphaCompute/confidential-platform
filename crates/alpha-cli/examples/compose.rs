//! Prints the compose `alpha deploy` would sign for a tenant YAML: `cargo run --example compose -- app.yaml`.
fn main() -> Result<(), String> {
    let path = std::env::args().nth(1).ok_or("usage: compose app.yaml")?;
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
    print!(
        "{}",
        alpha_cli::deploy::compose(&alpha_cli::deploy::parse(&text)?)?
    );
    Ok(())
}

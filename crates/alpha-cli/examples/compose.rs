//! Prints the compose `alpha deploy` would sign for a tenant YAML: `cargo run --example compose -- app.yaml`.
fn main() {
    let path = std::env::args().nth(1).expect("path to app.yaml");
    let spec = alpha_cli::deploy::parse(&std::fs::read_to_string(path).unwrap()).unwrap();
    print!("{}", alpha_cli::deploy::compose(&spec).unwrap());
}

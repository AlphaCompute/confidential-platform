//! Refuses to build a platform-document verifier on the production release key set while it is
//! still the placeholder, so no production image or page ships without the ceremony's key.

fn main() -> Result<(), String> {
    println!("cargo::rerun-if-changed=release-keys/prod.pub");
    let required = std::env::var_os("CARGO_FEATURE_REQUIRE_RELEASE_KEYS").is_some();
    let dev = std::env::var_os("CARGO_FEATURE_DEV").is_some();
    if !required || dev {
        return Ok(());
    }
    let text = std::fs::read_to_string("release-keys/prod.pub")
        .map_err(|e| format!("release-keys/prod.pub: {e}"))?;
    let mut keys = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .peekable();
    if keys.peek().is_some()
        && keys.all(|key| key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Ok(());
    }
    Err(
        "release-keys/prod.pub holds no production release key set: generate it at the key \
         ceremony, or build the dev variant (`dev`, `dev-root` for alpha-kms)"
            .into(),
    )
}

//! Refuses to build a platform-document verifier on the production release key set while it is
//! still the placeholder or could never meet the production threshold, so no production image or
//! page ships without the ceremony's keys.

// The production threshold in src/platform.rs; release_keys() checks the same at runtime.
const PRODUCTION_THRESHOLD: usize = 2;

fn main() -> Result<(), String> {
    println!("cargo::rerun-if-changed=release-keys/prod.pub");
    let required = std::env::var_os("CARGO_FEATURE_REQUIRE_RELEASE_KEYS").is_some();
    let dev = std::env::var_os("CARGO_FEATURE_DEV").is_some();
    if !required || dev {
        return Ok(());
    }
    let text = std::fs::read_to_string("release-keys/prod.pub")
        .map_err(|e| format!("release-keys/prod.pub: {e}"))?;
    let mut keys: Vec<String> = text
        .lines()
        .map(|l| l.trim().to_ascii_lowercase())
        .filter(|l| !l.is_empty())
        .collect();
    let hex = keys
        .iter()
        .all(|key| key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit()));
    let listed = keys.len();
    keys.sort_unstable();
    keys.dedup();
    if hex && keys.len() == listed && listed >= PRODUCTION_THRESHOLD {
        return Ok(());
    }
    Err(format!(
        "release-keys/prod.pub is not a production release key set of at least \
         {PRODUCTION_THRESHOLD} distinct hex keys: generate it at the key ceremony, or build the \
         dev variant (`dev`, `dev-root` for alpha-kms)"
    ))
}

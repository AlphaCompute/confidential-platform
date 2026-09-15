//! Renders the KMS node's compose for a built image and writes the unsigned release manifest:
//!   cargo run -p alpha-cli --example kms_compose -- [--dev-root] <app_id> <image@sha256:…> <out_dir>
//! `<out_dir>/app-compose.json` holds the exact bytes Phala measures; `<out_dir>/manifest.json`
//! the image reference and `compose_hash` the release-key holder puts into `kms_revisions`.
use std::path::PathBuf;

use alpha_core::{AppId, compose_hash};
use serde_json::json;

fn main() -> Result<(), String> {
    const USAGE: &str = "usage: kms_compose [--dev-root] <app_id> <image@sha256:…> <out_dir>";
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let dev_root = args.first().is_some_and(|a| a == "--dev-root");
    if dev_root {
        args.remove(0);
    }
    let [app_id, image, out_dir] = <[String; 3]>::try_from(args).map_err(|_| USAGE)?;
    let app_id: AppId = app_id.parse().map_err(|e| format!("app_id: {e}"))?;
    let compose = alpha_cli::deploy::kms_compose(app_id, &image, dev_root)?;
    let manifest = json!({
        "image": image,
        "compose_hash": compose_hash(&compose),
    });
    let manifest = serde_json::to_string_pretty(&manifest).map_err(|e| e.to_string())? + "\n";
    let out_dir = PathBuf::from(out_dir);
    std::fs::create_dir_all(&out_dir)
        .and_then(|()| std::fs::write(out_dir.join("app-compose.json"), &compose))
        .and_then(|()| std::fs::write(out_dir.join("manifest.json"), &manifest))
        .map_err(|e| format!("{}: {e}", out_dir.display()))?;
    print!("{manifest}");
    Ok(())
}

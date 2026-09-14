use serde_json::Value;
use sha2::{Digest, Sha256};

pub mod context {
    pub const REVISION: &str = "alphacompute/revision/v1";
    pub const SECRET: &str = "alphacompute/secret/v1";
    pub const PRINCIPAL_KEY: &str = "alphacompute/principal-key/v1";
    pub const CONTROL: &str = "alphacompute/control/v1";
    pub const PLATFORM: &str = "alphacompute/platform/v1";
    pub const NODE_BOOTSTRAP: &str = "alphacompute/node-bootstrap/v1";
}

pub fn jcs(document: &Value) -> serde_json::Result<Vec<u8>> {
    serde_json_canonicalizer::to_vec(document)
}

pub fn signing_digest(context: &str, document: &Value) -> serde_json::Result<[u8; 32]> {
    Ok(Sha256::new()
        .chain_update(context)
        .chain_update([0u8])
        .chain_update(jcs(document)?)
        .finalize()
        .into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn jcs_sorts_keys_and_formats_numbers_per_rfc8785() {
        let doc = json!({"b": 1.0, "a": [true, null, "ü"], "c": 1e21});
        assert_eq!(
            jcs(&doc).unwrap(),
            r#"{"a":[true,null,"ü"],"b":1,"c":1e+21}"#.as_bytes()
        );
    }

    #[test]
    fn digest_binds_the_context() {
        let doc = json!({"x": 1});
        assert_ne!(
            signing_digest(context::REVISION, &doc).unwrap(),
            signing_digest(context::CONTROL, &doc).unwrap()
        );
        let manual: [u8; 32] = Sha256::digest(b"alphacompute/revision/v1\0{\"x\":1}").into();
        assert_eq!(signing_digest(context::REVISION, &doc).unwrap(), manual);
    }
}

//! The KBS's `Vault` resource backend (`kbs/src/plugins/implementations/resource/vault_kv.rs`,
//! vaultrs 0.8.0 `kv1::get`) reads `GET {vault_url}/v1/{mount}/{repo}/{type}/{tag}` with an
//! `X-Vault-Token` header and takes the `data` key of the reply's `data`. A byte array there is the
//! resource's bytes exactly.

use serde_json::{Value, json};

/// The mount the feed serves under.
pub const MOUNT: &str = "alpha";

/// The path a resource is read at, below the Vault address.
pub fn read_path(resource_path: &str) -> String {
    format!("/v1/{MOUNT}/{resource_path}")
}

/// The reply vaultrs 0.8.0 parses (`GetSecretResponse`) carrying `value`.
pub fn kv1_read_reply(value: &[u8]) -> Value {
    json!({
        "request_id": "",
        "lease_id": "",
        "renewable": false,
        "lease_duration": 0,
        "data": { "data": value },
        "wrap_info": null,
        "warnings": null,
        "auth": null,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_value_is_the_byte_array_trustee_reads_back() {
        let reply = kv1_read_reply(&[0, 1, 255]);
        assert_eq!(reply["data"]["data"], json!([0, 1, 255]));
        let bytes: Vec<u8> = serde_json::from_value(reply["data"]["data"].clone()).unwrap();
        assert_eq!(bytes, [0, 1, 255]);
        assert_eq!(read_path("a/b/c"), "/v1/alpha/a/b/c");
    }
}

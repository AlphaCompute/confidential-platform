use std::fmt;

use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};

pub mod context {
    pub const REVISION: &str = "alphacompute/revision/v1";
    pub const SECRET: &str = "alphacompute/secret/v1";
    pub const ORG_ROOT_KEY: &str = "alphacompute/org-root-key/v1";
    pub const PRINCIPAL_KEY: &str = "alphacompute/principal-key/v1";
    pub const CONTROL: &str = "alphacompute/control/v1";
    pub const PLATFORM: &str = "alphacompute/platform/v1";
    pub const NODE_BOOTSTRAP: &str = "alphacompute/node-bootstrap/v1";
    pub const INNER_CHANNEL: &str = "alphacompute/inner-channel/v1";
    pub const CONNECTOR_REQUEST: &str = "alphacompute/connector-request/v1";
    pub const CONNECTOR_GRANT: &str = "alphacompute/connector-grant/v1";
    pub const CONNECTOR_WRITE: &str = "alphacompute/connector-write/v1";
    pub const KMS_RECEIPT: &str = "alphacompute/kms-receipt/v1";
    pub const CATALOG: &str = "alphacompute/catalog/v1";
}

pub fn jcs(document: &Value) -> serde_json::Result<Vec<u8>> {
    serde_json_canonicalizer::to_vec(document)
}

/// Parses JSON, refusing a repeated object key at any depth: serde_json keeps the last value
/// while other canonicalizers refuse the document, and the bytes a party hashes must mean one
/// document to everyone.
pub fn parse(bytes: &[u8]) -> serde_json::Result<Value> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let value = Unique.deserialize(&mut de)?;
    de.end()?;
    Ok(value)
}

struct Unique;

impl<'de> DeserializeSeed<'de> for Unique {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Unique {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("JSON")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("not a finite number"))
    }

    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }

    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(v) = seq.next_element_seed(Unique)? {
            out.push(v);
        }
        Ok(Value::Array(out))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut out = Map::new();
        while let Some(k) = map.next_key::<String>()? {
            if out.contains_key(&k) {
                return Err(de::Error::custom(format!("duplicate key {k:?}")));
            }
            let v = map.next_value_seed(Unique)?;
            out.insert(k, v);
        }
        Ok(Value::Object(out))
    }
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

    #[test]
    fn parse_refuses_repeated_keys_at_any_depth() {
        for bytes in [
            &br#"{"a":1,"a":2}"#[..],
            br#"{"a":1,"a":2}"#,
            br#"{"x":[{"k":1,"k":2}]}"#,
        ] {
            assert!(parse(bytes).is_err(), "{}", String::from_utf8_lossy(bytes));
        }
    }

    #[test]
    fn parse_matches_serde_json_when_no_key_repeats() {
        let mixed =
            r#"{"b":[1,2.5,-0,1e21,9007199254740993],"a":{"c":"ü 😀  ","d":null,"e":true}}"#;
        for bytes in [
            &b"{}"[..],
            b"[]",
            b"null",
            mixed.as_bytes(),
            br#"[[{"x":{}}]]"#,
        ] {
            assert_eq!(
                parse(bytes).unwrap(),
                serde_json::from_slice::<Value>(bytes).unwrap()
            );
        }
    }

    #[test]
    fn parse_keeps_serde_jsons_depth_limit() {
        let nested = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
        assert!(parse(nested(127).as_bytes()).is_ok());
        assert!(parse(nested(129).as_bytes()).is_err());
    }

    #[test]
    fn parse_refuses_trailing_bytes() {
        assert!(parse(b"{} {}").is_err());
    }

    #[test]
    fn inner_channel_digest_is_a_known_answer() {
        let digest = signing_digest(context::INNER_CHANNEL, &json!({"v": 1})).unwrap();
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "9d12562ab8a2fa23bbe004223823af162f68a9fef961cf45232f878cd2008afa"
        );
    }
}

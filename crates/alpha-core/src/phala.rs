use std::collections::BTreeMap;

use serde_json::Value;
use serde_json::ser::PrettyFormatter;

/// Phala Cloud's `dumpAppCompose`, the bytes its API writes into the CVM for a compose it
/// receives as a JSON object: keys sorted recursively, `JSON.stringify(obj, null, 4)`, then
/// every `": "` replaced by `":"` — also inside string values, which is why the replacement
/// runs over the finished text rather than being a formatter setting.
pub fn canonicalize(value: &Value) -> serde_json::Result<String> {
    let mut out = Vec::new();
    let mut ser =
        serde_json::Serializer::with_formatter(&mut out, PrettyFormatter::with_indent(b"    "));
    serde::Serialize::serialize(&sort_keys(value)?, &mut ser)?;
    Ok(String::from_utf8(out)
        .map_err(serde::ser::Error::custom)?
        .replace("\": ", "\":"))
}

// serde_json's map is only sorted without the `preserve_order` feature, which any crate in
// the workspace can switch on for everyone; the order must not depend on that.
fn sort_keys(value: &Value) -> serde_json::Result<Value> {
    match value {
        Value::Object(map) => map
            .iter()
            .map(|(key, value)| Ok((key.clone(), sort_keys(value)?)))
            .collect::<serde_json::Result<BTreeMap<_, _>>>()
            .map(|sorted| sorted.into_iter().collect()),
        Value::Array(items) => items.iter().map(sort_keys).collect(),
        // JSON.stringify prints fractions (`1.0` → `1`, `1e20` → `100000000000000000000`)
        // and magnitudes past 2^53 differently from serde_json; a compose has neither.
        Value::Number(n) => n
            .as_i64()
            .filter(|i| i.unsigned_abs() <= 1 << 53)
            .map(|_| value.clone())
            .ok_or_else(|| {
                serde::ser::Error::custom(format!(
                    "number {n} is not a safe integer; the provider's serializer would print it differently"
                ))
            }),
        other => Ok(other.clone()),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::json;

    use super::*;
    use crate::compose::compose_hash;

    fn read(path: &str) -> String {
        fs::read_to_string(
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/manifest/").to_owned() + path,
        )
        .unwrap()
    }

    #[test]
    fn reproduces_phala_bytes_and_hash() {
        let canonical = read("01-canonical/app-compose.json");
        let expected: Value = serde_json::from_str(&read("01-canonical/expected.json")).unwrap();
        for input in ["01-canonical/input.json", "04-trailing-newline/input.json"] {
            let value: Value = serde_json::from_str(&read(input)).unwrap();
            assert_eq!(canonicalize(&value).unwrap(), canonical, "{input}");
        }
        assert_eq!(
            compose_hash(&canonical).to_string(),
            expected["compose_hash"]
        );
    }

    #[test]
    fn replacement_also_rewrites_string_values_like_phala_does() {
        let value = json!({"b": "x\": y", "a": {"z": [], "y": {}}});
        assert_eq!(
            canonicalize(&value).unwrap(),
            "{\n    \"a\":{\n        \"y\":{},\n        \"z\":[]\n    },\n    \"b\":\"x\\\":y\"\n}"
        );
    }

    #[test]
    fn numbers_the_provider_would_print_differently_are_refused() {
        assert_eq!(
            canonicalize(&json!({"n": [1, -2, 9007199254740992i64]})).unwrap(),
            "{\n    \"n\":[\n        1,\n        -2,\n        9007199254740992\n    ]\n}"
        );
        for bad in [
            json!(1.0),
            json!(1e20),
            json!(-0.0),
            json!(9007199254740993i64),
            json!(u64::MAX),
        ] {
            assert!(canonicalize(&json!({"n": bad})).is_err(), "{bad}");
        }
    }
}

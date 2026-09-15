use std::collections::BTreeMap;

use serde_json::Value;

/// Phala Cloud's serialization of a compose: keys sorted recursively, no whitespace between
/// tokens (a running CVM's `tcb_info.app_compose` is this form and hashes to the API's
/// `compose_hash`; the SDK's indented `dumpAppCompose` is not). It adds and removes no fields,
/// so the result is what dstack measures only for a compose the API stores unchanged: one that
/// already spells out the fields the API fills in, has a `pre_launch_script` (without one the
/// API inserts its own) and has no `key_provider`, as `alpha_cli::deploy` builds it. For any other compose the API measures different bytes, which
/// the `compose_hash` comparison at provision time reports.
pub fn canonicalize(value: &Value) -> serde_json::Result<String> {
    serde_json::to_string(&sort_keys(value)?)
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
        // The provider's serializer is not ours, and serializers disagree on fractions
        // (`1.0`, `1e20`) and on magnitudes past 2^53; a compose has neither, so refuse
        // rather than guess how it would print them.
        Value::Number(n) => n
            .as_i64()
            .filter(|i| i.unsigned_abs() <= 1 << 53)
            .map(|_| value.clone())
            .ok_or_else(|| {
                serde::ser::Error::custom(format!(
                    "number {n} is not a safe integer; the provider's serializer could print it differently"
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
    fn sorted_compact_and_string_values_untouched() {
        let value = json!({"b": "x\": y", "a": {"z": [], "y": {}}});
        assert_eq!(
            canonicalize(&value).unwrap(),
            "{\"a\":{\"y\":{},\"z\":[]},\"b\":\"x\\\": y\"}"
        );
    }

    #[test]
    fn numbers_the_provider_could_print_differently_are_refused() {
        assert_eq!(
            canonicalize(&json!({"n": [1, -2, 9007199254740992i64]})).unwrap(),
            "{\"n\":[1,-2,9007199254740992]}"
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

use std::collections::BTreeMap;

use serde_json::Value;
use serde_json::ser::PrettyFormatter;

/// Phala Cloud's `dumpAppCompose`, the bytes its API writes into the CVM for a compose it
/// receives as a JSON object: keys sorted recursively, `JSON.stringify(obj, null, 4)`, then
/// every `": "` replaced by `":"` — also inside string values, which is why the replacement
/// runs over the finished text rather than being a formatter setting.
pub fn canonicalize(value: &Value) -> String {
    let mut out = Vec::new();
    let mut ser =
        serde_json::Serializer::with_formatter(&mut out, PrettyFormatter::with_indent(b"    "));
    serde::Serialize::serialize(&sort_keys(value), &mut ser)
        .expect("serializing a Value into a Vec cannot fail");
    String::from_utf8(out)
        .expect("serde_json emits UTF-8")
        .replace("\": ", "\":")
}

// serde_json's map is only sorted without the `preserve_order` feature, which any crate in
// the workspace can switch on for everyone; the order must not depend on that.
fn sort_keys(value: &Value) -> Value {
    match value {
        Value::Object(map) => map
            .iter()
            .map(|(key, value)| (key.clone(), sort_keys(value)))
            .collect::<BTreeMap<_, _>>()
            .into_iter()
            .collect(),
        Value::Array(items) => items.iter().map(sort_keys).collect(),
        other => other.clone(),
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
            assert_eq!(canonicalize(&value), canonical, "{input}");
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
            canonicalize(&value),
            "{\n    \"a\":{\n        \"y\":{},\n        \"z\":[]\n    },\n    \"b\":\"x\\\":y\"\n}"
        );
    }
}

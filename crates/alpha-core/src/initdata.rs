//! A Kata pod's init-data: the TOML a tenant signs as a Revision v2. Kata's shim hashes these
//! exact bytes into `MRCONFIGID`, not the base64-of-gzip annotation that carries them to the
//! host, so the host may re-encode the annotation without changing the Revision.

use serde::Deserialize;

use crate::{AppId, ComposeHash, KataPolicy, compose_hash};

#[derive(Debug)]
pub struct InitData(String);

#[derive(Debug, thiserror::Error)]
pub enum InitDataError {
    #[error("init-data is not TOML: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("init-data algorithm {0:?} is not \"sha256\"")]
    Algorithm(String),
    #[error("init-data version {0:?} is not \"0.1.0\"")]
    Version(String),
    #[error("init-data [data] has no \"policy.rego\" string")]
    NoPolicy,
    #[error("init-data [data] key {0:?} is neither \"app_id\" nor \"policy.rego\"")]
    UnknownKey(String),
    #[error("policy.rego has no \"\\npolicy_data := \"")]
    NoPolicyData,
    #[error("policy.rego rules are {0}, not the pinned rules")]
    Rules(ComposeHash),
    #[error("policy_data is not exactly one JSON value: {0}")]
    PolicyDataJson(serde_json::Error),
    #[error("policy_data is not an object with containers")]
    NoContainers,
    #[error("policy_data outside containers is {0}, not the pinned data")]
    PolicyData(ComposeHash),
}

const POLICY_DATA: &str = "\npolicy_data := ";

#[derive(Deserialize)]
struct Header {
    algorithm: String,
    version: String,
}

impl InitData {
    pub fn parse(toml: String) -> Result<Self, InitDataError> {
        let header: Header = toml::from_str(&toml)?;
        // sha256 alone makes the Revision digest the first half of MRCONFIGID. Kata's shim
        // dies on any other spelling (`SHA256`), and its agent refuses any other version.
        if header.algorithm != "sha256" {
            return Err(InitDataError::Algorithm(header.algorithm));
        }
        if header.version != "0.1.0" {
            return Err(InitDataError::Version(header.version));
        }
        Ok(Self(toml))
    }

    pub fn digest(&self) -> ComposeHash {
        compose_hash(&self.0)
    }

    /// The App the init-data names in `[data] app_id`, as a compose names it in `name`: the
    /// digest then belongs to one App, and no other can register the same bytes first.
    pub fn app_id(&self) -> Option<AppId> {
        #[derive(Deserialize)]
        struct Named {
            data: Data,
        }
        #[derive(Deserialize)]
        struct Data {
            app_id: String,
        }
        toml::from_str::<Named>(&self.0)
            .ok()?
            .data
            .app_id
            .parse()
            .ok()
    }

    /// `[data] "policy.rego"` is genpolicy's output: the rules file, `\npolicy_data := `, and a
    /// JSON object. The rules digest covers the bytes before the first separator, without it, so
    /// it is the SHA-256 of the rules file. The data digest covers the JCS of the object without
    /// `containers`, the only part that describes the pod; everything else, `ReadStreamRequest`
    /// included, decides what the agent allows. No rego is evaluated: any rego after the JSON
    /// would join the pinned rules, so nothing but whitespace may follow it.
    ///
    /// `[data]` holds nothing else: `aa.toml` or `cdh.toml` could point the guest at another key
    /// broker, and only alpha-kms releases keys.
    pub fn check_policy(&self, pinned: &KataPolicy) -> Result<(), InitDataError> {
        #[derive(Deserialize)]
        struct WithData {
            data: toml::Table,
        }
        let data = toml::from_str::<WithData>(&self.0)
            .map_err(|_| InitDataError::NoPolicy)?
            .data;
        if let Some(key) = data
            .keys()
            .find(|k| !matches!(k.as_str(), "app_id" | "policy.rego"))
        {
            return Err(InitDataError::UnknownKey(key.clone()));
        }
        let policy = data
            .get("policy.rego")
            .and_then(toml::Value::as_str)
            .ok_or(InitDataError::NoPolicy)?;
        let (rules, data) = policy
            .split_once(POLICY_DATA)
            .ok_or(InitDataError::NoPolicyData)?;
        let rules = compose_hash(rules);
        if rules != pinned.rules_sha256 {
            return Err(InitDataError::Rules(rules));
        }
        let mut data = crate::parse(data.as_bytes()).map_err(InitDataError::PolicyDataJson)?;
        data.as_object_mut()
            .and_then(|d| d.remove("containers"))
            .ok_or(InitDataError::NoContainers)?;
        let jcs = crate::jcs(&data).map_err(InitDataError::PolicyDataJson)?;
        let data = compose_hash(jcs);
        if data != pinned.data_sha256 {
            return Err(InitDataError::PolicyData(data));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T1: &str = include_str!("../../../testdata/attest/b300-kata-4.0.0/t1-sha256.toml");
    const K3: &str = include_str!("../../../testdata/attest/b300-kata-4.0.0/k3-app.toml");

    fn pinned() -> KataPolicy {
        let doc: serde_json::Value = serde_json::from_str(include_str!(
            "../../../testdata/attest/b300-kata-4.0.0/platform-document.json"
        ))
        .unwrap();
        serde_json::from_value(doc["kata_policy"].clone()).unwrap()
    }

    #[test]
    fn digest_is_sha256_of_the_signed_bytes() {
        let init_data = InitData::parse(T1.into()).unwrap();
        assert_eq!(
            init_data.digest().to_string(),
            "sha256:3e0edd232abd1af04a8d8db5ad17f6bd9a75a9643abcb25806b71bbe31d7020a"
        );
        let same_meaning = InitData::parse(T1.replace("\"note\"", "note")).unwrap();
        assert_ne!(same_meaning.digest(), init_data.digest());
    }

    #[test]
    fn app_id_is_read_from_data() {
        assert_eq!(
            InitData::parse(K3.into()).unwrap().app_id(),
            Some("0199e000-0000-7000-8000-00000000a11d".parse().unwrap())
        );
        assert_eq!(InitData::parse(T1.into()).unwrap().app_id(), None);
        let not_uuid = K3.replace("0199e000", "app");
        assert_eq!(InitData::parse(not_uuid).unwrap().app_id(), None);
    }

    #[test]
    fn refuses_what_kata_would_not_boot() {
        let cases = [
            (T1.replace("\"sha256\"", "\"SHA256\""), "algorithm"),
            (T1.replace("\"sha256\"", "\"sha384\""), "algorithm"),
            (T1.replace("\"0.1.0\"", "\"0.2.0\""), "version"),
            (T1.replace("algorithm = \"sha256\"\n", ""), "TOML"),
            (format!("algorithm = \"sha256\"\n{T1}"), "TOML"),
            ("not toml".into(), "TOML"),
        ];
        for (toml, fragment) in cases {
            let err = InitData::parse(toml.clone()).unwrap_err().to_string();
            assert!(err.contains(fragment), "{toml:?}: {err}");
        }
    }

    #[test]
    fn the_policy_genpolicy_generated_is_the_pinned_one() {
        InitData::parse(K3.into())
            .unwrap()
            .check_policy(&pinned())
            .unwrap();
    }

    #[test]
    fn a_policy_off_the_pins_is_refused() {
        let cases = [
            (
                K3.replace("\"policy.rego\"", "\"policy.txt\""),
                "\"policy.rego\"",
            ),
            (
                K3.replace("[data]\n", "[data]\n\"cdh.toml\" = \"\"\n"),
                "\"cdh.toml\" is neither",
            ),
            (
                K3.replace(POLICY_DATA, "\npolicy_data = "),
                "policy_data :=",
            ),
            (K3.replacen("(c) 2023", "(c) 2024", 1), "pinned rules"),
            // `ReadStreamRequest` is data, so the data pin alone keeps container output from
            // the host.
            (
                K3.replace(
                    "\"ReadStreamRequest\": false",
                    "\"ReadStreamRequest\": true",
                ),
                "pinned data",
            ),
            (
                K3.replace("}'''\n", "}\nExecProcessRequest if { true }'''\n"),
                "exactly one JSON value",
            ),
            (
                K3.replace(
                    "policy_data := {\n",
                    "policy_data := {\n  \"devices\": {},\n",
                ),
                "duplicate key",
            ),
            (
                K3.replace("\"containers\": [", "\"kontainers\": ["),
                "object with containers",
            ),
        ];
        for (toml, fragment) in cases {
            assert_ne!(toml, K3, "{fragment}");
            let err = InitData::parse(toml)
                .unwrap()
                .check_policy(&pinned())
                .unwrap_err()
                .to_string();
            assert!(err.contains(fragment), "{fragment}: {err}");
        }
    }
}

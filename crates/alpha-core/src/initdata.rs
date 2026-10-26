//! A Kata pod's init-data: the TOML a tenant signs as a Revision v2. Kata's shim hashes these
//! exact bytes into `MRCONFIGID`, not the base64-of-gzip annotation that carries them to the
//! host, so the host may re-encode the annotation without changing the Revision.

use serde::Deserialize;

use crate::{AppId, ComposeHash, KataPolicy, compose_hash};

#[derive(Debug)]
pub struct InitData(String);

#[derive(Debug, thiserror::Error)]
pub enum InitDataError {
    #[error("init-data is {MAX_INIT_DATA} bytes or more")]
    TooLarge,
    #[error("init-data is not TOML: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("init-data algorithm {0:?} is not \"sha256\"")]
    Algorithm(String),
    #[error("init-data version {0:?} is not \"0.1.0\"")]
    Version(String),
    #[error("init-data [data] has no \"policy.rego\" string")]
    NoPolicy,
    #[error(
        "init-data [data] key {0:?} is none of \"aa.toml\", \"app_id\", \"cdh.toml\", \"policy.rego\""
    )]
    UnknownKey(String),
    #[error(
        "init-data aa.toml and cdh.toml are not the platform's registry credential template: {0}"
    )]
    RegistryAuth(&'static str),
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
    #[error("policy_data lets the host exec {0} in a container; remove exec probes and exec hooks")]
    ExecCommands(serde_json::Value),
}

const POLICY_DATA: &str = "\npolicy_data := ";
/// The KMS Service in the cluster. Public CAs issue no name under `.svc`, and the guest also
/// trusts its built-in roots, so this name alone keeps the guest on our key broker.
const KBS_URL: &str = "https://kms.alpha-kms.svc:8443";
const CREDENTIAL_URI: &str = "kbs:///alpha/secret/";
/// The host writes the annotation that carries it, so a gzip bomb there must not exhaust a pod,
/// nor a page that reads it.
pub const MAX_INIT_DATA: usize = 1 << 20;

#[derive(Deserialize)]
struct Header {
    algorithm: String,
    version: String,
}

/// `aa.toml` and `cdh.toml` of a Revision whose images pull with the Secret `name`: the guest's
/// data hub gets the registry credential from the KMS at [`KBS_URL`], under `kms_ca_pem`. No
/// `[eventlog]`, so RTMR3 stays zero.
pub fn registry_auth(name: &str, kms_ca_pem: &str) -> (String, String) {
    (
        format!("[token_configs.kbs]\nurl = \"{KBS_URL}\"\ncert = \"\"\"{kms_ca_pem}\"\"\"\n"),
        format!(
            "[kbc]\nname = \"cc_kbc\"\nurl = \"{KBS_URL}\"\nkbs_cert = \"\"\"{kms_ca_pem}\"\"\"\n\n\
             [image]\nauthenticated_registry_credentials_uri = \"{CREDENTIAL_URI}{name}\"\n"
        ),
    )
}

impl InitData {
    pub fn parse(toml: String) -> Result<Self, InitDataError> {
        if toml.len() >= MAX_INIT_DATA {
            return Err(InitDataError::TooLarge);
        }
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
    /// `[data]` holds nothing else, except `aa.toml` and `cdh.toml` together and exactly as
    /// [`registry_auth`] renders them for one Secret name and `kms_ca_pem`: any other content could
    /// point the guest at another key broker, and only alpha-kms releases keys.
    ///
    /// No container may list `exec_commands`, the argv of its exec probes and hooks: the agent
    /// runs them whenever the host asks.
    pub fn check_policy(&self, pinned: &KataPolicy, kms_ca_pem: &str) -> Result<(), InitDataError> {
        let table = self.data()?;
        let (rules, data, containers) = policy(&table)?;
        check_registry_auth(&table, kms_ca_pem)?;
        if rules != pinned.rules_sha256 {
            return Err(InitDataError::Rules(rules));
        }
        let jcs = crate::jcs(&data).map_err(InitDataError::PolicyDataJson)?;
        let data = compose_hash(jcs);
        if data != pinned.data_sha256 {
            return Err(InitDataError::PolicyData(data));
        }
        for container in containers.as_array().ok_or(InitDataError::NoContainers)? {
            match container.get("exec_commands") {
                None | Some(serde_json::Value::Null) => {}
                Some(serde_json::Value::Array(commands)) if commands.is_empty() => {}
                Some(commands) => return Err(InitDataError::ExecCommands(commands.clone())),
            }
        }
        Ok(())
    }

    fn data(&self) -> Result<toml::Table, InitDataError> {
        #[derive(Deserialize)]
        struct WithData {
            data: toml::Table,
        }
        Ok(toml::from_str::<WithData>(&self.0)
            .map_err(|_| InitDataError::NoPolicy)?
            .data)
    }

    /// The policy data's `containers`, genpolicy's description of each container the agent lets
    /// the pod create. The pins are not checked: that is [`Self::check_policy`]'s job.
    pub fn containers(&self) -> Result<serde_json::Value, InitDataError> {
        Ok(policy(&self.data()?)?.2)
    }
}

fn credential_name(data: &toml::Table) -> Option<String> {
    let cdh = data
        .get("cdh.toml")?
        .as_str()?
        .parse::<toml::Table>()
        .ok()?;
    let uri = cdh
        .get("image")?
        .get("authenticated_registry_credentials_uri")?;
    Some(uri.as_str()?.strip_prefix(CREDENTIAL_URI)?.to_owned())
}

fn check_registry_auth(data: &toml::Table, kms_ca_pem: &str) -> Result<(), InitDataError> {
    if !data.contains_key("aa.toml") && !data.contains_key("cdh.toml") {
        return Ok(());
    }
    let name =
        credential_name(data).ok_or(InitDataError::RegistryAuth("cdh.toml names no Secret"))?;
    if !crate::is_secret_name(&name) {
        return Err(InitDataError::RegistryAuth("the Secret name is not valid"));
    }
    let (want_aa, want_cdh) = registry_auth(&name, kms_ca_pem);
    if data.get("aa.toml") != Some(&toml::Value::String(want_aa))
        || data.get("cdh.toml") != Some(&toml::Value::String(want_cdh))
    {
        return Err(InitDataError::RegistryAuth("they differ"));
    }
    Ok(())
}

/// The rules digest, the policy data without `containers`, and `containers`.
fn policy(
    data: &toml::Table,
) -> Result<(ComposeHash, serde_json::Value, serde_json::Value), InitDataError> {
    if let Some(key) = data.keys().find(|k| {
        !matches!(
            k.as_str(),
            "aa.toml" | "app_id" | "cdh.toml" | "policy.rego"
        )
    }) {
        return Err(InitDataError::UnknownKey(key.clone()));
    }
    let policy = data
        .get("policy.rego")
        .and_then(toml::Value::as_str)
        .ok_or(InitDataError::NoPolicy)?;
    let (rules, data) = policy
        .split_once(POLICY_DATA)
        .ok_or(InitDataError::NoPolicyData)?;
    let mut data = crate::parse(data.as_bytes()).map_err(InitDataError::PolicyDataJson)?;
    let containers = data
        .as_object_mut()
        .and_then(|d| d.remove("containers"))
        .ok_or(InitDataError::NoContainers)?;
    Ok((compose_hash(rules), data, containers))
}

#[cfg(test)]
mod tests {
    use super::*;

    const T1: &str = include_str!("../../../testdata/attest/b300-kata-4.0.0/t1-sha256.toml");
    const K3: &str = include_str!("../../../testdata/attest/b300-kata-4.0.0/k3-app.toml");

    const PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

    fn with_auth(aa: &str, cdh: &str) -> String {
        K3.replace(
            "[data]\n",
            &format!("[data]\n\"aa.toml\" = '''\n{aa}'''\n\"cdh.toml\" = '''\n{cdh}'''\n"),
        )
    }

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
            (" ".repeat(MAX_INIT_DATA), "bytes or more"),
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
            .check_policy(&pinned(), PEM)
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
                K3.replace("[data]\n", "[data]\n\"kbs.toml\" = \"\"\n"),
                "\"kbs.toml\" is none of",
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
            (
                K3.replacen("\"exec_commands\": []", "\"exec_commands\": [[\"sh\"]]", 1),
                "exec [[\"sh\"]]",
            ),
        ];
        for (toml, fragment) in cases {
            assert_ne!(toml, K3, "{fragment}");
            let err = InitData::parse(toml)
                .unwrap()
                .check_policy(&pinned(), PEM)
                .unwrap_err()
                .to_string();
            assert!(err.contains(fragment), "{fragment}: {err}");
        }
    }

    #[test]
    fn the_registry_auth_template_is_what_the_guest_reads() {
        let (aa, cdh) = registry_auth("regcred", PEM);
        assert_eq!(
            aa,
            "[token_configs.kbs]\nurl = \"https://kms.alpha-kms.svc:8443\"\ncert = \"\"\"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n\"\"\"\n"
        );
        assert_eq!(
            cdh,
            "[kbc]\nname = \"cc_kbc\"\nurl = \"https://kms.alpha-kms.svc:8443\"\nkbs_cert = \"\"\"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n\"\"\"\n\n[image]\nauthenticated_registry_credentials_uri = \"kbs:///alpha/secret/regcred\"\n"
        );
        let table: toml::Table = cdh.parse().unwrap();
        assert_eq!(table["kbc"]["kbs_cert"].as_str(), Some(PEM));

        let init_data = InitData::parse(with_auth(&aa, &cdh)).unwrap();
        init_data.check_policy(&pinned(), PEM).unwrap();
    }

    #[test]
    fn registry_auth_off_the_template_is_refused() {
        let (aa, cdh) = registry_auth("regcred", PEM);
        let (other_ca, _) = registry_auth("regcred", "-----BEGIN CERTIFICATE-----\nMIIC\n");
        let (_, bad_name) = registry_auth("RegCred", PEM);
        let cases = [
            (
                with_auth(&aa, &cdh.replace("https://kms", "http://kms")),
                "they differ",
            ),
            (
                with_auth(&aa.replace("kms.alpha-kms.svc", "kbs.example.com"), &cdh),
                "they differ",
            ),
            (with_auth(&other_ca, &cdh), "they differ"),
            (
                with_auth(&format!("{aa}[eventlog]\nenable_eventlog = true\n"), &cdh),
                "they differ",
            ),
            (
                with_auth(
                    &aa,
                    &format!("{cdh}image_security_policy_uri = \"kbs:///alpha/secret/p\"\n"),
                ),
                "they differ",
            ),
            (
                with_auth(&aa, &cdh.replace("alpha/secret/", "default/credential/")),
                "names no Secret",
            ),
            (with_auth(&aa, &bad_name), "not valid"),
            (
                K3.replace(
                    "[data]\n",
                    &format!("[data]\n\"cdh.toml\" = '''\n{cdh}'''\n"),
                ),
                "they differ",
            ),
        ];
        for (toml, fragment) in cases {
            let err = InitData::parse(toml)
                .unwrap()
                .check_policy(&pinned(), PEM)
                .unwrap_err()
                .to_string();
            assert!(err.contains(fragment), "{fragment}: {err}");
        }
    }
}

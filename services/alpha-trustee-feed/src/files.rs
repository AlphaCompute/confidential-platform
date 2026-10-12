//! What the feed writes for the pod's three Trustee containers before they start, into the
//! pod's in-guest `emptyDir`: their configuration (none of it from a ConfigMap, which the host
//! writes), the KBS admin API's public key, and the Attestation Service's token-signing key and
//! certificate.
//!
//! Every listener is on the TD's loopback: the KBS on `127.0.0.1:8080` without TLS (the feed's
//! gate terminates TLS in front of it), the Attestation Service on `127.0.0.1:50004`, the RVPS on
//! `127.0.0.1:50003`, and the feed's resource backend on `127.0.0.1:8200`. No other pod reaches
//! any of them, whatever the cluster network does.

use std::path::{Path, PathBuf};

use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer;
use p256::pkcs8::EncodePrivateKey;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256, PublicKeyData, SerialNumber, SignatureAlgorithm,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::Error;

pub const KBS_ADDR: &str = "127.0.0.1:8080";
pub const AS_ADDR: &str = "127.0.0.1:50004";
pub const RVPS_ADDR: &str = "127.0.0.1:50003";
pub const VAULT_ADDR: &str = "127.0.0.1:8200";

/// The KBS admin API's only identity: the feed, with a key generated in the TD at start.
pub const ADMIN_ISSUER: &str = "alpha-trustee-feed";
pub const ADMIN_AUDIENCE: &str = "kbs-admin";
pub const ADMIN_ROLE: &str = "alpha-trustee-feed";
/// The admin endpoints the feed may call; resource writes are not among them.
pub const ADMIN_ENDPOINTS: &str = "^/kbs/v0/(resource-policy|attestation-policy|reference-value)$";

/// The Trustee App's derived key the Attestation Service signs tokens with: the same in every
/// Trustee pod, so a token one replica's KBS issued verifies at the other's, and the one alpha-kms
/// verifies every token the feed reports under.
pub use alpha_trustee::ear::AS_TOKEN_PURPOSE;
/// Attestation tokens live five minutes (Trustee's default).
pub const AS_TOKEN_MINUTES: u32 = 5;

/// The files, under the pod's shared in-guest directory.
#[derive(Clone, Debug)]
pub struct Paths {
    dir: PathBuf,
}

impl Paths {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn kbs_config(&self) -> PathBuf {
        self.dir.join("kbs-config.toml")
    }

    pub fn as_config(&self) -> PathBuf {
        self.dir.join("as-config.json")
    }

    pub fn rvps_config(&self) -> PathBuf {
        self.dir.join("rvps.json")
    }

    pub fn admin_public(&self) -> PathBuf {
        self.dir.join("admin.pem")
    }

    pub fn as_key(&self) -> PathBuf {
        self.dir.join("as-token.key")
    }

    pub fn as_cert(&self) -> PathBuf {
        self.dir.join("as-token.crt")
    }
}

fn quoted(path: &Path) -> String {
    json!(path.to_string_lossy()).to_string()
}

/// The KBS's configuration (`kbs/docs/config.md`): HTTP on loopback; attestation by the
/// Attestation Service on loopback; tokens trusted only under the AS's certificate; the admin API
/// to the feed's key alone, for the three endpoints it installs through; resources only from the
/// feed's Vault KV v1 endpoint (`kbs/src/plugins/implementations/resource/vault_kv.rs`), which
/// answers with a value the KMS released for the request in flight and nothing else.
pub fn kbs_config(paths: &Paths, vault_token: &str) -> String {
    format!(
        r#"[http_server]
sockets = ["{KBS_ADDR}"]
insecure_http = true

[attestation_token]
trusted_certs_paths = [{cert}]

[attestation_service]
type = "coco_as_grpc"
as_addr = "http://{AS_ADDR}"

[admin]
authorization_mode = "AuthenticatedAuthorization"

[admin.authentication.bearer_jwt]
identity_providers = [{{ issuer = "{ADMIN_ISSUER}", audience = "{ADMIN_AUDIENCE}", public_key_uri = {admin} }}]

[admin.authorization.regex_acl]
acls = [{{ role = "{ADMIN_ROLE}", allowed_endpoints = {endpoints} }}]

[[plugins]]
name = "resource"
storage_backend_type = "Vault"
vault_url = "http://{VAULT_ADDR}"
token = {token}
mount_path = "{mount}"
"#,
        cert = quoted(&paths.as_cert()),
        admin = quoted(&paths.admin_public()),
        endpoints = json!(ADMIN_ENDPOINTS),
        token = json!(vault_token),
        mount = alpha_trustee::vault::MOUNT,
    )
}

/// The Attestation Service's configuration (`attestation-service/docs/config.md`): the RVPS on
/// loopback, tokens signed with the Trustee App's derived key, DCAP collateral from the site PCCS,
/// GPUs verified by NRAS (D1) at the URL the platform document names.
pub fn as_config(paths: &Paths, pccs_url: &str, nras_verifier_url: &str) -> String {
    json!({
        "rvps_config": { "type": "GrpcRemote", "address": format!("http://{RVPS_ADDR}") },
        "attestation_token_broker": {
            "duration_min": AS_TOKEN_MINUTES,
            "verbose_token": false,
            "signer": {
                "key_path": paths.as_key().to_string_lossy(),
                "cert_path": paths.as_cert().to_string_lossy(),
            },
        },
        "verifier_config": {
            // ponytail: G0 — that the AS image reaches the site PCCS and verifies its TLS
            // certificate; until then collateral fetches fail and no TD is affirming.
            "dcap_verifier": { "collateral_service": pccs_url },
            "nvidia_verifier": { "type": "Remote", "verifier_url": nras_verifier_url },
        },
    })
    .to_string()
}

/// The RVPS keeps its reference values in memory; the feed registers them again on every sync.
pub fn rvps_config() -> String {
    json!({ "storage": { "storage_type": "Memory" } }).to_string()
}

/// The token-signing key from the 32 bytes the KMS derives for [`AS_TOKEN_PURPOSE`].
pub fn as_signing_key(derived: &[u8; 32]) -> Result<SigningKey, Error> {
    alpha_trustee::ear::token_signing_key(derived).map_err(Error::Key)
}

/// [`SigningKey`] as rcgen signs with it: RFC 6979, so the certificate below is the same bytes in
/// every Trustee pod.
struct Deterministic {
    key: SigningKey,
    public: Vec<u8>,
}

impl PublicKeyData for Deterministic {
    fn der_bytes(&self) -> &[u8] {
        &self.public
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ECDSA_P256_SHA256
    }
}

impl rcgen::SigningKey for Deterministic {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let signature: p256::ecdsa::Signature = self.key.sign(msg);
        Ok(signature.to_der().as_bytes().to_vec())
    }
}

/// The self-signed certificate of the token-signing key, which the AS puts in each token's header
/// and the KBS trusts: a function of the key alone.
pub fn as_certificate(key: &SigningKey) -> Result<Vec<u8>, Error> {
    let public = key.verifying_key().to_sec1_point(false).as_bytes().to_vec();
    let digest = Sha256::digest(&public);
    let mut serial = digest.get(..16).unwrap_or_default().to_vec();
    if let Some(first) = serial.first_mut() {
        *first &= 0x7f;
    }
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "alpha-trustee attestation token signer");
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
    ];
    params.not_before = rcgen::date_time_ymd(2026, 1, 1);
    params.not_after = rcgen::date_time_ymd(2046, 1, 1);
    params.serial_number = Some(SerialNumber::from(serial));
    let signer = Deterministic {
        key: key.clone(),
        public,
    };
    Ok(params
        .self_signed(&signer)
        .map_err(|e| Error::Key(format!("attestation token certificate: {e}")))?
        .der()
        .to_vec())
}

/// Everything above, written for the containers to start with.
pub fn write_all(
    paths: &Paths,
    vault_token: &str,
    admin_public_pem: &str,
    as_key: &SigningKey,
    pccs_url: &str,
    nras_verifier_url: &str,
) -> Result<(), Error> {
    let io =
        |path: PathBuf| move |e: std::io::Error| Error::Files(format!("{}: {e}", path.display()));
    std::fs::create_dir_all(paths.dir()).map_err(io(paths.dir().to_owned()))?;
    let key_der = Zeroizing::new(
        as_key
            .to_pkcs8_der()
            .map_err(|e| Error::Key(format!("attestation token key: {e}")))?
            .as_bytes()
            .to_vec(),
    );
    let key_pem = Zeroizing::new(pem::encode(&pem::Pem::new("PRIVATE KEY", key_der.to_vec())));
    let cert_pem = pem::encode(&pem::Pem::new("CERTIFICATE", as_certificate(as_key)?));
    for (path, text) in [
        (paths.as_key(), key_pem.as_str()),
        (paths.as_cert(), cert_pem.as_str()),
        (paths.admin_public(), admin_public_pem),
        (paths.rvps_config(), rvps_config().as_str()),
        (
            paths.as_config(),
            as_config(paths, pccs_url, nras_verifier_url).as_str(),
        ),
        // Last: the KBS's configuration names the files above.
        (paths.kbs_config(), kbs_config(paths, vault_token).as_str()),
    ] {
        std::fs::write(&path, text).map_err(io(path.clone()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    #[test]
    fn the_kbs_listens_on_loopback_and_reads_resources_only_from_the_feed() {
        let paths = Paths::new("/run/trustee");
        let toml = kbs_config(&paths, "t0ken");
        assert!(toml.contains("sockets = [\"127.0.0.1:8080\"]"));
        assert!(toml.contains("trusted_certs_paths = [\"/run/trustee/as-token.crt\"]"));
        assert!(toml.contains("as_addr = \"http://127.0.0.1:50004\""));
        assert!(toml.contains("authorization_mode = \"AuthenticatedAuthorization\""));
        assert!(toml.contains("public_key_uri = \"/run/trustee/admin.pem\""));
        assert!(toml.contains(
            "allowed_endpoints = \"^/kbs/v0/(resource-policy|attestation-policy|reference-value)$\""
        ));
        assert!(toml.contains("storage_backend_type = \"Vault\""));
        assert!(toml.contains("vault_url = \"http://127.0.0.1:8200\""));
        assert!(toml.contains("token = \"t0ken\""));
        assert!(toml.contains("mount_path = \"alpha\""));
        assert!(!toml.contains("0.0.0.0"));
        assert!(!toml.contains("insecure_header_jwk"));
        assert!(!toml.contains("InsecureAllowAll"));
    }

    #[test]
    fn the_attestation_service_signs_with_the_derived_key_and_asks_nras_and_the_pccs() {
        let paths = Paths::new("/run/trustee");
        let config: Value = serde_json::from_str(&as_config(
            &paths,
            "https://pccs.site1.alphacompute.internal:8081/sgx/certification/v4/",
            "https://nras.attestation.nvidia.com/v4/attest",
        ))
        .unwrap();
        assert_eq!(config["rvps_config"]["address"], "http://127.0.0.1:50003");
        assert_eq!(
            config["attestation_token_broker"]["signer"]["key_path"],
            "/run/trustee/as-token.key"
        );
        assert_eq!(config["attestation_token_broker"]["duration_min"], 5);
        assert_eq!(
            config["verifier_config"]["nvidia_verifier"],
            serde_json::json!({ "type": "Remote", "verifier_url": "https://nras.attestation.nvidia.com/v4/attest" })
        );
        assert_eq!(
            config["verifier_config"]["dcap_verifier"]["collateral_service"],
            "https://pccs.site1.alphacompute.internal:8081/sgx/certification/v4/"
        );
    }

    #[test]
    fn every_pod_derives_the_same_signing_certificate() {
        let key = as_signing_key(&[5; 32]).unwrap();
        let cert = as_certificate(&key).unwrap();
        assert_eq!(
            cert,
            as_certificate(&as_signing_key(&[5; 32]).unwrap()).unwrap()
        );
        assert_ne!(
            cert,
            as_certificate(&as_signing_key(&[6; 32]).unwrap()).unwrap()
        );
        let spki = p256::pkcs8::EncodePublicKey::to_public_key_der(key.verifying_key()).unwrap();
        let spki = spki.as_bytes();
        assert!(
            cert.windows(spki.len()).any(|w| w == spki),
            "the certificate is over the key"
        );
        assert!(as_signing_key(&[0; 32]).is_err());
    }

    #[test]
    fn everything_lands_in_the_shared_directory() {
        let dir = std::env::temp_dir().join(format!("alpha-trustee-feed-{}", std::process::id()));
        let paths = Paths::new(&dir);
        let key = as_signing_key(&[5; 32]).unwrap();
        write_all(
            &paths,
            "t",
            "PUBLIC",
            &key,
            "https://pccs.example/",
            "https://nras.example/v4/attest",
        )
        .unwrap();
        for p in [
            paths.kbs_config(),
            paths.as_config(),
            paths.rvps_config(),
            paths.admin_public(),
            paths.as_key(),
            paths.as_cert(),
        ] {
            assert!(p.is_file(), "{}", p.display());
        }
        let key_pem = std::fs::read_to_string(paths.as_key()).unwrap();
        assert!(key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        std::fs::remove_dir_all(dir).unwrap();
    }
}

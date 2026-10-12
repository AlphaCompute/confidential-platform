//! D10 (draft): how a KMS node authenticates to the trust-zone Postgres without a password.
//!
//! A Kata KMS node cannot carry a database password: `GET /v1/node/evidence` serves its init-data,
//! and with it every measured env value, to anyone (#87). The proposal (D10 option (a), designed
//! together with M2(a)) is mutual TLS under a **database client CA that only an attested KMS node
//! or the attested Postgres pod can hold**:
//!
//! - The CA's P-256 key is derived (HKDF-SHA256) from the `db-volume` intermediate (#103). That key
//!   exists, before the database opens, only in a node the custodians unsealed (the share files
//!   carry it wrapped under the root KEK), a node that joined (the join reply carries it), a node
//!   that ran genesis, and the Postgres pod `POST /v1/node/db-key` appraised. Each of those
//!   parties was attested before it got it, so "holds the CA" means "was attested".
//! - Each node issues **itself** a short-lived client leaf from that CA: a fresh P-256 key that
//!   never leaves the node's memory, CN `kms-node-<first 16 hex of its runtime SPKI digest>` (so
//!   Postgres's connection log names the node), and the URI SAN
//!   `alphacompute://kms-db-client/<runtime SPKI digest>`.
//! - Postgres runs `hostssl … cert clientcert=verify-full map=alpha-kms` with `ssl_ca_file` = this
//!   CA's certificate, and `pg_ident.conf` maps `/^kms-node-[0-9a-f]{16}$` to the `alpha_kms_node`
//!   login role, a member of the migration's `alpha_kms` (`docs/db-client-auth.md`). The node pins Postgres's server certificate to the same CA
//!   (`sslmode=verify-full`), so it never sends a query to a database that is not the attested pod.
//!
//! Nothing here touches what a node may read: the rows are sealed under the KMS intermediates
//! either way (#95). This decides who may connect.
//!
//! QUESTION(PRD-05 Q44): which CA issues the Postgres client certificate. Proposed: this derived
//! CA, not the KMS CA. The KMS CA's key is in `intermediate_keys`, inside the very database it
//! would let the node into, so a cold-starting node cannot use it (M4 keeps it there); it would
//! also make every KMS-CA leaf (tenant Instances included) a candidate client, filtered only by
//! the CN map. The derived CA exists before the database does and only TEEs hold it.
//!
//! QUESTION(PRD-05 Q47): does Postgres verify the KMS's attestation or trust the CA? Proposed:
//! trust the CA. Stock Postgres cannot appraise TDX evidence; possession of the CA key is
//! the attestation proxy (see above). A custom auth hook or an attesting proxy in the Postgres
//! pod is possible later.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use hkdf::Hkdf;
use p256::pkcs8::EncodePrivateKey;
use parking_lot::Mutex;
use rcgen::string::Ia5String;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PublicKeyData, SanType,
};
use sha2::{Digest, Sha256};
use sqlx::postgres::{PgConnectOptions, PgSslMode};
use zeroize::Zeroizing;

use crate::error::ApiError;
use crate::{Node, later};

/// The env variable choosing how the node authenticates to Postgres.
pub const MODE_ENV: &str = "ALPHACOMPUTE_DATABASE_AUTH";
/// The Postgres login role every KMS node's certificate maps to. It is a member of the `alpha_kms`
/// group role the migration creates (`nologin`), so it has exactly the grants the KMS has today.
pub const ROLE: &str = "alpha_kms_node";
/// The `pg_ident.conf` map name `docs/db-client-auth.md` uses.
pub const IDENT_MAP: &str = "alpha-kms";
/// How long a node's client leaf lives. A connection outlives its certificate (TLS checks it at
/// the handshake only), so this bounds how long a node that lost its keys can open *new* ones.
pub const CLIENT_TTL: Duration = Duration::from_secs(3600);
/// A leaf with less than this left is replaced on the next tick or wait-loop pass.
const RENEW_BEFORE: Duration = Duration::from_secs(1800);
/// HKDF salt; the info strings below separate the CA key from its serial.
const SALT: &[u8] = b"alphacompute-kms/db-client-ca/v1";
/// URI SAN prefix of a node's client leaf.
pub const CLIENT_SAN_PREFIX: &str = "alphacompute://kms-db-client/";

/// `pg_hba.conf` for the trust-zone Postgres pod: only TLS, only the [`ROLE`] login, only by a
/// certificate from the derived CA mapped through [`PG_IDENT`]. The `local` line is the pod's
/// own socket (initdb and the entrypoint), which the TD's agent policy keeps exec-free.
///
/// QUESTION(PRD-05 Q50): restrict the address to the verifier pool's pod CIDR? Proposed: yes once
/// PRD-01 names it; the certificate is the control, the CIDR only narrows noise.
pub const PG_HBA: &str = "\
# D10 (draft): alpha-kms nodes by client certificate only (docs/db-client-auth.md).
local   all  all                    trust
hostssl all  alpha_kms_node  0.0.0.0/0   cert  clientcert=verify-full  map=alpha-kms
hostssl all  alpha_kms_node  ::/0        cert  clientcert=verify-full  map=alpha-kms
";

/// `pg_ident.conf`: every node CN [`node_cn`] makes maps to [`ROLE`], and nothing else does.
pub const PG_IDENT: &str = "\
# MAPNAME  SYSTEM-USERNAME              PG-USERNAME
alpha-kms  /^kms-node-[0-9a-f]{16}$     alpha_kms_node
";

/// How the node authenticates to Postgres.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// `ALPHACOMPUTE_DATABASE_URL` as given: the prototype nodes' password in their encrypted,
    /// unmeasured env. On a Kata node only a URL without a password is accepted (see [`check_url`]).
    Url,
    /// D10 (a): a client leaf from the derived CA, `sslmode=verify-full` against the same CA.
    ClientCert,
}

/// `ALPHACOMPUTE_DATABASE_AUTH`: unset or `url`, or `client-cert`.
pub fn mode(value: Option<&str>) -> Result<Mode, String> {
    match value.map(str::trim) {
        None | Some("") | Some("url") => Ok(Mode::Url),
        Some("client-cert") => Ok(Mode::ClientCert),
        Some(other) => Err(format!(
            "{MODE_ENV}={other:?}: expected \"url\" or \"client-cert\""
        )),
    }
}

/// Refuses a database URL the mode cannot use safely.
///
/// - Any mode on a Kata node (`kata`): no password. The node's measured env is public (#87).
/// - `client-cert`: no password at all, and no `sslmode` other than `verify-full`: the mode
///   sets TLS itself and a URL must not weaken it. The user, if named, must be [`ROLE`].
///
/// QUESTION(PRD-05 Q48): should a Kata node refuse `url` mode outright? Proposed: not yet. During
/// the migration a Kata node may need to connect before D10 lands (network-granted `trust` on a
/// Postgres only the verifier pool reaches, accepted as a gap since the rows are sealed). Once
/// D10 is decided, `url` mode on a Kata node should be refused.
pub fn check_url(url: &str, mode: Mode, kata: bool) -> Result<(), String> {
    if (kata || mode == Mode::ClientCert) && has_password(url) {
        return Err(
            "ALPHACOMPUTE_DATABASE_URL carries a password, which a Kata node's evidence endpoint \
             would publish (D10); use ALPHACOMPUTE_DATABASE_AUTH=client-cert"
                .into(),
        );
    }
    if mode == Mode::ClientCert {
        if let Some(sslmode) = query_param(url, "sslmode")
            && sslmode != "verify-full"
        {
            return Err(format!(
                "sslmode={sslmode}: client-cert mode verifies the server with verify-full only"
            ));
        }
        for name in ["sslcert", "sslkey", "sslrootcert"] {
            if query_param(url, name).is_some() {
                return Err(format!(
                    "{name}: client-cert mode sets the certificates itself, from the db-volume key"
                ));
            }
        }
        if let Some(user) = user(url)
            && user != ROLE
        {
            return Err(format!(
                "user {user:?}: a KMS node's certificate maps to the role {ROLE}"
            ));
        }
    }
    Ok(())
}

fn authority(url: &str) -> Option<&str> {
    let rest = url.split_once("://")?.1;
    Some(rest.split(['/', '?']).next().unwrap_or(rest))
}

fn userinfo(url: &str) -> Option<&str> {
    authority(url)?.rsplit_once('@').map(|(info, _)| info)
}

fn user(url: &str) -> Option<&str> {
    let info = userinfo(url)?;
    Some(info.split(':').next().unwrap_or(info)).filter(|u| !u.is_empty())
}

fn query_param<'a>(url: &'a str, name: &str) -> Option<&'a str> {
    url.split_once('?')?
        .1
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

fn has_password(url: &str) -> bool {
    userinfo(url).is_some_and(|info| info.contains(':')) || query_param(url, "password").is_some()
}

fn hkdf(db_volume: &[u8; 32], info: &[u8]) -> Result<Zeroizing<[u8; 32]>, ApiError> {
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(SALT), db_volume)
        .expand(info, out.as_mut())
        .map_err(|e| ApiError::internal(format!("hkdf: {e}")))?;
    Ok(out)
}

/// The client CA: its key pair, derived from the `db-volume` key, and a self-signed certificate.
///
/// The key is a function of the volume key alone, so every node and the Postgres pod arrive at
/// the same CA without storing it anywhere, and it survives custodian rotations (the volume key's
/// value never changes, #102/#103). The certificate's validity and serial are fixed too, so the
/// certificate is the same apart from its ECDSA signature; Postgres and rustls match a trust
/// anchor by subject and key, so any node's copy serves as `ssl_ca_file`.
pub struct ClientCa {
    pub key: KeyPair,
    pub cert_der: Vec<u8>,
}

impl ClientCa {
    pub fn derive(db_volume: &[u8; 32]) -> Result<Self, ApiError> {
        // A 32-byte HKDF output is a valid P-256 scalar except with probability ~2^-128; try a
        // few counters rather than fail on it.
        let mut secret = None;
        for counter in 0u8..4 {
            let seed = hkdf(db_volume, &[b"ca-key-".as_slice(), &[counter]].concat())?;
            if let Ok(s) = p256::SecretKey::from_slice(seed.as_slice()) {
                secret = Some(s);
                break;
            }
        }
        let secret = secret.ok_or_else(|| ApiError::internal("db client CA: no scalar"))?;
        let pkcs8 = Zeroizing::new(
            secret
                .to_pkcs8_der()
                .map_err(|e| ApiError::internal(format!("db client CA: {e}")))?
                .as_bytes()
                .to_vec(),
        );
        let key = crate::certs::key_pair(&pkcs8)?;
        let serial = hkdf(db_volume, b"ca-serial")?;
        let mut serial = serial.get(..16).unwrap_or_default().to_vec();
        if let Some(first) = serial.first_mut() {
            *first &= 0x7f;
        }
        let mut params = CertificateParams::default();
        params.distinguished_name = subject("alpha-kms db client CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.not_before = rcgen::date_time_ymd(2026, 1, 1);
        params.not_after = rcgen::date_time_ymd(2046, 1, 1);
        params.serial_number = Some(rcgen::SerialNumber::from(serial));
        let cert_der = params
            .self_signed(&key)
            .map_err(|e| ApiError::internal(format!("db client CA certificate: {e}")))?
            .der()
            .to_vec();
        Ok(Self { key, cert_der })
    }

    pub fn cert_pem(&self) -> String {
        crate::certs::pem(&self.cert_der)
    }

    /// The SHA-256 of the CA's SubjectPublicKeyInfo, for comparing CAs across nodes and with the
    /// Postgres pod's `ssl_ca_file` without the signature getting in the way.
    pub fn spki_sha256(&self) -> String {
        hex::encode(Sha256::digest(self.key.subject_public_key_info()))
    }
}

fn subject(cn: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    dn
}

/// The CN a node's leaf carries and `pg_ident.conf` maps to [`ROLE`].
pub fn node_cn(runtime_spki: &[u8]) -> String {
    let digest = hex::encode(Sha256::digest(runtime_spki));
    format!("kms-node-{}", digest.get(..16).unwrap_or(&digest))
}

/// A node's client leaf.
pub struct ClientLeaf {
    pub cert_der: Vec<u8>,
    pub key_pkcs8: Zeroizing<Vec<u8>>,
    pub not_after: SystemTime,
}

/// A fresh P-256 key and a [`CLIENT_TTL`] leaf over it from `ca`, naming the node.
pub fn issue_client(
    ca: &ClientCa,
    runtime_spki: &[u8],
    now: SystemTime,
) -> Result<ClientLeaf, ApiError> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|e| ApiError::internal(format!("db client key: {e}")))?;
    let issuer = Issuer::from_ca_cert_der(&ca.cert_der.as_slice().into(), &ca.key)
        .map_err(|e| ApiError::internal(format!("db client CA certificate: {e}")))?;
    let not_after = later(now, CLIENT_TTL)?;
    let mut params = CertificateParams::default();
    params.distinguished_name = subject(&node_cn(runtime_spki));
    params.subject_alt_names = vec![SanType::URI(
        Ia5String::try_from(format!(
            "{CLIENT_SAN_PREFIX}{}",
            hex::encode(Sha256::digest(runtime_spki))
        ))
        .map_err(|e| ApiError::internal(format!("san: {e}")))?,
    )];
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.use_authority_key_identifier_extension = true;
    params.not_before = now.into();
    params.not_after = not_after.into();
    let serial = crate::random::<16>()?;
    let mut serial = serial.to_vec();
    if let Some(first) = serial.first_mut() {
        *first &= 0x7f;
    }
    params.serial_number = Some(rcgen::SerialNumber::from(serial));
    let cert_der = params
        .signed_by(&key, &issuer)
        .map_err(|e| ApiError::internal(format!("db client leaf: {e}")))?
        .der()
        .to_vec();
    Ok(ClientLeaf {
        cert_der,
        key_pkcs8: Zeroizing::new(key.serialize_der()),
        not_after,
    })
}

/// The Postgres pod's server certificate from the same CA, for `host_names` (the Service's DNS
/// names the KMS's URL uses), over a fresh key. The pod can derive the CA because it holds the
/// volume key (#103), so the KMS's `sslmode=verify-full` pins the server to a party that was
/// attested as a listed `db_revisions` build.
///
/// TODO(draft): nothing calls this outside tests yet. `alpha-volume open-db` (the Postgres pod's
/// init container, PRD-05 draft) should write `root.crt`, `server.crt` and `server.key` next to
/// the data directory with it once this lands.
pub fn issue_server(
    ca: &ClientCa,
    host_names: &[&str],
    now: SystemTime,
) -> Result<ClientLeaf, ApiError> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|e| ApiError::internal(format!("db server key: {e}")))?;
    let issuer = Issuer::from_ca_cert_der(&ca.cert_der.as_slice().into(), &ca.key)
        .map_err(|e| ApiError::internal(format!("db client CA certificate: {e}")))?;
    // QUESTION(PRD-05 Q45): rotation. Proposed: the pod's certificate lives as long as the pod
    // (Postgres re-reads it only on reload), bounded at 30 days; the CA itself never rotates
    // because the volume key never does.
    let not_after = later(now, Duration::from_secs(30 * 86400))?;
    let mut params = CertificateParams::new(
        host_names
            .iter()
            .map(|h| (*h).to_owned())
            .collect::<Vec<_>>(),
    )
    .map_err(|e| ApiError::malformed(format!("host name: {e}")))?;
    params.distinguished_name = subject("alpha-kms trust-zone postgres");
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.use_authority_key_identifier_extension = true;
    params.not_before = now.into();
    params.not_after = not_after.into();
    let cert_der = params
        .signed_by(&key, &issuer)
        .map_err(|e| ApiError::internal(format!("db server certificate: {e}")))?
        .der()
        .to_vec();
    Ok(ClientLeaf {
        cert_der,
        key_pkcs8: Zeroizing::new(key.serialize_der()),
        not_after,
    })
}

/// `base` with the leaf as client identity and the CA as the only root for the server.
pub fn connect_options(
    base: &PgConnectOptions,
    ca: &ClientCa,
    leaf: &ClientLeaf,
) -> PgConnectOptions {
    let key_pem = Zeroizing::new(pem::encode(&pem::Pem::new(
        "PRIVATE KEY",
        leaf.key_pkcs8.to_vec(),
    )));
    base.clone()
        .username(ROLE)
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert_from_pem(ca.cert_pem().into_bytes())
        .ssl_client_cert_from_pem(crate::certs::pem(&leaf.cert_der))
        .ssl_client_key_from_pem(key_pem.as_bytes())
}

/// Client-cert mode's state on a node: the URL's options, and when the installed leaf expires.
pub struct ClientCert {
    base: PgConnectOptions,
    installed_until: Mutex<Option<SystemTime>>,
}

impl ClientCert {
    pub fn new(base: PgConnectOptions) -> Self {
        Self {
            base,
            installed_until: Mutex::new(None),
        }
    }

    /// Whether a leaf is installed and not expired at `now`.
    pub fn installed(&self, now: SystemTime) -> bool {
        self.installed_until.lock().is_some_and(|until| until > now)
    }
}

/// Turns client-cert mode on for `node`. Until [`install`] runs, the pool's connections carry no
/// client certificate, which Postgres refuses: the node cannot reach the database before it holds
/// the volume key, which is the point.
pub fn enable(node: &Node, base: PgConnectOptions) {
    // Until then, nothing is sent to a server that is not verified: no root is configured, so
    // `verify-full` against the system roots fails the handshake (`unreachable` to the M2(a) code).
    node.pool
        .set_connect_options(base.clone().username(ROLE).ssl_mode(PgSslMode::VerifyFull));
    *node.db_auth.lock() = Some(Arc::new(ClientCert::new(base)));
}

/// Whether this node is in client-cert mode.
pub fn client_cert_mode(node: &Node) -> bool {
    node.db_auth.lock().is_some()
}

/// Whether `e` is Postgres refusing a client-cert node that holds no leaf yet (SQLSTATE 28000).
/// Before unseal that is the database being closed *to this node*, which the M2(a) code treats as
/// unreachable: the platform document stays in memory and an unseal waits for the database.
pub fn refused_without_leaf(node: &Node, e: &sqlx::Error) -> bool {
    let Some(state) = node.db_auth.lock().clone() else {
        return false;
    };
    !state.installed(node.now())
        && matches!(e, sqlx::Error::Database(db) if db.code().as_deref() == Some("28000"))
}

/// Issues this node a leaf from the CA `db_volume` derives and points the pool's new connections
/// at it. A no-op in `url` mode.
pub fn install(node: &Node, db_volume: &[u8; 32]) -> Result<(), ApiError> {
    let Some(state) = node.db_auth.lock().clone() else {
        return Ok(());
    };
    let ca = ClientCa::derive(db_volume)?;
    let leaf = issue_client(&ca, &node.runtime_spki, node.now())?;
    node.pool
        .set_connect_options(connect_options(&state.base, &ca, &leaf));
    *state.installed_until.lock() = Some(leaf.not_after);
    Ok(())
}

/// Replaces the leaf once less than [`RENEW_BEFORE`] is left. Called from the platform tick and
/// the wait-for-database loop. A node holding no volume key keeps what it has; once that expires
/// Postgres refuses its new connections, which is fail-closed.
pub fn renew_if_due(node: &Node) {
    let Some(state) = node.db_auth.lock().clone() else {
        return;
    };
    let now = node.now();
    let due = match *state.installed_until.lock() {
        None => true,
        Some(until) => until
            .duration_since(now)
            .map_or(true, |left| left < RENEW_BEFORE),
    };
    if !due {
        return;
    }
    match node.db_volume_key() {
        Ok(key) => {
            if let Err(e) = install(node, &key) {
                eprintln!("db client certificate: {}", e.message);
            }
        }
        // TODO(draft): a serving node of a database from before M2(a) has no volume key, so it has
        // no client CA either; client-cert mode requires a database that has one.
        Err(e) => eprintln!("db client certificate: {}", e.message),
    }
}

/// The joining side of `node.join.request` in client-cert mode.
///
/// A joining node writes its `node.join.request` row *before* the join reply hands it the volume
/// key, and the serving node refuses a join without that row. In client-cert mode the joining node
/// has no database credential until the reply, so the row cannot be written.
///
/// QUESTION(PRD-05 Q46): what replaces the row for a client-cert joiner? Proposed: the serving node
/// writes `node.join.request` itself when it mints the join nonce for an attested, listed Kata
/// node, because the row's job (proof that the joiner holds the database credential) is exactly
/// what D10 (a) moves into attestation. Until that is decided this refuses, so a client-cert node
/// can be unsealed by custodians but cannot join.
pub fn check_can_join(node: &Node) -> Result<(), ApiError> {
    let Some(state) = node.db_auth.lock().clone() else {
        return Ok(());
    };
    if state.installed(node.now()) {
        return Ok(());
    }
    Err(ApiError::internal(
        "client-cert mode: a joining node has no database credential before the join reply, so \
         it cannot write node.join.request (TODO(draft), QUESTION(PRD-05 Q46)); unseal this node \
         with custodians instead",
    ))
}

#[cfg(test)]
mod tests {
    use rustls::pki_types::CertificateDer;

    use super::*;

    const URL: &str = "postgres://alpha_kms_node@postgres.verifier.svc:5432/alpha";

    #[test]
    fn mode_is_url_unless_client_cert_is_named() {
        assert_eq!(mode(None), Ok(Mode::Url));
        assert_eq!(mode(Some("url")), Ok(Mode::Url));
        assert_eq!(mode(Some("client-cert")), Ok(Mode::ClientCert));
        assert!(mode(Some("password")).is_err());
        assert!(mode(Some("cert")).is_err());
    }

    #[test]
    fn a_password_is_refused_on_a_kata_node_and_in_client_cert_mode() {
        let with_password = "postgres://alpha_kms_node:s3cret@db:5432/alpha";
        let in_query = "postgres://alpha_kms_node@db:5432/alpha?password=s3cret";
        // The prototype node's encrypted env still carries one.
        assert!(check_url(with_password, Mode::Url, false).is_ok());
        for url in [with_password, in_query] {
            assert!(check_url(url, Mode::Url, true).is_err(), "{url}");
            assert!(check_url(url, Mode::ClientCert, false).is_err(), "{url}");
        }
        assert!(check_url(URL, Mode::Url, true).is_ok());
        assert!(check_url(URL, Mode::ClientCert, true).is_ok());
    }

    #[test]
    fn client_cert_mode_refuses_weaker_tls_foreign_certificates_and_another_role() {
        for url in [
            "postgres://alpha_kms_node@db/alpha?sslmode=require",
            "postgres://alpha_kms_node@db/alpha?sslmode=disable",
            "postgres://alpha_kms_node@db/alpha?sslmode=verify-ca",
            "postgres://alpha_kms_node@db/alpha?sslcert=/tmp/c.pem",
            "postgres://alpha_kms_node@db/alpha?sslrootcert=/tmp/ca.pem",
            "postgres://postgres@db/alpha",
        ] {
            assert!(check_url(url, Mode::ClientCert, true).is_err(), "{url}");
        }
        assert!(
            check_url(
                "postgres://db/alpha?sslmode=verify-full",
                Mode::ClientCert,
                true
            )
            .is_ok()
        );
    }

    #[test]
    fn the_ca_is_a_function_of_the_volume_key_alone() {
        let a = ClientCa::derive(&[7; 32]).unwrap();
        let again = ClientCa::derive(&[7; 32]).unwrap();
        let other = ClientCa::derive(&[8; 32]).unwrap();
        assert_eq!(a.spki_sha256(), again.spki_sha256());
        assert_ne!(a.spki_sha256(), other.spki_sha256());
        let (_, cert) = x509_parser::parse_x509_certificate(&a.cert_der).unwrap();
        let (_, cert_again) = x509_parser::parse_x509_certificate(&again.cert_der).unwrap();
        assert_eq!(cert.subject(), cert_again.subject());
        assert_eq!(cert.serial, cert_again.serial);
        assert!(cert.is_ca());
    }

    #[test]
    fn a_node_leaf_chains_to_the_ca_names_the_node_and_lasts_an_hour() {
        let ca = ClientCa::derive(&[7; 32]).unwrap();
        let spki = b"runtime spki".to_vec();
        let now = SystemTime::now();
        let leaf = issue_client(&ca, &spki, now).unwrap();
        let verifier = crate::certs::ca_verifier(&ca.cert_der).unwrap();
        let chain = [CertificateDer::from(leaf.cert_der.clone())];
        let sans = crate::certs::verify_to_ca(verifier.as_ref(), &chain, now).unwrap();
        let digest = hex::encode(Sha256::digest(&spki));
        assert_eq!(sans, [format!("{CLIENT_SAN_PREFIX}{digest}")]);
        let (_, cert) = x509_parser::parse_x509_certificate(&leaf.cert_der).unwrap();
        let cn = cert.subject().iter_common_name().next().unwrap();
        assert_eq!(cn.as_str().unwrap(), node_cn(&spki));
        assert_eq!(node_cn(&spki).len(), "kms-node-".len() + 16);
        assert!(!cert.is_ca());
        assert_eq!(leaf.not_after.duration_since(now).unwrap(), CLIENT_TTL);
        // Another volume key's CA does not accept it, and neither does this CA once it expired.
        let other = ClientCa::derive(&[8; 32]).unwrap();
        let other = crate::certs::ca_verifier(&other.cert_der).unwrap();
        assert!(crate::certs::verify_to_ca(other.as_ref(), &chain, now).is_err());
        let after = now
            .checked_add(CLIENT_TTL + Duration::from_secs(1))
            .unwrap();
        assert!(crate::certs::verify_to_ca(verifier.as_ref(), &chain, after).is_err());
    }

    #[test]
    fn each_leaf_has_its_own_key() {
        let ca = ClientCa::derive(&[7; 32]).unwrap();
        let a = issue_client(&ca, b"n", SystemTime::now()).unwrap();
        let b = issue_client(&ca, b"n", SystemTime::now()).unwrap();
        assert_ne!(a.key_pkcs8.as_slice(), b.key_pkcs8.as_slice());
    }
}

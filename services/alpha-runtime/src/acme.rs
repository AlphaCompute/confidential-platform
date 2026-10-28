//! A browser-trusted certificate for the Endpoint's public name, from an ACME CA through
//! TLS-ALPN-01 on the Endpoint's own port, the one port the public path forwards.
//!
//! The certificate key and the ACME account key are derived from the App's `edge-tls` key, which
//! only Instances of the App receive. So every restart, renewal and Revision of the App holds the
//! same key, and every current certificate for the name in Certificate Transparency holds it too.
//! At start the runtime looks up the newest such certificate through Cert Spotter and fetches its
//! chain from the CA, so a restart orders nothing. [`alpha_channel::binding`] ties the key to the
//! Instance leaf.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use alpha_client::log::Field;
use alpha_client::tls;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hkdf::Hkdf;
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, Key, NewOrder, OrderStatus,
    RetryPolicy,
};
use p256::elliptic_curve::array::Array;
use p256::elliptic_curve::consts::U48;
use p256::elliptic_curve::ops::Reduce;
use p256::pkcs8::EncodePrivateKey;
use p256::{NonZeroScalar, Scalar, SecretKey};
use parking_lot::RwLock;
use rcgen::PublicKeyData;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, DnsName, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, X509Certificate};
use zeroize::{Zeroize, Zeroizing};

use crate::{Error, Runtime};

pub const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";
const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
/// Boulder serves an issued certificate's chain to anyone at its serial, the chain an order
/// returns.
const LETS_ENCRYPT_CERT: &str = "https://acme-v02.api.letsencrypt.org/acme/cert/";
/// Lists the unexpired certificates for a name, oldest discovered first.
const CT_SEARCH: &str = "https://api.certspotter.com/v1/issuances";
const CT_PAGES: usize = 4;
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(60);
/// Let's Encrypt allows five failed validations per name and account, refilled one every 12
/// minutes. The quick retries spend four of the five, so a new App whose route the edge router
/// has not loaded yet gets its certificate within minutes; `RETRY_AFTER` then refills faster
/// than it spends.
const QUICK_RETRIES: [Duration; 3] = [
    Duration::from_secs(60),
    Duration::from_secs(2 * 60),
    Duration::from_secs(4 * 60),
];
const RETRY_AFTER: Duration = Duration::from_secs(15 * 60);
/// The CA validates over the public path, which reaches a new pod only once its Service lists it.
const ROUTABLE_AFTER: Duration = Duration::from_secs(30);
/// A certificate already expired by the TD clock means a skewed clock; a new order would expire
/// too. Let's Encrypt refills one duplicate per name every 34 hours, so wait two days and never
/// order faster than the refill.
const EXPIRED_BACKOFF: Duration = Duration::from_secs(48 * 60 * 60);
const KEY_PURPOSE: &str = "edge-tls";
const KEY_RETRY: Duration = Duration::from_secs(5);
// ponytail: one key per name and one account per App for as long as the label stays. A leaked
// key or a key rotation means a new label version, and the certificates of the old key stay in
// CT until they expire.
const CERT_KEY_LABEL: &[u8] = b"alphacompute-runtime/public-name-key/v1/";
const ACCOUNT_KEY_LABEL: &[u8] = b"alphacompute-runtime/acme-account-key/v1";
const POLL: RetryPolicy = RetryPolicy::new()
    .initial_delay(Duration::from_secs(1))
    .timeout(Duration::from_secs(120));

/// `ALPHACOMPUTE_PUBLIC_NAME`; None when it is not set.
pub fn parse_public_name(
    name: Option<&str>,
    upstream: Option<&str>,
    callers: &[alpha_core::AppId],
) -> Result<Option<String>, Error> {
    let refused = |m: &str| Error::Config(format!("ALPHACOMPUTE_PUBLIC_NAME: {m}"));
    let Some(name) = name else {
        return Ok(None);
    };
    if !name.contains('.')
        || name.bytes().any(|b| b.is_ascii_uppercase())
        || DnsName::try_from(name).is_err()
    {
        return Err(refused("is not a lowercase DNS name"));
    }
    if upstream.is_none() {
        return Err(refused("set without ALPHACOMPUTE_TLS_UPSTREAM"));
    }
    // A browser and the ACME CA present no Instance leaf.
    if !callers.is_empty() {
        return Err(refused("set with ALPHACOMPUTE_TLS_CALLER_APPS"));
    }
    Ok(Some(name.to_owned()))
}

/// The public certificate and the pending challenge's, replaced by the issuance task while the
/// listener serves them.
#[derive(Debug, Default)]
pub struct Edge {
    pub served: RwLock<Option<Arc<CertifiedKey>>>,
    pub challenge: RwLock<Option<Arc<CertifiedKey>>>,
}

/// Which certificate a handshake gets, from its SNI and the protocols it offers.
#[derive(Debug, PartialEq, Eq)]
pub enum Route {
    /// The KMS leaf: an `alpha` client offers no ALPN, and any other name keeps it too.
    Instance,
    /// The ACME CA's validation (RFC 8737).
    Challenge,
    /// A browser on the public name.
    Public,
}

pub fn route<'a>(
    public: &str,
    sni: Option<&str>,
    alpn: Option<impl Iterator<Item = &'a [u8]>>,
) -> Route {
    let (Some(sni), Some(alpn)) = (sni, alpn) else {
        return Route::Instance;
    };
    if !sni.eq_ignore_ascii_case(public) {
        return Route::Instance;
    }
    let mut http = false;
    for protocol in alpn {
        if protocol == ACME_TLS_ALPN {
            return Route::Challenge;
        }
        http |= protocol == b"http/1.1" || protocol == b"h2";
    }
    if http { Route::Public } else { Route::Instance }
}

// ponytail: one copy per App with a public name. Each copy keeps its own challenge and orders
// on its own, so the CA's validation routed to another copy fails; the upgrade is one copy that
// orders and the others that find its certificate in CT.
pub async fn issue_forever(edge: Arc<Edge>, name: String, runtime: Arc<Runtime>) {
    let app_key = edge_tls_key(&runtime).await;
    let keys = derive_p256(&app_key, &[CERT_KEY_LABEL, name.as_bytes()].concat())
        .and_then(|cert| Ok((cert, derive_p256(&app_key, ACCOUNT_KEY_LABEL)?)));
    let (cert_key, account_key) = match keys {
        Ok(keys) => keys,
        Err(e) => {
            alpha_client::error!("public_certificate_key_failed", error = Field::text(&e));
            return;
        }
    };
    let reused = match tokio::time::timeout(LOOKUP_TIMEOUT, reuse(&edge, &name, &cert_key))
        .await
        .unwrap_or_else(|_| Err("timed out".into()))
    {
        Ok(reused) => reused,
        Err(e) => {
            alpha_client::warn!("public_certificate_lookup_failed", error = Field::text(&e));
            None
        }
    };
    tokio::time::sleep(reused.unwrap_or(ROUTABLE_AFTER)).await;
    let account = loop {
        match account(&account_key).await {
            Ok(account) => break account,
            Err(e) => {
                alpha_client::warn!("acme_account_failed", error = Field::text(&e));
                tokio::time::sleep(RETRY_AFTER).await;
            }
        }
    };
    let mut failures = 0usize;
    loop {
        let wait = match issue(&edge, &name, &account, &cert_key).await {
            Ok(not_after) => {
                alpha_client::info!("public_certificate_issued", not_after = not_after);
                failures = 0;
                renewal_delay(not_after, SystemTime::now())
            }
            Err(e) => {
                alpha_client::warn!("public_certificate_failed", error = Field::text(&e));
                failures = failures.saturating_add(1);
                retry_delay(failures)
            }
        };
        tokio::time::sleep(wait).await;
    }
}

fn retry_delay(failures: usize) -> Duration {
    failures
        .checked_sub(1)
        .and_then(|i| QUICK_RETRIES.get(i))
        .copied()
        .unwrap_or(RETRY_AFTER)
}

/// Renew with a third of the remaining lifetime left.
fn renewal_delay(not_after: SystemTime, now: SystemTime) -> Duration {
    match not_after.duration_since(now) {
        Ok(left) if !left.is_zero() => left
            .checked_div(3)
            .unwrap_or_default()
            .saturating_mul(2)
            .max(RETRY_AFTER),
        _ => EXPIRED_BACKOFF,
    }
}

/// At start the runtime may not have its first leaf yet; nothing can be served or ordered
/// without the key.
async fn edge_tls_key(runtime: &Runtime) -> Zeroizing<Vec<u8>> {
    loop {
        let decoded = runtime
            .key(KEY_PURPOSE)
            .await
            .map_err(|e| e.to_string())
            .and_then(|k| alpha_client::decode("key", &k.key).map_err(|e| e.to_string()));
        match decoded {
            Ok(key) => return Zeroizing::new(key),
            Err(e) => alpha_client::warn!("edge_tls_key_failed", error = Field::text(&e)),
        }
        tokio::time::sleep(KEY_RETRY).await;
    }
}

/// The PKCS#8 of the P-256 key HKDF-SHA256 of `app_key` gives for `info`: 48 bytes reduced
/// modulo the group order, which leaves a bias of about 2^-128 (RFC 9380 §5).
fn derive_p256(app_key: &[u8], info: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut wide = Array::<u8, U48>::default();
    Hkdf::<Sha256>::new(None, app_key)
        .expand(info, &mut wide)
        .map_err(|e| format!("hkdf: {e}"))?;
    let scalar = <Scalar as Reduce<Array<u8, U48>>>::reduce(&wide);
    wide.zeroize();
    let scalar = Option::<NonZeroScalar>::from(NonZeroScalar::new(scalar))
        .ok_or("the derived scalar is zero")?;
    let pkcs8 = SecretKey::from(scalar)
        .to_pkcs8_der()
        .map_err(|e| format!("pkcs8: {e}"))?;
    Ok(Zeroizing::new(pkcs8.as_bytes().to_vec()))
}

fn spki_sha256(pkcs8: &[u8]) -> Result<[u8; 32], String> {
    let key = rcgen::KeyPair::try_from(pkcs8).map_err(|e| e.to_string())?;
    Ok(Sha256::digest(key.subject_public_key_info()).into())
}

/// The same key gives the same Let's Encrypt account on every start.
async fn account(pkcs8: &[u8]) -> Result<Account, String> {
    let der = PrivatePkcs8KeyDer::from(pkcs8.to_vec());
    let key = Key::from_pkcs8_der(der.clone_key()).map_err(|e| e.to_string())?;
    let (account, _) = Account::builder()
        .map_err(|e| e.to_string())?
        .create_from_key((key, PrivateKeyDer::Pkcs8(der)), LETS_ENCRYPT.to_owned())
        .await
        .map_err(|e| e.to_string())?;
    Ok(account)
}

/// The issued certificate's `not_after`.
async fn issue(
    edge: &Edge,
    name: &str,
    account: &Account,
    pkcs8: &[u8],
) -> Result<SystemTime, String> {
    let acme = |e: instant_acme::Error| e.to_string();
    let identifiers = [Identifier::Dns(name.to_owned())];
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .map_err(acme)?;
    let mut authorizations = order.authorizations();
    while let Some(authorization) = authorizations.next().await {
        let mut authorization = authorization.map_err(acme)?;
        if authorization.status == AuthorizationStatus::Valid {
            continue;
        }
        let mut challenge = authorization
            .challenge(ChallengeType::TlsAlpn01)
            .ok_or("the CA offers no tls-alpn-01 challenge")?;
        let digest = challenge.key_authorization().digest();
        *edge.challenge.write() = Some(challenge_cert(name, digest.as_ref())?);
        challenge.set_ready().await.map_err(acme)?;
    }
    let status = order.poll_ready(&POLL).await;
    *edge.challenge.write() = None;
    if status.map_err(acme)? != OrderStatus::Ready {
        return Err("the order did not become ready".into());
    }
    let key = rcgen::KeyPair::try_from(pkcs8).map_err(|e| e.to_string())?;
    let mut params = rcgen::CertificateParams::new([name.to_owned()]).map_err(|e| e.to_string())?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let csr = params.serialize_request(&key).map_err(|e| e.to_string())?;
    order.finalize_csr(csr.der()).await.map_err(acme)?;
    let chain_pem = order.poll_certificate(&POLL).await.map_err(acme)?;
    install(edge, pkcs8, &chain_pem)
}

/// Serves `chain_pem` with the key if its leaf holds that key; returns the leaf's `not_after`.
fn install(edge: &Edge, pkcs8: &[u8], chain_pem: &str) -> Result<SystemTime, String> {
    let chain = CertificateDer::pem_slice_iter(chain_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("certificate chain: {e}"))?;
    let leaf = chain.first().ok_or("the chain has no certificate")?;
    if alpha_channel::cert::spki_sha256(leaf) != Some(spki_sha256(pkcs8)?) {
        return Err("the chain's leaf does not hold the derived key".into());
    }
    let not_after = alpha_channel::cert::not_after(leaf).map_err(|e| e.to_string())?;
    let certified = tls::certified(chain, pkcs8).map_err(|e| e.to_string())?;
    *edge.served.write() = Some(certified);
    Ok(not_after)
}

/// Serves the newest certificate for the name in CT that holds the key, and returns the wait
/// until its renewal; None when there is none. Both connections end in the TD, and a chain
/// for another key fails the key check; an old chain that passes it is a certificate of this
/// App. Cert Spotter or the CA can only withhold or break the certificate, and a new order
/// replaces it.
async fn reuse(edge: &Edge, name: &str, pkcs8: &[u8]) -> Result<Option<Duration>, String> {
    let http = alpha_client::http().build().map_err(|e| e.to_string())?;
    let spki = spki_sha256(pkcs8)?;
    let now = SystemTime::now();
    let mut newest = None;
    let mut after = String::new();
    for _ in 0..CT_PAGES {
        let url = format!("{CT_SEARCH}?domain={name}&expand=cert_der&after={after}");
        let page: Vec<serde_json::Value> = serde_json::from_slice(&get(&http, &url).await?)
            .map_err(|e| format!("cert spotter: {e}"))?;
        let Some(last) = page.last() else { break };
        last.get("id")
            .and_then(|id| id.as_str())
            .filter(|id| id.bytes().all(|b| b.is_ascii_digit()))
            .ok_or("cert spotter: an issuance without a numeric id")?
            .clone_into(&mut after);
        newest = newest
            .into_iter()
            .chain(newest_holding(&page, &spki, now))
            .max_by_key(|issued| issued.not_after);
    }
    let Some(found) = newest else {
        return Ok(None);
    };
    let chain = get(&http, &format!("{LETS_ENCRYPT_CERT}{}", found.serial)).await?;
    let chain = String::from_utf8(chain).map_err(|_| "the chain is not PEM")?;
    install(edge, pkcs8, &chain)?;
    alpha_client::info!("public_certificate_reused", not_after = found.not_after);
    // Past its renewal time the certificate is still served while the new order runs.
    let renew_at = found
        .not_before
        .checked_add(renewal_delay(found.not_after, found.not_before))
        .ok_or("the renewal time is out of range")?;
    Ok(Some(
        renew_at
            .duration_since(now)
            .unwrap_or_default()
            .max(ROUTABLE_AFTER),
    ))
}

async fn get(http: &reqwest::Client, url: &str) -> Result<Vec<u8>, String> {
    let response = http
        .get(url)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| e.to_string())?;
    alpha_client::read_capped(response, 1 << 20).await
}

#[derive(Debug)]
struct Issued {
    serial: String,
    not_before: SystemTime,
    not_after: SystemTime,
}

/// Of Cert Spotter's issuances, the unrevoked one valid at `now` whose key is `spki`, with the
/// latest `not_after`. A precertificate has the serial, key and validity of its certificate, so
/// either one gives the chain's URL.
fn newest_holding(page: &[serde_json::Value], spki: &[u8; 32], now: SystemTime) -> Option<Issued> {
    page.iter()
        .filter(|issuance| issuance.get("revoked") != Some(&serde_json::Value::Bool(true)))
        .filter_map(|issuance| {
            let der = STANDARD.decode(issuance.get("cert_der")?.as_str()?).ok()?;
            let (_, cert) = X509Certificate::from_der(&der).ok()?;
            if <[u8; 32]>::from(Sha256::digest(cert.public_key().raw)) != *spki {
                return None;
            }
            let at = |t: x509_parser::time::ASN1Time| {
                SystemTime::UNIX_EPOCH
                    .checked_add(Duration::from_secs(u64::try_from(t.timestamp()).ok()?))
            };
            let validity = cert.validity();
            let issued = Issued {
                serial: serial_hex(cert.raw_serial()),
                not_before: at(validity.not_before)?,
                not_after: at(validity.not_after)?,
            };
            (issued.not_before <= now && now < issued.not_after).then_some(issued)
        })
        .max_by_key(|issued| issued.not_after)
}

/// Boulder's spelling in a certificate URL: lowercase hex, at least 36 digits, no sign byte.
fn serial_hex(raw: &[u8]) -> String {
    let hex: String = raw
        .iter()
        .skip_while(|b| **b == 0)
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("{hex:0>36}")
}

/// The self-signed certificate RFC 8737 asks for: the name, and the SHA-256 of the key
/// authorization in a critical `acmeIdentifier` extension.
fn challenge_cert(name: &str, digest: &[u8]) -> Result<Arc<CertifiedKey>, String> {
    let key = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
    let mut params = rcgen::CertificateParams::new([name.to_owned()]).map_err(|e| e.to_string())?;
    params.custom_extensions = vec![rcgen::CustomExtension::new_acme_identifier(digest)];
    let cert = params.self_signed(&key).map_err(|e| e.to_string())?;
    tls::certified(vec![cert.der().clone()], &key.serialize_der()).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NAME: &str = "hello.alphacompute.cc";

    fn routed(sni: Option<&str>, alpn: Option<&[&[u8]]>) -> Route {
        route(NAME, sni, alpn.map(|a| a.iter().copied()))
    }

    #[test]
    fn the_certificate_follows_sni_and_alpn() {
        assert_eq!(routed(Some(NAME), None), Route::Instance);
        assert_eq!(routed(None, Some(&[b"h2"])), Route::Instance);
        assert_eq!(
            routed(Some(NAME), Some(&[b"h2", b"http/1.1"])),
            Route::Public
        );
        assert_eq!(
            routed(Some("HELLO.alphacompute.cc"), Some(&[b"http/1.1"])),
            Route::Public
        );
        assert_eq!(routed(Some(NAME), Some(&[ACME_TLS_ALPN])), Route::Challenge);
        assert_eq!(
            routed(Some("other.alphacompute.cc"), Some(&[ACME_TLS_ALPN])),
            Route::Instance
        );
        assert_eq!(
            routed(Some("other.alphacompute.cc"), Some(&[b"h2"])),
            Route::Instance
        );
        assert_eq!(routed(Some(NAME), Some(&[b"grpc-exp"])), Route::Instance);
    }

    #[test]
    fn a_public_name_is_one_lowercase_dns_name_on_an_endpoint_open_to_any_client() {
        let upstream = Some("app:8080");
        assert_eq!(
            parse_public_name(Some(NAME), upstream, &[])
                .unwrap()
                .as_deref(),
            Some(NAME)
        );
        assert!(parse_public_name(None, upstream, &[]).unwrap().is_none());

        let caller = [alpha_core::AppId::mint()];
        for (name, upstream, callers) in [
            ("Hello.alphacompute.cc", upstream, &[][..]),
            ("localhost", upstream, &[]),
            ("10.0.0.1", upstream, &[]),
            (NAME, None, &[]),
            (NAME, upstream, &caller),
        ] {
            assert!(
                parse_public_name(Some(name), upstream, callers).is_err(),
                "{name:?} {upstream:?}"
            );
        }
    }

    #[test]
    fn the_derived_key_depends_only_on_the_app_key_and_the_label() {
        let label = |name: &str| [CERT_KEY_LABEL, name.as_bytes()].concat();
        let a = derive_p256(&[7; 32], &label(NAME)).unwrap();
        assert_eq!(*a, *derive_p256(&[7; 32], &label(NAME)).unwrap());
        assert_ne!(*a, *derive_p256(&[8; 32], &label(NAME)).unwrap());
        assert_ne!(
            *a,
            *derive_p256(&[7; 32], &label("other.alphacompute.cc")).unwrap()
        );
        assert_ne!(*a, *derive_p256(&[7; 32], ACCOUNT_KEY_LABEL).unwrap());
        tls::certified(vec![CertificateDer::from(vec![0])], &a).unwrap();
        Key::from_pkcs8_der(PrivatePkcs8KeyDer::from(a.to_vec())).unwrap();
    }

    #[test]
    fn the_lookup_takes_the_newest_valid_certificate_holding_the_key() {
        let ours = rcgen::KeyPair::generate().unwrap();
        let other = rcgen::KeyPair::generate().unwrap();
        let day = |d: u64| SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000 + d * 86_400);
        let issuance = |key: &rcgen::KeyPair, serial: u8, from: u64, to: u64, revoked: bool| {
            let mut params = rcgen::CertificateParams::new([NAME.to_owned()]).unwrap();
            params.serial_number = Some(rcgen::SerialNumber::from(vec![serial]));
            params.not_before = day(from).into();
            params.not_after = day(to).into();
            let der = params.self_signed(key).unwrap().der().to_vec();
            serde_json::json!({"revoked": revoked, "cert_der": STANDARD.encode(der)})
        };
        let page = [
            issuance(&ours, 1, 10, 100, false),
            issuance(&ours, 2, 0, 20, false),
            issuance(&other, 3, 30, 120, false),
            issuance(&ours, 4, 20, 110, false),
            issuance(&ours, 5, 25, 115, true),
            issuance(&ours, 6, 50, 140, false),
        ];
        let spki: [u8; 32] = Sha256::digest(ours.subject_public_key_info()).into();
        let found = newest_holding(&page, &spki, day(40)).unwrap();
        assert_eq!(
            (found.serial.as_str(), found.not_after),
            ("000000000000000000000000000000000004", day(110))
        );
        assert!(newest_holding(&page[1..3], &spki, day(40)).is_none());
    }

    #[test]
    fn renewal_waits_for_two_thirds_of_the_remaining_lifetime() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let days = |n: u64| Duration::from_secs(n * 86_400);
        assert_eq!(renewal_delay(now + days(90), now), days(60));
        assert_eq!(renewal_delay(now - days(1), now), EXPIRED_BACKOFF);
        assert_eq!(
            renewal_delay(now + Duration::from_secs(60), now),
            RETRY_AFTER
        );
    }

    #[test]
    fn failed_orders_stay_within_the_failed_validation_limit() {
        // Let's Encrypt's bucket in seconds of refill: five failures, one back every 720 s.
        let (capacity, cost) = (5 * 720, 720);
        let mut tokens = capacity;
        for failures in 1..50 {
            assert!(tokens >= cost, "failure {failures} is over the limit");
            tokens -= cost;
            tokens = (tokens + retry_delay(failures).as_secs()).min(capacity);
        }
        assert_eq!(retry_delay(1), QUICK_RETRIES[0]);
    }
}

//! A browser-trusted certificate for the Endpoint's public name, from an ACME CA through
//! TLS-ALPN-01 on the Endpoint's own port, the one port the public path forwards. The key is
//! made here and leaves the TD only sealed under the App's own key;
//! [`alpha_channel::binding`] ties it to the Instance leaf.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};

use alpha_client::log::Field;
use alpha_client::tls;
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
    RetryPolicy,
};
use parking_lot::RwLock;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, DnsName};
use rustls::sign::CertifiedKey;
use zeroize::Zeroizing;

use crate::{Error, Runtime};

pub const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";
const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
/// Let's Encrypt allows five failed validations per name and hour.
const RETRY_AFTER: Duration = Duration::from_secs(15 * 60);
/// The CA validates over the public path, which reaches a new pod only once its Service lists it.
const ROUTABLE_AFTER: Duration = Duration::from_secs(30);
/// A certificate already expired by the TD clock means a skewed clock; a new order would expire
/// too. Let's Encrypt refills one duplicate per name every 34 hours, so wait two days and never
/// order faster than the refill.
const EXPIRED_BACKOFF: Duration = Duration::from_secs(48 * 60 * 60);
/// The App's derived key that seals the cached certificate; only an Instance of the App gets it.
const CACHE_KEY_PURPOSE: &str = "edge-tls";
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
// orders and the others that read its sealed certificate from shared storage.
// ponytail: the certificate survives a restart only in the file `ALPHACOMPUTE_ACME_CACHE` names;
// without that file, or with a lost one, every start orders anew and a restart loop runs into
// Let's Encrypt's five certificates per name and week. The upgrade is the same sealed blob
// stored as a Secret at the KMS.
pub async fn issue_forever(edge: Arc<Edge>, name: String, runtime: Arc<Runtime>) {
    let cache = runtime.config().acme_cache.clone();
    let restored = match &cache {
        Some(path) => restore(&edge, &runtime, path, &name)
            .await
            .inspect_err(|e| alpha_client::warn!("acme_cache_unread", error = Field::text(e)))
            .ok()
            .flatten(),
        None => None,
    };
    match restored {
        Some(wait) => {
            alpha_client::info!("public_certificate_restored");
            tokio::time::sleep(wait).await;
        }
        None => tokio::time::sleep(ROUTABLE_AFTER).await,
    }
    let account = loop {
        match account().await {
            Ok(account) => break account,
            Err(e) => {
                alpha_client::warn!("acme_account_failed", error = Field::text(&e));
                tokio::time::sleep(RETRY_AFTER).await;
            }
        }
    };
    loop {
        let wait = match issue(&edge, &name, &account).await {
            Ok((not_after, pkcs8, chain_pem)) => {
                alpha_client::info!("public_certificate_issued", not_after = not_after);
                let now = SystemTime::now();
                let wait = renewal_delay(not_after, now);
                if let Some(path) = &cache
                    && let Err(e) =
                        store(&runtime, path, &name, now, wait, &pkcs8, &chain_pem).await
                {
                    alpha_client::warn!("acme_cache_unwritten", error = Field::text(&e));
                }
                wait
            }
            Err(e) => {
                alpha_client::warn!("public_certificate_failed", error = Field::text(&e));
                RETRY_AFTER
            }
        };
        tokio::time::sleep(wait).await;
    }
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

async fn account() -> Result<Account, String> {
    let (account, _) = Account::builder()
        .map_err(|e| e.to_string())?
        .create(
            &NewAccount {
                contact: &[],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            LETS_ENCRYPT.to_owned(),
            None,
        )
        .await
        .map_err(|e| e.to_string())?;
    Ok(account)
}

/// The certificate's `not_after`, its PKCS#8 key and its chain as the CA sent it.
async fn issue(
    edge: &Edge,
    name: &str,
    account: &Account,
) -> Result<(SystemTime, Zeroizing<Vec<u8>>, String), String> {
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
    let key = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
    let mut params = rcgen::CertificateParams::new([name.to_owned()]).map_err(|e| e.to_string())?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let csr = params.serialize_request(&key).map_err(|e| e.to_string())?;
    order.finalize_csr(csr.der()).await.map_err(acme)?;
    let chain_pem = order.poll_certificate(&POLL).await.map_err(acme)?;
    let pkcs8 = Zeroizing::new(key.serialize_der());
    let not_after = install(edge, &pkcs8, &chain_pem)?;
    Ok((not_after, pkcs8, chain_pem))
}

fn install(edge: &Edge, pkcs8: &[u8], chain_pem: &str) -> Result<SystemTime, String> {
    let chain = CertificateDer::pem_slice_iter(chain_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("certificate chain: {e}"))?;
    let leaf = chain.first().ok_or("the chain has no certificate")?;
    let not_after = alpha_channel::cert::not_after(leaf).map_err(|e| e.to_string())?;
    let certified = tls::certified(chain, pkcs8).map_err(|e| e.to_string())?;
    *edge.served.write() = Some(certified);
    Ok(not_after)
}

async fn cache_key(runtime: &Runtime) -> Result<Zeroizing<[u8; 32]>, String> {
    let derived = runtime
        .key(CACHE_KEY_PURPOSE)
        .await
        .map_err(|e| e.to_string())?;
    let bytes =
        Zeroizing::new(alpha_client::decode("key", &derived.key).map_err(|e| e.to_string())?);
    let key: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "the edge-tls key is not 32 bytes")?;
    Ok(Zeroizing::new(key))
}

/// The wait until renewal of the cached certificate it installed; None when there is no file or
/// the certificate is both due for renewal and expired.
async fn restore(
    edge: &Edge,
    runtime: &Runtime,
    path: &Path,
    name: &str,
) -> Result<Option<Duration>, String> {
    let blob = match std::fs::read(path) {
        Ok(blob) => blob,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let key = cache_key(runtime).await?;
    let (renew_at, pkcs8, chain_pem) =
        open(&key, name, &blob).ok_or("the cached certificate does not open")?;
    let now = SystemTime::now();
    let due = renew_at.duration_since(now).ok();
    let not_after = install(edge, &pkcs8, &chain_pem)?;
    // Before its renewal time even an expired certificate stays, so a skewed clock keeps its
    // backoff across restarts; after it, a valid one is served while the new order runs.
    if due.is_none() && not_after <= now {
        *edge.served.write() = None;
        return Ok(None);
    }
    Ok(Some(due.unwrap_or_default().max(ROUTABLE_AFTER)))
}

async fn store(
    runtime: &Runtime,
    path: &Path,
    name: &str,
    now: SystemTime,
    wait: Duration,
    pkcs8: &[u8],
    chain_pem: &str,
) -> Result<(), String> {
    let renew_at = now
        .checked_add(wait)
        .ok_or("the renewal time is out of range")?;
    let key = cache_key(runtime).await?;
    let blob = seal(&key, name, renew_at, pkcs8, chain_pem)?;
    let (Some(dir), Some(file)) = (path.parent(), path.file_name().and_then(|f| f.to_str())) else {
        return Err(format!("{} names no file", path.display()));
    };
    crate::write_secret(dir, file, &blob).map_err(|e| format!("{}: {e}", path.display()))
}

/// `nonce(12) ‖ AES-256-GCM(renew_at(8, seconds, big-endian) ‖ len(2) ‖ pkcs8 ‖ chain PEM)`,
/// with the public name as associated data. The file sits on host storage: the host can neither
/// read the key nor write a certificate of its own, and a file of another name does not open.
fn seal(
    key: &[u8; 32],
    name: &str,
    renew_at: SystemTime,
    pkcs8: &[u8],
    chain_pem: &str,
) -> Result<Vec<u8>, String> {
    let renew_at = renew_at
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let len = u16::try_from(pkcs8.len()).map_err(|_| "the key is too long")?;
    let plaintext = Zeroizing::new(
        [
            &renew_at.to_be_bytes()[..],
            &len.to_be_bytes(),
            pkcs8,
            chain_pem.as_bytes(),
        ]
        .concat(),
    );
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce).map_err(|e| format!("rng: {e}"))?;
    let ct = Aes256Gcm::new(key.into())
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &plaintext,
                aad: name.as_bytes(),
            },
        )
        .map_err(|_| "aead: encryption failed")?;
    Ok([nonce.as_slice(), &ct].concat())
}

fn open(
    key: &[u8; 32],
    name: &str,
    blob: &[u8],
) -> Option<(SystemTime, Zeroizing<Vec<u8>>, String)> {
    let (nonce, ct) = blob.split_first_chunk::<12>()?;
    let plaintext = Zeroizing::new(
        Aes256Gcm::new(key.into())
            .decrypt(
                &Nonce::from(*nonce),
                Payload {
                    msg: ct,
                    aad: name.as_bytes(),
                },
            )
            .ok()?,
    );
    let (renew_at, rest) = plaintext.split_first_chunk::<8>()?;
    let (len, rest) = rest.split_first_chunk::<2>()?;
    let (pkcs8, chain_pem) = rest.split_at_checked(usize::from(u16::from_be_bytes(*len)))?;
    let renew_at = UNIX_EPOCH.checked_add(Duration::from_secs(u64::from_be_bytes(*renew_at)))?;
    Some((
        renew_at,
        Zeroizing::new(pkcs8.to_vec()),
        std::str::from_utf8(chain_pem).ok()?.to_owned(),
    ))
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
    fn a_cached_certificate_opens_only_under_its_key_and_name_and_unaltered() {
        let key = [7u8; 32];
        let renew_at = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let blob = seal(&key, NAME, renew_at, b"pkcs8", "chain").unwrap();
        let (at, pkcs8, chain) = open(&key, NAME, &blob).unwrap();
        assert_eq!(
            (at, pkcs8.as_slice(), chain.as_str()),
            (renew_at, &b"pkcs8"[..], "chain")
        );
        assert!(open(&[8u8; 32], NAME, &blob).is_none());
        assert!(open(&key, "other.alphacompute.cc", &blob).is_none());
        let mut tampered = blob.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(open(&key, NAME, &tampered).is_none());
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
}

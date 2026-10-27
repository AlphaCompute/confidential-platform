//! A browser-trusted certificate for the Endpoint's public name, from an ACME CA through
//! TLS-ALPN-01 on the Endpoint's own port, the one port the public path forwards. The key is
//! made here and never leaves the TD; [`alpha_channel::binding`] ties it to the Instance leaf.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

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

use crate::Error;

pub const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";
const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
/// Let's Encrypt allows five failed validations per name and hour.
const RETRY_AFTER: Duration = Duration::from_secs(15 * 60);
/// The CA validates over the public path, which reaches a new pod only once its Service lists it.
const ROUTABLE_AFTER: Duration = Duration::from_secs(30);
const POLL: RetryPolicy = RetryPolicy::new()
    .initial_delay(Duration::from_secs(1))
    .timeout(Duration::from_secs(120));

/// `ALPHACOMPUTE_PUBLIC_NAME`.
#[derive(Clone, Debug)]
pub struct PublicName {
    pub name: String,
}

impl PublicName {
    /// None when no name is set.
    pub fn parse(
        name: Option<&str>,
        upstream: Option<&str>,
        callers: &[alpha_core::AppId],
    ) -> Result<Option<Self>, Error> {
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
        Ok(Some(Self {
            name: name.to_owned(),
        }))
    }
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

// ponytail: one copy per App with a public name. Each copy keeps its own challenge and
// certificate, so the CA's validation routed to another copy fails; the upgrade is the same
// sealed certificate below, which every copy reads, and one copy that orders it.
// ponytail: a new account and certificate on every start, so a restart loop runs into Let's
// Encrypt's five certificates per name and week; the upgrade is the key and chain sealed under
// the App's derived key `edge-tls` and stored as a Secret, read back while valid.
pub async fn issue_forever(edge: Arc<Edge>, public: PublicName) {
    tokio::time::sleep(ROUTABLE_AFTER).await;
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
        let wait = match issue(&edge, &public.name, &account).await {
            Ok(not_after) => {
                alpha_client::info!("public_certificate_issued", not_after = not_after);
                renewal_delay(not_after, SystemTime::now())
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
    not_after
        .duration_since(now)
        .unwrap_or_default()
        .checked_div(3)
        .unwrap_or_default()
        .saturating_mul(2)
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

async fn issue(edge: &Edge, name: &str, account: &Account) -> Result<SystemTime, String> {
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
    let chain = CertificateDer::pem_slice_iter(chain_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("certificate chain: {e}"))?;
    let leaf = chain.first().ok_or("the CA returned no certificate")?;
    let not_after = alpha_channel::cert::not_after(leaf).map_err(|e| e.to_string())?;
    let pkcs8 = Zeroizing::new(key.serialize_der());
    let certified = tls::certified(chain, &pkcs8).map_err(|e| e.to_string())?;
    *edge.served.write() = Some(certified);
    Ok(not_after)
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
        let parsed = PublicName::parse(Some(NAME), upstream, &[])
            .unwrap()
            .unwrap();
        assert_eq!(parsed.name, NAME);
        assert!(PublicName::parse(None, upstream, &[]).unwrap().is_none());

        let caller = [alpha_core::AppId::mint()];
        for (name, upstream, callers) in [
            ("Hello.alphacompute.cc", upstream, &[][..]),
            ("localhost", upstream, &[]),
            ("10.0.0.1", upstream, &[]),
            (NAME, None, &[]),
            (NAME, upstream, &caller),
        ] {
            assert!(
                PublicName::parse(Some(name), upstream, callers).is_err(),
                "{name:?} {upstream:?}"
            );
        }
    }

    #[test]
    fn renewal_waits_for_two_thirds_of_the_remaining_lifetime() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let days = |n: u64| Duration::from_secs(n * 86_400);
        assert_eq!(renewal_delay(now + days(90), now), days(60));
        assert_eq!(renewal_delay(now - days(1), now), Duration::ZERO);
    }
}

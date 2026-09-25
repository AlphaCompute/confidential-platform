//! The client side of every platform TLS hop: TLS 1.3 with `X25519MLKEM768` and the server
//! pinned by value — a CA plus a Revision allowlist (join), the CA's SPKI hash plus a Revision
//! allowlist (the runtime, which holds only the hash), a CA alone (the admin CLI) or one exact
//! SPKI (the custodian CLI on a sealed node). The host name is only routing.

use std::sync::Arc;
use std::time::Duration;

use alpha_core::ComposeHash;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use parking_lot::RwLock;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::crypto::aws_lc_rs::{self, kx_group};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, TrustAnchor, UnixTime,
};
use rustls::server::danger::ClientCertVerifier;
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls::time_provider::TimeProvider;
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::Error;
use crate::runtime::RuntimeIdentity;

pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(CryptoProvider {
        kx_groups: vec![kx_group::X25519MLKEM768],
        ..aws_lc_rs::default_provider()
    })
}

/// The URI SAN every KMS node's leaf carries beside its Revision.
pub const KMS_SAN: &str = "alphacompute://kms";

/// What the server must prove, as a value.
#[derive(Clone, Debug)]
pub enum Pin {
    /// The chain ends at this CA.
    Ca(CertificateDer<'static>),
    /// The chain ends at this CA and the leaf carries one of these Revisions.
    CaAndRevisions(CertificateDer<'static>, Vec<ComposeHash>),
    /// The chain ends at this CA and the leaf is an App Instance's carrying one of these
    /// Revisions; an empty list matches nothing.
    CaAndInstanceRevisions(CertificateDer<'static>, Vec<ComposeHash>),
    /// The chain ends at a CA the server presents whose SPKI SHA-256 is these bytes, and the
    /// leaf carries one of these Revisions; an empty list matches nothing.
    CaSpkiAndRevisions([u8; 32], Vec<ComposeHash>),
    /// The leaf's SubjectPublicKeyInfo is exactly these bytes.
    Spki(Vec<u8>),
}

pub fn cert_from_pem(pem: &str) -> Result<CertificateDer<'static>, Error> {
    CertificateDer::from_pem_slice(pem.as_bytes())
        .map_err(|e| Error::Invalid(format!("certificate pem: {e}")))
}

/// The client's own certificate for mTLS hops: an Instance leaf or a node's self-signed one.
pub struct Identity {
    pub chain: Vec<Vec<u8>>,
    pub pkcs8: Vec<u8>,
}

/// `pin: None` accepts any certificate; it exists only to read a sealed node's evidence, whose
/// quote is what authenticates it, and the caller compares the observed SPKI with the attested key.
#[derive(Debug)]
struct PinnedServer {
    pin: Option<Pin>,
    anchor: Option<TrustAnchor<'static>>,
    provider: Arc<CryptoProvider>,
}

impl PinnedServer {
    fn new(pin: Option<Pin>) -> Result<Self, Error> {
        let anchor = match &pin {
            Some(Pin::Ca(ca) | Pin::CaAndRevisions(ca, _) | Pin::CaAndInstanceRevisions(ca, _)) => {
                Some(
                    webpki::anchor_from_trusted_cert(ca)
                        .map_err(|e| Error::Invalid(format!("pinned ca: {e}")))?
                        .to_owned(),
                )
            }
            Some(Pin::CaSpkiAndRevisions(..) | Pin::Spki(_)) | None => None,
        };
        Ok(Self {
            pin,
            anchor,
            provider: provider(),
        })
    }
}

impl ServerCertVerifier for PinnedServer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let refuse = |m: String| rustls::Error::General(m);
        let Some(pin) = &self.pin else {
            return Ok(ServerCertVerified::assertion());
        };
        let presented;
        let anchor = match pin {
            Pin::Ca(_) | Pin::CaAndRevisions(..) | Pin::CaAndInstanceRevisions(..) => Some(
                self.anchor
                    .as_ref()
                    .ok_or_else(|| refuse("pinned ca is not an anchor".into()))?,
            ),
            Pin::CaSpkiAndRevisions(sha256, _) => {
                let ca = intermediates
                    .iter()
                    .find(|c| spki_sha256(c).as_ref() == Some(sha256))
                    .ok_or_else(|| {
                        refuse(
                            "no certificate in the server chain carries the pinned ca key".into(),
                        )
                    })?;
                presented =
                    webpki::anchor_from_trusted_cert(ca).map_err(|e| refuse(e.to_string()))?;
                Some(&presented)
            }
            Pin::Spki(_) => None,
        };
        if let Some(anchor) = anchor {
            webpki::EndEntityCert::try_from(end_entity)
                .map_err(|e| refuse(e.to_string()))?
                .verify_for_usage(
                    self.provider.signature_verification_algorithms.all,
                    std::slice::from_ref(anchor),
                    intermediates,
                    now,
                    webpki::KeyUsage::server_auth(),
                    None,
                    None,
                )
                .map_err(|e| refuse(format!("server chain does not end at the pinned ca: {e}")))?;
        }
        match pin {
            Pin::Ca(_) => {}
            Pin::CaAndRevisions(_, revisions) | Pin::CaSpkiAndRevisions(_, revisions) => {
                let sans = uri_sans(end_entity).map_err(|e| refuse(e.to_string()))?;
                // An Instance leaf from the same CA also carries a Revision SAN and the
                // server-auth EKU; only a node's leaf carries the KMS identity.
                if !sans.iter().any(|s| s == KMS_SAN) {
                    return Err(refuse("server certificate is not a KMS node's".into()));
                }
                let allowed = revisions
                    .iter()
                    .map(|r| format!("urn:alphacompute:revision:{r}"))
                    .any(|urn| sans.contains(&urn));
                if !allowed {
                    return Err(refuse(
                        "server certificate carries no allowed KMS revision".into(),
                    ));
                }
            }
            Pin::CaAndInstanceRevisions(_, revisions) => {
                let sans = uri_sans(end_entity).map_err(|e| refuse(e.to_string()))?;
                let instance = parse_instance_sans(&sans).map_err(|e| refuse(e.to_string()))?;
                if !revisions.contains(&instance.compose_hash) {
                    return Err(refuse(
                        "server certificate carries no allowed App revision".into(),
                    ));
                }
            }
            Pin::Spki(spki) => {
                if spki_of(end_entity).map_err(|e| refuse(e.to_string()))? != *spki {
                    return Err(refuse(
                        "server key is not the pinned SubjectPublicKeyInfo".into(),
                    ));
                }
            }
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// `time` is the clock certificate validity is judged by; `main` passes
/// `rustls::time_provider::DefaultTimeProvider`, a test can pin it to a capture.
pub fn client_config(
    pin: Option<Pin>,
    identity: Option<Identity>,
    time: Arc<dyn TimeProvider>,
) -> Result<ClientConfig, Error> {
    let builder = ClientConfig::builder_with_details(provider(), time)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::Invalid(format!("tls: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedServer::new(pin)?));
    Ok(match identity {
        None => builder.with_no_client_auth(),
        Some(identity) => builder
            .with_client_auth_cert(
                identity
                    .chain
                    .into_iter()
                    .map(CertificateDer::from)
                    .collect(),
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.pkcs8)),
            )
            .map_err(|e| Error::Invalid(format!("client identity: {e}")))?,
    })
}

pub use alpha_channel::cert::{InstanceSans, parse_instance_sans, spki_of, spki_sha256, uri_sans};

fn certified_key(identity: &RuntimeIdentity) -> Result<Arc<CertifiedKey>, Error> {
    let chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(identity.certificate_chain.as_bytes())
            .collect::<Result<_, _>>()
            .map_err(|e| Error::Invalid(format!("certificate chain: {e}")))?;
    if chain.is_empty() {
        return Err(Error::Invalid("certificate chain is empty".into()));
    }
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.tls_private_key.to_vec()));
    let signing = provider()
        .key_provider
        .load_private_key(key)
        .map_err(|e| Error::Invalid(format!("runtime key: {e}")))?;
    Ok(Arc::new(CertifiedKey::new(chain, signing)))
}

/// The Endpoint's TLS key material, swapped whole on renewal so a handshake in flight during a
/// `replace` still sees one complete chain — old or new, never a mix.
#[derive(Debug)]
pub struct InstanceCert(RwLock<Arc<CertifiedKey>>);

impl InstanceCert {
    pub fn new(identity: &RuntimeIdentity) -> Result<Self, Error> {
        Ok(Self(RwLock::new(certified_key(identity)?)))
    }

    pub fn replace(&self, identity: &RuntimeIdentity) -> Result<(), Error> {
        let certified = certified_key(identity)?;
        *self.0.write() = certified;
        Ok(())
    }
}

impl ResolvesServerCert for InstanceCert {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.read().clone())
    }
}

/// The KMS CA: the last certificate of this Instance's own chain, which `alpha-runtime` already
/// checked against the measured one, so a CA rotation needs only a restart.
pub fn kms_ca(identity: &RuntimeIdentity) -> Result<CertificateDer<'static>, Error> {
    CertificateDer::pem_slice_iter(identity.certificate_chain.as_bytes())
        .last()
        .ok_or_else(|| Error::Invalid("certificate chain is empty".into()))?
        .map_err(|e| Error::Invalid(format!("certificate chain: {e}")))
}

/// TLS 1.3 only, `http/1.1`, the client judged by `verifier`, the server's chain from `cert`.
fn listener(
    cert: Arc<dyn ResolvesServerCert>,
    verifier: Arc<dyn ClientCertVerifier>,
) -> Result<Arc<ServerConfig>, Error> {
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::Invalid(format!("tls: {e}")))?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(cert);
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// An Endpoint listener over `cert` with no client auth.
pub fn server_config(cert: Arc<InstanceCert>) -> Result<Arc<ServerConfig>, Error> {
    listener(cert, WebPkiClientVerifier::no_client_auth())
}

/// As [`server_config`], but a client certificate is requested, not required: one that is
/// presented must chain to `kms_ca` or the handshake fails, and each route decides from
/// [`PeerCerts`] whether it needs one.
pub fn mtls_server_config(
    cert: Arc<dyn ResolvesServerCert>,
    kms_ca: CertificateDer<'static>,
) -> Result<Arc<ServerConfig>, Error> {
    let tls = |e: &dyn std::fmt::Display| Error::Invalid(format!("tls: {e}"));
    let mut roots = RootCertStore::empty();
    roots.add(kms_ca).map_err(|e| tls(&e))?;
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider())
        .allow_unauthenticated()
        .build()
        .map_err(|e| tls(&e))?;
    listener(cert, verifier)
}

/// The certificate chain the peer presented, if any; each route decides what it needs of it.
#[derive(Clone, Debug, Default)]
pub struct PeerCerts(pub Vec<CertificateDer<'static>>);

const HANDSHAKE: Duration = Duration::from_secs(10);

/// Accepts until `shutdown` resolves, then drains the open connections. Each request carries
/// the peer's chain as a [`PeerCerts`] extension.
pub async fn serve(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    app: axum::Router,
    shutdown: impl Future<Output = ()>,
) {
    let acceptor = TlsAcceptor::from(config);
    let graceful = GracefulShutdown::new();
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        let (stream, _) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                // Out of descriptors, accept fails at once until one frees up.
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
            () = &mut shutdown => break,
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        let watcher = graceful.watcher();
        tokio::spawn(async move {
            let Ok(Ok(tls)) = tokio::time::timeout(HANDSHAKE, acceptor.accept(stream)).await else {
                return;
            };
            let peer = PeerCerts(
                tls.get_ref()
                    .1
                    .peer_certificates()
                    .map(|c| c.to_vec())
                    .unwrap_or_default(),
            );
            let service = TowerToHyperService::new(app.layer(axum::Extension(peer)));
            let mut builder = Builder::new(TokioExecutor::new());
            // hyper's header-read timeout only runs once it has a timer.
            builder.http1().timer(TokioTimer::new());
            let conn = builder.serve_connection(TokioIo::new(tls), service);
            let _ = watcher.watch(conn).await;
        });
    }
    graceful.shutdown().await;
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use alpha_attest::{AttestationResult, Measured, Measurement, Revision, Verdict};
    use alpha_core::{AppId, OrgId};
    use rcgen::string::Ia5String;
    use rcgen::{
        BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, SanType, SerialNumber,
    };
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::{TlsAcceptor, TlsConnector};
    use x509_parser::prelude::{FromDer, X509Certificate};
    use zeroize::Zeroizing;

    use super::*;

    fn dummy_attestation() -> AttestationResult {
        let m = Measurement([0u8; 48]);
        AttestationResult {
            format: "test".into(),
            verdict: Verdict::Verified,
            measured: Measured {
                mrtd: m,
                rtmr0: m,
                rtmr1: m,
                rtmr2: m,
                rtmr3: m,
            },
            tcb_status: "UpToDate".into(),
            advisories: Vec::new(),
            os_image: "test".into(),
            revision: Revision {
                compose_hash: alpha_core::compose_hash("test"),
                app_id: AppId::mint(),
                org_id: OrgId::mint(),
            },
            runtime_pubkey_sha256: format!("sha256:{}", "0".repeat(64)),
            evidence_sha256: format!("sha256:{}", "0".repeat(64)),
            verified_at: "1970-01-01T00:00:00Z".into(),
            policy_version: 1,
        }
    }

    fn new_ca() -> (KeyPair, rcgen::Certificate) {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.not_before = (SystemTime::now() - Duration::from_secs(3600)).into();
        params.not_after = (SystemTime::now() + Duration::from_secs(3600)).into();
        let cert = params.self_signed(&key).unwrap();
        (key, cert)
    }

    /// A leaf under `ca`, one URI SAN, its own key, and a one-byte serial to tell it apart from
    /// a sibling leaf.
    fn new_leaf(ca_key: &KeyPair, ca_cert: &rcgen::Certificate, serial: u8) -> RuntimeIdentity {
        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let issuer = Issuer::from_ca_cert_der(ca_cert.der(), ca_key).unwrap();
        let mut params = CertificateParams::default();
        let san = format!(
            "urn:alphacompute:revision:sha256:{}{serial:02x}",
            "0".repeat(62)
        );
        params.subject_alt_names = vec![SanType::URI(Ia5String::try_from(san).unwrap())];
        params.serial_number = Some(SerialNumber::from(vec![serial]));
        params.not_before = (SystemTime::now() - Duration::from_secs(3600)).into();
        params.not_after = (SystemTime::now() + Duration::from_secs(3600)).into();
        let cert = params.signed_by(&leaf_key, &issuer).unwrap();
        RuntimeIdentity {
            app_id: AppId::mint(),
            org_id: OrgId::mint(),
            compose_hash: alpha_core::compose_hash("test"),
            certificate_chain: format!("{}\n{}", cert.pem(), ca_cert.pem()),
            tls_private_key: Zeroizing::new(leaf_key.serialize_der()),
            attestation_result: dummy_attestation(),
        }
    }

    fn client_config_for(ca_cert: &rcgen::Certificate) -> Arc<ClientConfig> {
        let ca = CertificateDer::from(ca_cert.der().to_vec());
        Arc::new(
            crate::tls::client_config(
                Some(crate::tls::Pin::Ca(ca)),
                None,
                crate::system_time_provider(),
            )
            .unwrap(),
        )
    }

    /// The one-byte serial number the leaf was minted with.
    fn served_serial(chain: &[CertificateDer<'_>]) -> u8 {
        let leaf = chain.first().expect("a served chain has a leaf");
        let (_, cert) = X509Certificate::from_der(leaf).unwrap();
        *cert.raw_serial().last().expect("a nonempty serial")
    }

    async fn handshake(addr: std::net::SocketAddr, ca_cert: &rcgen::Certificate) -> u8 {
        let tcp = TcpStream::connect(addr).await.unwrap();
        let connector = TlsConnector::from(client_config_for(ca_cert));
        let tls = connector
            .connect(ServerName::try_from("app.example").unwrap(), tcp)
            .await
            .unwrap();
        served_serial(tls.get_ref().1.peer_certificates().unwrap())
    }

    fn leaf_with_sans(
        ca_key: &KeyPair,
        ca_cert: &rcgen::Certificate,
        sans: &[String],
    ) -> RuntimeIdentity {
        let mut identity = new_leaf(ca_key, ca_cert, 1);
        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let issuer = Issuer::from_ca_cert_der(ca_cert.der(), ca_key).unwrap();
        let mut params = CertificateParams::default();
        params.subject_alt_names = sans
            .iter()
            .map(|s| SanType::URI(Ia5String::try_from(s.as_str()).unwrap()))
            .collect();
        params.not_before = (SystemTime::now() - Duration::from_secs(3600)).into();
        params.not_after = (SystemTime::now() + Duration::from_secs(3600)).into();
        let cert = params.signed_by(&leaf_key, &issuer).unwrap();
        identity.certificate_chain = format!("{}\n{}", cert.pem(), ca_cert.pem());
        identity.tls_private_key = Zeroizing::new(leaf_key.serialize_der());
        identity
    }

    async fn pinned_handshake(identity: &RuntimeIdentity, pin: Pin) -> bool {
        let cert = Arc::new(InstanceCert::new(identity).unwrap());
        let acceptor = TlsAcceptor::from(server_config(cert).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((tcp, _)) = listener.accept().await {
                let _ = acceptor.accept(tcp).await;
            }
        });
        let config = client_config(Some(pin), None, crate::system_time_provider()).unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from("app.example").unwrap(), tcp)
            .await
            .is_ok()
    }

    #[tokio::test]
    async fn an_instance_revision_pin_accepts_only_an_app_leaf_carrying_a_listed_revision() {
        let (ca_key, ca_cert) = new_ca();
        let ca = CertificateDer::from(ca_cert.der().to_vec());
        let revision = alpha_core::compose_hash("front");
        let instance = format!(
            "alphacompute://{}/{}/{}",
            OrgId::mint(),
            AppId::mint(),
            "a".repeat(64)
        );
        let revision_san = format!("urn:alphacompute:revision:{revision}");
        let app = leaf_with_sans(&ca_key, &ca_cert, &[instance, revision_san.clone()]);
        let node = leaf_with_sans(&ca_key, &ca_cert, &[KMS_SAN.into(), revision_san]);
        let pin = |revisions| Pin::CaAndInstanceRevisions(ca.clone(), revisions);

        assert!(pinned_handshake(&app, pin(vec![revision])).await);
        assert!(!pinned_handshake(&app, pin(vec![alpha_core::compose_hash("other")])).await);
        assert!(!pinned_handshake(&app, pin(vec![])).await);
        assert!(!pinned_handshake(&node, pin(vec![revision])).await);
        let (_, other_ca) = new_ca();
        let foreign = Pin::CaAndInstanceRevisions(other_ca.der().clone(), vec![revision]);
        assert!(!pinned_handshake(&app, foreign).await);
    }

    #[tokio::test]
    async fn replace_serves_the_new_leaf_and_never_a_torn_chain_to_a_concurrent_handshake() {
        let (ca_key, ca_cert) = new_ca();
        let identity1 = new_leaf(&ca_key, &ca_cert, 1);
        let identity2 = new_leaf(&ca_key, &ca_cert, 2);

        let cert = Arc::new(InstanceCert::new(&identity1).unwrap());
        let acceptor = TlsAcceptor::from(server_config(cert.clone()).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(mut tls) = acceptor.accept(tcp).await {
                        let _ = tokio::io::AsyncWriteExt::shutdown(&mut tls).await;
                    }
                });
            }
        });

        // Before the swap, only the first leaf is ever served.
        assert_eq!(handshake(addr, &ca_cert).await, 1);

        // A burst of handshakes races the swap; each sees one whole chain, never a mix of the
        // two — the resolver swaps a single Arc under a lock, so there is nothing to tear.
        let swap = {
            let cert = cert.clone();
            tokio::spawn(async move { cert.replace(&identity2).unwrap() })
        };
        let mut handles = Vec::new();
        for _ in 0..8 {
            let ca_cert = ca_cert.clone();
            handles.push(tokio::spawn(async move { handshake(addr, &ca_cert).await }));
        }
        swap.await.unwrap();
        for h in handles {
            let serial = h.await.unwrap();
            assert!(serial == 1 || serial == 2, "{serial}: neither known leaf");
        }

        // After the swap, only the second leaf is served.
        assert_eq!(handshake(addr, &ca_cert).await, 2);
    }
}

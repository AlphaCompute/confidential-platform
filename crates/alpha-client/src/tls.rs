//! The client side of every platform TLS hop: TLS 1.3 with `X25519MLKEM768` and the server
//! pinned by value — a CA plus a Revision allowlist (join), the CA's SPKI hash plus a Revision
//! allowlist (the runtime, which holds only the hash), a CA alone (the admin CLI) or one exact
//! SPKI (the custodian CLI on a sealed node). The host name is only routing.

use std::sync::Arc;

use alpha_core::{AppId, ComposeHash, OrgId};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::crypto::aws_lc_rs::{self, kx_group};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, TrustAnchor, UnixTime,
};
use rustls::time_provider::TimeProvider;
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, GeneralName, ParsedExtension, X509Certificate};

use crate::Error;

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
            Some(Pin::Ca(ca) | Pin::CaAndRevisions(ca, _)) => Some(
                webpki::anchor_from_trusted_cert(ca)
                    .map_err(|e| Error::Invalid(format!("pinned ca: {e}")))?
                    .to_owned(),
            ),
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
            Pin::Ca(_) | Pin::CaAndRevisions(..) => Some(
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

pub fn uri_sans(cert: &[u8]) -> Result<Vec<String>, Error> {
    let (_, cert) =
        X509Certificate::from_der(cert).map_err(|e| Error::Invalid(format!("certificate: {e}")))?;
    Ok(cert
        .extensions()
        .iter()
        .filter_map(|ext| match ext.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => Some(&san.general_names),
            _ => None,
        })
        .flatten()
        .filter_map(|name| match name {
            GeneralName::URI(uri) => Some((*uri).to_owned()),
            _ => None,
        })
        .collect())
}

pub fn spki_of(cert: &[u8]) -> Result<Vec<u8>, Error> {
    let (_, cert) =
        X509Certificate::from_der(cert).map_err(|e| Error::Invalid(format!("certificate: {e}")))?;
    Ok(cert.public_key().raw.to_vec())
}

pub fn spki_sha256(cert: &[u8]) -> Option<[u8; 32]> {
    spki_of(cert).ok().map(|spki| Sha256::digest(spki).into())
}

/// The identity an Instance certificate carries: `alphacompute://<org>/<app>/<key sha256>`
/// then `urn:alphacompute:revision:sha256:<hex>`, in the order the KMS issues them.
#[derive(Clone, Debug)]
pub struct InstanceSans {
    pub org_id: OrgId,
    pub app_id: AppId,
    pub runtime_pubkey_sha256_hex: String,
    pub compose_hash: ComposeHash,
}

pub fn parse_instance_sans(sans: &[String]) -> Result<InstanceSans, Error> {
    let invalid = || Error::Invalid("certificate SANs are not an Instance's".into());
    let [identity, revision] = sans else {
        return Err(invalid());
    };
    let parts: Vec<&str> = identity
        .strip_prefix("alphacompute://")
        .ok_or_else(invalid)?
        .split('/')
        .collect();
    let [org, app, key] = parts[..] else {
        return Err(invalid());
    };
    let compose_hash = revision
        .strip_prefix("urn:alphacompute:revision:")
        .and_then(|s| s.parse().ok())
        .ok_or_else(invalid)?;
    Ok(InstanceSans {
        org_id: org.parse().map_err(|_| invalid())?,
        app_id: app.parse().map_err(|_| invalid())?,
        runtime_pubkey_sha256_hex: alpha_core::hex_bytes::<32>(key)
            .map(|_| key.to_owned())
            .ok_or_else(invalid)?,
        compose_hash,
    })
}

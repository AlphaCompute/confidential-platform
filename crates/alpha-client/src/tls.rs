//! The client side of every platform TLS hop: TLS 1.3 with `X25519MLKEM768` and the server
//! pinned by value — a CA plus a Revision allowlist (runtime, join), a CA alone (the admin CLI)
//! or one exact SPKI (the custodian CLI on a sealed node). The host name is only routing.

use std::sync::Arc;

use alpha_core::ComposeHash;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::crypto::aws_lc_rs::{self, kx_group};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, TrustAnchor, UnixTime,
};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use x509_parser::prelude::{FromDer, GeneralName, ParsedExtension, X509Certificate};

use crate::Error;

pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(CryptoProvider {
        kx_groups: vec![kx_group::X25519MLKEM768],
        ..aws_lc_rs::default_provider()
    })
}

/// What the server must prove, as a value.
#[derive(Clone, Debug)]
pub enum Pin {
    /// The chain ends at this CA.
    Ca(CertificateDer<'static>),
    /// The chain ends at this CA and the leaf carries one of these Revisions.
    CaAndRevisions(CertificateDer<'static>, Vec<ComposeHash>),
    /// The leaf's SubjectPublicKeyInfo is exactly these bytes.
    Spki(Vec<u8>),
}

pub fn ca_from_pem(pem: &str) -> Result<CertificateDer<'static>, Error> {
    CertificateDer::from_pem_slice(pem.as_bytes())
        .map_err(|e| Error::Invalid(format!("ca pem: {e}")))
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
            Some(Pin::Spki(_)) | None => None,
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
        if let Some(anchor) = &self.anchor {
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
            Pin::CaAndRevisions(_, revisions) => {
                let sans = uri_sans(end_entity).map_err(|e| refuse(e.to_string()))?;
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

pub fn client_config(pin: Option<Pin>, identity: Option<Identity>) -> Result<ClientConfig, Error> {
    let builder = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 is supported")
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

//! One round trip. The initiator sends a fresh X-Wing key and a nonce; the responder, an Instance,
//! encapsulates to that key with HPKE and signs the exchange with its leaf key, returning its
//! certificate chain and the exact compose it runs. The initiator derives keys only after the CA,
//! the leaf, its SANs, the Revision allowlist, the compose and the signature all check out; both
//! direction keys come from the HPKE exporter.

use std::fmt;
use std::time::SystemTime;

use alpha_core::{AppId, ComposeHash, OrgId, context, signing_digest};
use alpha_crypto::{KEM_NAME, PrivateKey};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use chrono::DateTime;
use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha256;
use hpke::kem::XWing;
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePublicKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::cert::{parse_instance_sans, pem_to_der, spki_of, uri_sans, verify_leaf};
use crate::frame::Channel;
use crate::{
    ECDSA_P256, Error, NamedSignature, from_unix_seconds, p256_signature, random, rfc3339,
    sha256_label,
};

pub const VERSION: u8 = 1;

const C2S: &[u8] = b"alphacompute/inner-channel/v1 c2s";
const S2C: &[u8] = b"alphacompute/inner-channel/v1 s2c";

/// `{ "v": 1, "kem": "x-wing", "pk": "<base64url>", "nonce": "<base64url, 32 bytes>" }`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientHello {
    pub v: u8,
    pub kem: String,
    pub pk: String,
    pub nonce: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerHello {
    pub v: u8,
    pub channel: String,
    pub enc: String,
    pub now: String,
    /// The leaf PEM, then the CA PEM.
    pub certificate_chain: Vec<String>,
    /// `app-compose.json`, the exact bytes whose SHA-256 is the Revision.
    pub compose: String,
    pub signature: NamedSignature,
}

/// Who the initiator means to reach: one App of one organization, at one of these Revisions.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expected {
    pub org_id: OrgId,
    pub app_id: AppId,
    pub revisions: Vec<ComposeHash>,
}

/// What the initiator verified; everything here comes from the certificate or the compose.
#[derive(Clone, Debug)]
pub struct Verified {
    pub org_id: OrgId,
    pub app_id: AppId,
    pub compose_hash: ComposeHash,
    /// SHA-256 of the leaf's SPKI, the Instance key a grant names.
    pub aud: [u8; 32],
    pub not_before: SystemTime,
    pub not_after: SystemTime,
    pub kms_ca_sha256: [u8; 32],
    pub compose: String,
    /// The responder's clock, as it signed it.
    pub now: SystemTime,
}

fn info(nonce: &[u8; 32]) -> Vec<u8> {
    [context::INNER_CHANNEL.as_bytes(), &[0u8], nonce].concat()
}

fn signed_document(
    channel: &str,
    nonce: &str,
    client_pk: &[u8],
    enc: &[u8],
    compose_hash: &ComposeHash,
    now: &str,
) -> Value {
    json!({
        "v": VERSION,
        "channel": channel,
        "nonce": nonce,
        "client_pk_sha256": sha256_label(client_pk),
        "enc_sha256": sha256_label(enc),
        "compose_hash": compose_hash.to_string(),
        "now": now,
    })
}

fn digest(document: &Value) -> Result<[u8; 32], Error> {
    signing_digest(context::INNER_CHANNEL, document)
        .map_err(|e| Error::Malformed(format!("handshake document: {e}")))
}

fn channel<E>(id: &[u8; 16], export: E) -> Result<Channel, Error>
where
    E: Fn(&[u8], &mut [u8]) -> Result<(), hpke::HpkeError>,
{
    let mut c2s = Zeroizing::new([0u8; 32]);
    let mut s2c = Zeroizing::new([0u8; 32]);
    export(C2S, c2s.as_mut()).map_err(|_| Error::Seal)?;
    export(S2C, s2c.as_mut()).map_err(|_| Error::Seal)?;
    Ok(Channel::new(id, c2s, s2c))
}

fn decode<const N: usize>(field: &str, text: &str) -> Result<[u8; N], Error> {
    BASE64_URL_SAFE_NO_PAD
        .decode(text)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| Error::Malformed(format!("{field} is not {N} bytes of base64url")))
}

pub struct Initiator {
    key: PrivateKey,
    nonce: [u8; 32],
}

impl fmt::Debug for Initiator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Initiator(..)")
    }
}

impl Initiator {
    pub fn new() -> Result<(Self, ClientHello), Error> {
        let key = PrivateKey::generate().map_err(|_| Error::Rng)?;
        let pk = key.public();
        let nonce = random::<32>()?;
        let hello = ClientHello {
            v: VERSION,
            kem: KEM_NAME.into(),
            pk: BASE64_URL_SAFE_NO_PAD.encode(pk.as_bytes()),
            nonce: BASE64_URL_SAFE_NO_PAD.encode(nonce),
        };
        Ok((Self { key, nonce }, hello))
    }

    /// `kms_ca_pem` is the verified platform document's; `now` is the initiator's own clock.
    pub fn finish(
        self,
        hello: &ServerHello,
        kms_ca_pem: &str,
        expected: &Expected,
        now: SystemTime,
    ) -> Result<(Channel, Verified), Error> {
        if hello.v != VERSION {
            return Err(Error::Malformed(format!("version {}", hello.v)));
        }
        let channel_id = decode::<16>("channel", &hello.channel)?;
        let enc = BASE64_URL_SAFE_NO_PAD
            .decode(&hello.enc)
            .map_err(|_| Error::Malformed("enc is not base64url".into()))?;
        let responder_now = DateTime::parse_from_rfc3339(&hello.now)
            .ok()
            .and_then(|t| from_unix_seconds(t.timestamp()))
            .ok_or_else(|| Error::Malformed("now is not RFC 3339 after 1970".into()))?;
        let [leaf_pem, ca_pem] = hello.certificate_chain.as_slice() else {
            return Err(Error::ForeignCertificate(
                "the chain is not exactly a leaf and the KMS CA".into(),
            ));
        };

        let kms_ca = pem_to_der(kms_ca_pem)?;
        let foreign = |m: &str| Error::ForeignCertificate(m.into());
        if pem_to_der(ca_pem).ok().as_ref() != Some(&kms_ca) {
            return Err(foreign("the chain's CA is not the platform's KMS CA"));
        }
        let leaf = pem_to_der(leaf_pem).map_err(|_| foreign("the leaf is not a certificate"))?;
        let (not_before, not_after) = verify_leaf(&leaf, &kms_ca, now)?;

        let sans = parse_instance_sans(&uri_sans(&leaf)?)?;
        if sans.org_id != expected.org_id || sans.app_id != expected.app_id {
            return Err(foreign("the certificate names another organization or app"));
        }
        if !expected.revisions.contains(&sans.compose_hash) {
            return Err(Error::UnknownRevision(sans.compose_hash));
        }
        if alpha_core::compose_hash(&hello.compose) != sans.compose_hash {
            return Err(Error::ComposeMismatch);
        }

        let refuse = |m: &str| Error::HandshakeSignature(format!("handshake: {m}"));
        if hello.signature.algorithm != ECDSA_P256 {
            return Err(refuse("algorithm is not ecdsa-p256"));
        }
        let leaf_spki = spki_of(&leaf)?;
        let key = VerifyingKey::from_public_key_der(&leaf_spki)
            .map_err(|_| refuse("the leaf key is not P-256"))?;
        let signature = p256_signature(&hello.signature.signature)
            .ok_or_else(|| refuse("signature is not base64url r‖s"))?;
        let document = signed_document(
            &hello.channel,
            &BASE64_URL_SAFE_NO_PAD.encode(self.nonce),
            self.key.public().as_bytes(),
            &enc,
            &sans.compose_hash,
            &hello.now,
        );
        key.verify(&digest(&document)?, &signature)
            .map_err(|_| refuse("signature does not verify under the leaf key"))?;

        let enc = <XWing as Kem>::EncappedKey::from_bytes(&enc)
            .map_err(|_| refuse("enc is not an X-Wing encapsulation"))?;
        let sk = <XWing as Kem>::PrivateKey::from_bytes(self.key.seed().as_ref())
            .map_err(|_| Error::Rng)?;
        let ctx = hpke::setup_receiver::<AesGcm256, HkdfSha256, XWing>(
            &OpModeR::Base,
            &sk,
            &enc,
            &info(&self.nonce),
        )
        .map_err(|_| refuse("enc does not decapsulate"))?;
        let channel = channel(&channel_id, |label, out| ctx.export(label, out))?;

        Ok((
            channel,
            Verified {
                org_id: sans.org_id,
                app_id: sans.app_id,
                compose_hash: sans.compose_hash,
                aud: Sha256::digest(&leaf_spki).into(),
                not_before,
                not_after,
                kms_ca_sha256: Sha256::digest(&kms_ca).into(),
                compose: hello.compose.clone(),
                now: responder_now,
            },
        ))
    }
}

/// The Instance's end: its chain, its leaf key and the compose the leaf's Revision is the hash of.
pub struct Responder {
    certificate_chain: Vec<String>,
    key: SigningKey,
    compose: String,
    compose_hash: ComposeHash,
}

impl fmt::Debug for Responder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Responder({})", self.compose_hash)
    }
}

impl Responder {
    /// Refuses a chain that is not a leaf and a CA, a key that is not the leaf's, and a compose
    /// that is not the leaf's Revision, so a misconfigured Instance fails here and not in every
    /// client.
    pub fn new(
        certificate_chain_pem: Vec<String>,
        tls_private_key_pkcs8: &[u8],
        compose: String,
    ) -> Result<Self, Error> {
        let [leaf_pem, _ca] = certificate_chain_pem.as_slice() else {
            return Err(Error::Malformed(
                "the chain is not exactly a leaf and a CA".into(),
            ));
        };
        let leaf = pem_to_der(leaf_pem)?;
        let key = SigningKey::from_pkcs8_der(tls_private_key_pkcs8)
            .map_err(|_| Error::Malformed("the private key is not P-256 PKCS#8".into()))?;
        let public = key
            .verifying_key()
            .to_public_key_der()
            .map_err(|_| Error::Malformed("the public key does not encode".into()))?;
        if spki_of(&leaf)? != public.as_bytes() {
            return Err(Error::Malformed("the private key is not the leaf's".into()));
        }
        let compose_hash = parse_instance_sans(&uri_sans(&leaf)?)?.compose_hash;
        if alpha_core::compose_hash(&compose) != compose_hash {
            return Err(Error::ComposeMismatch);
        }
        Ok(Self {
            certificate_chain: certificate_chain_pem,
            key,
            compose,
            compose_hash,
        })
    }

    pub fn respond(
        &self,
        hello: &ClientHello,
        now: SystemTime,
    ) -> Result<(ServerHello, Channel), Error> {
        if hello.v != VERSION {
            return Err(Error::Malformed(format!("version {}", hello.v)));
        }
        if hello.kem != KEM_NAME {
            return Err(Error::Malformed(format!("kem {:?}", hello.kem)));
        }
        let pk_bytes = BASE64_URL_SAFE_NO_PAD
            .decode(&hello.pk)
            .map_err(|_| Error::Malformed("pk is not base64url".into()))?;
        let pk = <XWing as Kem>::PublicKey::from_bytes(&pk_bytes)
            .map_err(|_| Error::Malformed("pk is not an X-Wing public key".into()))?;
        let nonce = decode::<32>("nonce", &hello.nonce)?;
        let channel_id = random::<16>()?;
        let channel_b64 = BASE64_URL_SAFE_NO_PAD.encode(channel_id);
        let now = rfc3339(now)?;

        let (enc, ctx) =
            hpke::setup_sender::<AesGcm256, HkdfSha256, XWing>(&OpModeS::Base, &pk, &info(&nonce))
                .map_err(|_| Error::Seal)?;
        let enc = enc.to_bytes();
        let document = signed_document(
            &channel_b64,
            &hello.nonce,
            &pk_bytes,
            &enc,
            &self.compose_hash,
            &now,
        );
        let signature: Signature = self
            .key
            .try_sign(&digest(&document)?)
            .map_err(|_| Error::Seal)?;
        let keys = channel(&channel_id, |label, out| ctx.export(label, out))?;

        Ok((
            ServerHello {
                v: VERSION,
                channel: channel_b64,
                enc: BASE64_URL_SAFE_NO_PAD.encode(enc),
                now,
                certificate_chain: self.certificate_chain.clone(),
                compose: self.compose.clone(),
                signature: NamedSignature {
                    algorithm: ECDSA_P256.into(),
                    signature: BASE64_URL_SAFE_NO_PAD.encode(signature.to_bytes()),
                },
            },
            keys,
        ))
    }
}

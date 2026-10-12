//! OCSP (RFC 6960) for every certificate a chain's revocation depends on: in a device chain every
//! certificate between the leaf and the root (the leaf is issued by the device itself, so NVIDIA's
//! OCSP service does not know it), in a RIM signing chain every certificate but the root (the
//! SDK's `X509CertChain::collect_ocsp_responses`).
//!
//! A response counts only if it is signed (ECDSA) either by the issuer of the
//! certificate it is about or by a responder certificate that issuer issued for OCSP signing
//! (`id-kp-OCSPSigning`, RFC 6960 §4.2.2.2), with a P-384 key (SHA-384 or, as NVIDIA's RIM-side
//! responder certificates are, SHA-256), names that certificate by a SHA-256 or SHA-384
//! `CertID`, is no older than the policy's maximum age and not past its `nextUpdate`, and says
//! `good`. `revoked` and `unknown` refuse. `certificateHold` refuses too unless the release-signed
//! `gpu_policy` accepts it: NVIDIA's RIM service still serves RIMs whose signing certificate is
//! on hold (seen on `NV_GPU_VBIOS_G525_0220_886_970088000F`, 2026-10-12), so that choice is
//! the release's, made per document, never a default.
//!
//! Responses come from the offline-refreshed cache or, when the policy pins an endpoint, from an
//! online query bound to a fresh OCSP nonce; this module only verifies them.

use std::time::Duration;

use der::asn1::ObjectIdentifier;
use der::{Decode, Encode};
use sha2::{Digest, Sha256, Sha384};
use x509_cert::Certificate;
use x509_cert::ext::pkix::CrlReason;
use x509_ocsp::{
    BasicOcspResponse, CertId, CertStatus, OcspResponse, OcspResponseStatus, ResponderId,
};

use super::cert::{self, ID_KP_OCSP_SIGNING, describe};
use super::{Result, refuse};

pub const MAX_RESPONSE_DER: usize = 16 * 1024;
/// Clock skew tolerated on `thisUpdate` and `producedAt`.
pub const CLOCK_SKEW: Duration = Duration::from_secs(60);
const ID_PKIX_OCSP_BASIC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.1");
const ID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const ID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");

/// What the policy requires of a response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Freshness {
    /// A response whose `thisUpdate` is older than this is refused.
    pub max_age: Duration,
    /// Whether `certificateHold` counts as good (release decision; default no).
    pub accept_certificate_hold: bool,
}

/// What a reliable response says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Good,
    /// Revoked (beyond an accepted hold) or unknown, with the reason.
    Bad(String),
}

/// Whether `cert` (issued by `issuer`) is good by the responses given: refused if any reliable
/// response about it says revoked or unknown, accepted if at least one says good, refused
/// otherwise with the reason the last response could not be relied on.
pub fn require_good<'a>(
    responses: impl IntoIterator<Item = &'a Response>,
    cert: &Certificate,
    issuer: &Certificate,
    now: Duration,
    freshness: Freshness,
) -> Result<()> {
    let mut good = false;
    let mut last = None;
    for response in responses {
        if !response.is_about(cert, issuer) {
            continue;
        }
        match response.status(cert, issuer, now, freshness) {
            Ok(Status::Good) => good = true,
            Ok(Status::Bad(why)) => return refuse(why),
            Err(e) => last = Some(e),
        }
    }
    if good {
        return Ok(());
    }
    Err(last.unwrap_or_else(|| super::Refused(format!("ocsp: no status for {}", describe(cert)))))
}

/// A parsed response: its basic response, ready to be checked for any certificate.
#[derive(Clone, Debug)]
pub struct Response {
    basic: BasicOcspResponse,
    tbs: Vec<u8>,
}

/// Parses an `OCSPResponse`; only a successful basic response is accepted.
pub fn parse(der: &[u8]) -> Result<Response> {
    if der.len() > MAX_RESPONSE_DER {
        return refuse(format!(
            "ocsp: response is {} bytes, more than {MAX_RESPONSE_DER}",
            der.len()
        ));
    }
    let response =
        OcspResponse::from_der(der).or_else(|e| refuse(format!("ocsp: does not parse: {e}")))?;
    if response.response_status != OcspResponseStatus::Successful {
        return refuse(format!(
            "ocsp: response status is {:?}",
            response.response_status
        ));
    }
    let bytes = response
        .response_bytes
        .ok_or_else(|| super::Refused("ocsp: successful response has no body".into()))?;
    if bytes.response_type != ID_PKIX_OCSP_BASIC {
        return refuse("ocsp: response is not a basic OCSP response");
    }
    let basic = BasicOcspResponse::from_der(bytes.response.as_bytes())
        .or_else(|e| refuse(format!("ocsp: basic response does not parse: {e}")))?;
    let tbs = basic
        .tbs_response_data
        .to_der()
        .or_else(|e| refuse(format!("ocsp: {e}")))?;
    Ok(Response { basic, tbs })
}

impl Response {
    /// How long ago the responder produced this response.
    pub fn age(&self, now: Duration) -> Duration {
        now.saturating_sub(
            self.basic
                .tbs_response_data
                .produced_at
                .0
                .to_unix_duration(),
        )
    }

    /// The nonce the response echoes, if any.
    pub fn nonce(&self) -> Option<Vec<u8>> {
        self.basic.nonce().map(|n| n.0.as_bytes().to_vec())
    }

    /// Whether this response has a status for `cert` (issued by `issuer`), by `CertID`.
    pub fn is_about(&self, cert: &Certificate, issuer: &Certificate) -> bool {
        self.basic
            .tbs_response_data
            .responses
            .iter()
            .any(|single| cert_id_matches(&single.cert_id, cert, issuer).unwrap_or(false))
    }

    /// Checks that `cert`, issued by `issuer`, is `good` according to this response at `now`.
    pub fn check(
        &self,
        cert: &Certificate,
        issuer: &Certificate,
        now: Duration,
        freshness: Freshness,
    ) -> Result<()> {
        match self.status(cert, issuer, now, freshness)? {
            Status::Good => Ok(()),
            Status::Bad(why) => Err(super::Refused(why)),
        }
    }

    /// What this response, once its signature, `CertID` and freshness hold, says of `cert`:
    /// `Err` when it cannot be relied on at all, [`Status::Bad`] when it reliably refuses.
    pub fn status(
        &self,
        cert: &Certificate,
        issuer: &Certificate,
        now: Duration,
        freshness: Freshness,
    ) -> Result<Status> {
        let who = describe(cert);
        let mut matching = self
            .basic
            .tbs_response_data
            .responses
            .iter()
            .filter(|single| cert_id_matches(&single.cert_id, cert, issuer).unwrap_or(false));
        let single = matching
            .next()
            .ok_or_else(|| super::Refused(format!("ocsp: no status for {who}")))?;
        if matching.next().is_some() {
            return refuse(format!("ocsp: two statuses for {who}"));
        }
        self.verify_signer(issuer, now)?;

        let produced = self
            .basic
            .tbs_response_data
            .produced_at
            .0
            .to_unix_duration();
        let this_update = single.this_update.0.to_unix_duration();
        if this_update > now.saturating_add(CLOCK_SKEW) || produced > now.saturating_add(CLOCK_SKEW)
        {
            return refuse(format!("ocsp: status for {who} is from the future"));
        }
        if now.saturating_sub(this_update) > freshness.max_age {
            return refuse(format!(
                "ocsp: status for {who} is {}s old, more than the policy's {}s",
                now.saturating_sub(this_update).as_secs(),
                freshness.max_age.as_secs()
            ));
        }
        if let Some(next) = single.next_update
            && now > next.0.to_unix_duration()
        {
            return refuse(format!("ocsp: status for {who} is past its nextUpdate"));
        }
        Ok(match &single.cert_status {
            CertStatus::Good(_) => Status::Good,
            CertStatus::Revoked(info)
                if info.revocation_reason == Some(CrlReason::CertificateHold)
                    && freshness.accept_certificate_hold =>
            {
                Status::Good
            }
            CertStatus::Revoked(info) => Status::Bad(format!(
                "ocsp: {who} is revoked ({})",
                info.revocation_reason
                    .map_or_else(|| "no reason given".to_owned(), |r| format!("{r:?}"))
            )),
            CertStatus::Unknown(_) => {
                Status::Bad(format!("ocsp: {who} is unknown to its responder"))
            }
        })
    }

    /// The response is signed by `issuer` or by a responder `issuer` delegated OCSP signing to.
    fn verify_signer(&self, issuer: &Certificate, now: Duration) -> Result<()> {
        let signature = self.basic.signature.as_bytes().unwrap_or_default();
        let mut candidates: Vec<&Certificate> = vec![issuer];
        candidates.extend(self.basic.certs.iter().flatten());
        let mut last = "no responder certificate is named by the response".to_owned();
        for candidate in candidates {
            if !self.names(candidate)? {
                continue;
            }
            let delegated = candidate != issuer;
            if delegated && let Err(e) = authorized_responder(candidate, issuer, now) {
                last = e.0;
                continue;
            }
            return cert::verify_ecdsa(
                &cert::p384_key(candidate)?,
                &self.basic.signature_algorithm,
                &self.tbs,
                signature,
            )
            .or_else(|e| refuse(format!("ocsp: response {e}")));
        }
        refuse(format!("ocsp: {last}"))
    }

    /// Whether the response's `ResponderID` names `cert`: by name, or by key through the
    /// certificate's subject key identifier (NVIDIA's responders set it to the key hash).
    fn names(&self, cert: &Certificate) -> Result<bool> {
        Ok(match &self.basic.tbs_response_data.responder_id {
            ResponderId::ByName(name) => *name == cert.tbs_certificate.subject,
            ResponderId::ByKey(hash) => cert::extensions(cert)?
                .subject_key_identifier
                .is_some_and(|ski| ski == hash.as_bytes()),
        })
    }
}

/// A delegated responder: issued by `issuer`, for OCSP signing, valid now.
fn authorized_responder(
    responder: &Certificate,
    issuer: &Certificate,
    now: Duration,
) -> Result<()> {
    cert::verify_issued_by(responder, issuer)?;
    cert::check_validity(responder, now)?;
    let eku = cert::extensions(responder)?.extended_key_usage;
    if !eku.is_some_and(|eku| eku.0.contains(&ID_KP_OCSP_SIGNING)) {
        return refuse(format!(
            "{} is not authorized for OCSP signing",
            describe(responder)
        ));
    }
    Ok(())
}

/// `CertID` for `cert` issued by `issuer`, under SHA-256 or SHA-384.
fn cert_id_matches(id: &CertId, cert: &Certificate, issuer: &Certificate) -> Result<bool> {
    if id.serial_number.as_bytes() != cert.tbs_certificate.serial_number.as_bytes() {
        return Ok(false);
    }
    let name = issuer
        .tbs_certificate
        .subject
        .to_der()
        .or_else(|e| refuse(format!("ocsp: {e}")))?;
    let key = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let (name_hash, key_hash): (Vec<u8>, Vec<u8>) = match id.hash_algorithm.oid {
        ID_SHA256 => (Sha256::digest(&name).to_vec(), Sha256::digest(key).to_vec()),
        ID_SHA384 => (Sha384::digest(&name).to_vec(), Sha384::digest(key).to_vec()),
        _ => return Ok(false),
    };
    Ok(id.issuer_name_hash.as_bytes() == name_hash && id.issuer_key_hash.as_bytes() == key_hash)
}

/// The DER `OCSPRequest` for `cert` (SHA-384 `CertID`) with `nonce`, for an online query.
pub fn request(cert: &Certificate, issuer: &Certificate, nonce: &[u8]) -> Result<Vec<u8>> {
    use der::asn1::OctetString;
    use x509_cert::ext::Extension;
    use x509_cert::spki::AlgorithmIdentifierOwned;
    use x509_ocsp::{OcspRequest, Request, TbsRequest, Version};
    let fail = |e: der::Error| super::Refused(format!("ocsp request: {e}"));
    let name = issuer.tbs_certificate.subject.to_der().map_err(fail)?;
    let key = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let req_cert = CertId {
        hash_algorithm: AlgorithmIdentifierOwned {
            oid: ID_SHA384,
            parameters: None,
        },
        issuer_name_hash: OctetString::new(Sha384::digest(&name).to_vec()).map_err(fail)?,
        issuer_key_hash: OctetString::new(Sha384::digest(key).to_vec()).map_err(fail)?,
        serial_number: cert.tbs_certificate.serial_number.clone(),
    };
    let nonce_ext = Extension {
        extn_id: ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.2"),
        critical: false,
        extn_value: OctetString::new(
            OctetString::new(nonce.to_vec())
                .map_err(fail)?
                .to_der()
                .map_err(fail)?,
        )
        .map_err(fail)?,
    };
    OcspRequest {
        tbs_request: TbsRequest {
            version: Version::V1,
            requestor_name: None,
            request_list: vec![Request {
                req_cert,
                single_request_extensions: None,
            }],
            request_extensions: Some(vec![nonce_ext]),
        },
        optional_signature: None,
    }
    .to_der()
    .map_err(fail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_responses_are_refused() {
        for (case, der, reason) in [
            ("empty", &[][..], "does not parse"),
            ("junk", &[0x30, 0x03, 0x0A, 0x01, 0x00][..], "no body"),
            // OCSPResponse { responseStatus tryLater (3) }
            ("try later", &[0x30, 0x03, 0x0A, 0x01, 0x03][..], "TryLater"),
        ] {
            let error = parse(der).unwrap_err().to_string();
            assert!(error.contains(reason), "{case}: {error}");
        }
        assert!(
            parse(&vec![0; MAX_RESPONSE_DER + 1])
                .unwrap_err()
                .to_string()
                .contains("more than")
        );
    }
}

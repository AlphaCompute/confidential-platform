//! RFC 6960 OCSP for NVIDIA's certificates. NVIDIA's responder signs each answer on request and
//! echoes the request's nonce, so a fresh nonce is what makes an answer current; the answer must
//! come from a responder its issuer delegated, and only `good` passes.
// ponytail: DER is encoded and decoded by hand for the one request and response shape NVIDIA's
// responder uses, as the workspace has no OCSP crate; the upgrade is RustCrypto's `x509-ocsp` once
// a responder with another shape has to be read.

use std::time::{Duration, SystemTime};

use p384::ecdsa::signature::hazmat::PrehashVerifier;
use p384::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256, Sha384};
use x509_parser::asn1_rs::{Any, Class, FromDer, Oid, Tag};
use x509_parser::certificate::X509Certificate;
use x509_parser::oid_registry::{
    OID_SIG_ECDSA_WITH_SHA256, OID_SIG_ECDSA_WITH_SHA384, OID_X509_EXT_EXTENDED_KEY_USAGE,
};
use x509_parser::time::ASN1Time;

use super::{asn1_time, p384_key, unknown_critical};
use crate::AppraisalError;

/// `AlgorithmIdentifier { sha384, NULL }`, as OpenSSL and NVIDIA's verifier encode it.
const SHA384_ID: [u8; 15] = [
    0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00,
];
/// id-pkix-ocsp-nonce and id-pkix-ocsp-basic, 1.3.6.1.5.5.7.48.1.2 and .1.
const NONCE_OID: [u8; 9] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02];
const BASIC_OID: [u8; 9] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];
/// How far the responder's clock may run ahead of ours.
const SKEW: Duration = Duration::from_secs(300);

fn failed(what: impl Into<String>) -> AppraisalError {
    AppraisalError::Failed(format!("ocsp: {}", what.into()))
}

/// A certificate whose status NVIDIA's responder reports, and the certificate that issued it.
#[derive(Debug, PartialEq, Eq)]
pub struct OcspQuery {
    cert: Vec<u8>,
    issuer: Vec<u8>,
}

impl OcspQuery {
    pub fn new(cert: Vec<u8>, issuer: Vec<u8>) -> Self {
        Self { cert, issuer }
    }

    /// The DER `OCSPRequest` for this certificate, carrying `nonce`.
    pub fn request(&self, nonce: &[u8; 32]) -> Result<Vec<u8>, AppraisalError> {
        let (_, _, cert_id) = self.parse()?;
        let request = der(0x30, &[&cert_id])?;
        let tbs = der(
            0x30,
            &[
                &der(0x30, &[&request])?,
                &der(0xa2, &[&der(0x30, &[&nonce_extension(nonce)?])?])?,
            ],
        )?;
        der(0x30, &[&tbs])
    }

    /// Accepts `response` only when it is a basic response for this certificate, signed by a
    /// responder the issuer delegated, echoing `nonce`, current at `now`, and `good`. A
    /// certificate on hold is revoked with reason `certificateHold`, so it is refused too.
    pub fn check(
        &self,
        response: &[u8],
        nonce: &[u8; 32],
        now: SystemTime,
    ) -> Result<(), AppraisalError> {
        let (cert, issuer, cert_id) = self.parse()?;
        let subject = cert.subject().to_string();
        let mut outer = sequence(response, "response")?;
        let status = next(&mut outer, "response status")?;
        if status.tag() != Tag::Enumerated || status.data != [0] {
            return Err(failed(format!(
                "responder refused the request for {subject}"
            )));
        }
        let bytes = next(&mut outer, "response bytes")?;
        if !is_context(&bytes, 0) || !outer.is_empty() {
            return Err(failed("response bytes"));
        }
        let mut bytes = sequence(bytes.data, "response bytes")?;
        let kind = Oid::from_der(bytes).map_err(|_| failed("response type"))?;
        bytes = kind.0;
        let basic = next(&mut bytes, "basic response")?;
        if kind.1.as_bytes() != BASIC_OID || basic.tag() != Tag::OctetString {
            return Err(failed("not a basic response"));
        }

        let mut basic = sequence(basic.data, "basic response")?;
        let (tbs, tbs_der) = next_raw(&mut basic, "response data")?;
        let (_, algorithm) = Oid::from_der(next(&mut basic, "signature algorithm")?.data)
            .map_err(|_| failed("signature algorithm"))?;
        let signature = match next(&mut basic, "signature")? {
            bits if bits.tag() == Tag::BitString => match bits.data.split_first() {
                Some((0, signature)) => signature,
                _ => return Err(failed("signature")),
            },
            _ => return Err(failed("signature")),
        };
        let certs = next(&mut basic, "responder certificates")?;
        if !is_context(&certs, 0) || !basic.is_empty() {
            return Err(failed("response carries no responder certificate"));
        }
        let certs = sequence(certs.data, "responder certificates")?;
        let responder = certificates(certs)?
            .into_iter()
            .find(|c| p384_key(c).is_ok_and(|k| verify(&k, &algorithm, tbs_der, signature)))
            .ok_or_else(|| failed("response is not signed by a certificate it carries"))?;
        delegated(&responder, &issuer, now)?;

        let mut fields = tbs.data;
        let mut field = next(&mut fields, "response data")?;
        if is_context(&field, 0) {
            field = next(&mut fields, "responder id")?;
        }
        if !is_context(&field, 1) && !is_context(&field, 2) {
            return Err(failed("responder id"));
        }
        let _produced_at = next(&mut fields, "producedAt")?;
        let mut responses = next(&mut fields, "responses")?.data;
        let single = next(&mut responses, "single response")?;
        if !responses.is_empty() {
            return Err(failed("more than one single response"));
        }
        let exts = match next(&mut fields, "response extensions") {
            Ok(exts) if is_context(&exts, 1) && fields.is_empty() => extensions(exts.data)?,
            _ => return Err(failed("response carries no nonce")),
        };
        let nonces: Vec<_> = exts
            .into_iter()
            .filter(|(oid, _)| oid.as_bytes() == NONCE_OID)
            .map(|(_, value)| value)
            .collect();
        if nonces != [der(0x04, &[nonce])?.as_slice()] {
            return Err(failed("nonce is not this request's"));
        }

        let mut single = single.data;
        if next_raw(&mut single, "certID")?.1 != cert_id {
            return Err(failed("response is for another certificate"));
        }
        let status = next(&mut single, "certStatus")?;
        let (_, this_update) = next_raw(&mut single, "thisUpdate")?;
        let next_update = next(&mut single, "nextUpdate")?;
        let this_update = time(this_update)?;
        let next_update = is_context(&next_update, 0)
            .then(|| time(next_update.data))
            .ok_or_else(|| failed("response has no nextUpdate"))??;
        let ahead = now.checked_add(SKEW).ok_or_else(|| failed("now"))?;
        if this_update > asn1_time(ahead)? || asn1_time(now)? >= next_update {
            return Err(failed(format!(
                "response for {subject} is current from {this_update} to {next_update}"
            )));
        }

        match (status.class(), status.tag().0) {
            (Class::ContextSpecific, 0) if status.data.is_empty() => Ok(()),
            (Class::ContextSpecific, 1) => Err(failed(format!("certificate {subject} is revoked"))),
            (Class::ContextSpecific, 2) => {
                Err(failed(format!("responder does not know {subject}")))
            }
            _ => Err(failed("certStatus")),
        }
    }

    /// Both certificates and the SHA-384 `CertID` of the first.
    fn parse(&self) -> Result<(X509Certificate<'_>, X509Certificate<'_>, Vec<u8>), AppraisalError> {
        let (cert, issuer) = (parse(&self.cert)?, parse(&self.issuer)?);
        if cert.issuer().as_raw() != issuer.subject().as_raw() {
            return Err(failed("issuer does not issue the certificate"));
        }
        let cert_id = der(
            0x30,
            &[
                &SHA384_ID,
                &der(0x04, &[&Sha384::digest(issuer.subject().as_raw())])?,
                &der(
                    0x04,
                    &[&Sha384::digest(
                        &issuer.public_key().subject_public_key.data,
                    )],
                )?,
                &der(0x02, &[cert.raw_serial()])?,
            ],
        )?;
        Ok((cert, issuer, cert_id))
    }
}

/// The id-pkix-ocsp-nonce `Extension` carrying `nonce`.
fn nonce_extension(nonce: &[u8; 32]) -> Result<Vec<u8>, AppraisalError> {
    der(
        0x30,
        &[
            &der(0x06, &[&NONCE_OID])?,
            &der(0x04, &[&der(0x04, &[nonce])?])?,
        ],
    )
}

/// The responder must be issued by the checked certificate's issuer for OCSP signing only, and
/// current. NVIDIA signs its responders with ecdsa-with-SHA256 under P-384 keys.
fn delegated(
    responder: &X509Certificate<'_>,
    issuer: &X509Certificate<'_>,
    now: SystemTime,
) -> Result<(), AppraisalError> {
    let name = responder.subject().to_string();
    if responder.issuer().as_raw() != issuer.subject().as_raw()
        || !verify(
            &p384_key(issuer)?,
            &responder.signature_algorithm.algorithm,
            responder.tbs_certificate.as_ref(),
            &responder.signature_value.data,
        )
    {
        return Err(failed(format!(
            "responder {name} is not issued by the issuer"
        )));
    }
    if !responder
        .extended_key_usage()
        .ok()
        .flatten()
        .is_some_and(|eku| eku.value.ocsp_signing)
    {
        return Err(failed(format!("responder {name} is not for OCSP signing")));
    }
    if responder.key_usage().map_or(true, |ku| {
        ku.is_some_and(|ku| !ku.value.digital_signature())
    }) {
        return Err(failed(format!("responder {name} may not sign")));
    }
    if !responder.validity().is_valid_at(asn1_time(now)?) {
        return Err(failed(format!("responder {name} is outside its validity")));
    }
    if let Some(oid) = unknown_critical(responder, &OID_X509_EXT_EXTENDED_KEY_USAGE.to_id_string())
    {
        return Err(failed(format!(
            "responder {name} has unknown critical extension {oid}"
        )));
    }
    Ok(())
}

fn verify(key: &VerifyingKey, algorithm: &Oid<'_>, signed: &[u8], signature: &[u8]) -> bool {
    let Ok(signature) = Signature::from_der(signature) else {
        return false;
    };
    if *algorithm == OID_SIG_ECDSA_WITH_SHA384 {
        key.verify_prehash(&Sha384::digest(signed), &signature)
            .is_ok()
    } else if *algorithm == OID_SIG_ECDSA_WITH_SHA256 {
        key.verify_prehash(&Sha256::digest(signed), &signature)
            .is_ok()
    } else {
        false
    }
}

fn parse(der: &[u8]) -> Result<X509Certificate<'_>, AppraisalError> {
    match X509Certificate::from_der(der) {
        Ok(([], cert)) => Ok(cert),
        _ => Err(failed("certificate does not parse")),
    }
}

fn certificates(mut data: &[u8]) -> Result<Vec<X509Certificate<'_>>, AppraisalError> {
    let mut certs = Vec::new();
    while !data.is_empty() {
        let (rest, cert) =
            X509Certificate::from_der(data).map_err(|_| failed("responder certificate"))?;
        certs.push(cert);
        data = rest;
    }
    Ok(certs)
}

/// `(extnID, extnValue)` of each extension in `[n] EXPLICIT Extensions`.
fn extensions(data: &[u8]) -> Result<Vec<(Oid<'_>, &[u8])>, AppraisalError> {
    let mut list = sequence(data, "extensions")?;
    let mut out = Vec::new();
    while !list.is_empty() {
        let mut ext = next(&mut list, "extension")?.data;
        let (rest, oid) = Oid::from_der(ext).map_err(|_| failed("extension id"))?;
        ext = rest;
        let mut value = next(&mut ext, "extension value")?;
        if value.tag() == Tag::Boolean {
            value = next(&mut ext, "extension value")?;
        }
        if value.tag() != Tag::OctetString || !ext.is_empty() {
            return Err(failed("extension value"));
        }
        out.push((oid, value.data));
    }
    Ok(out)
}

fn time(der: &[u8]) -> Result<ASN1Time, AppraisalError> {
    match ASN1Time::from_der(der) {
        Ok(([], time)) => Ok(time),
        _ => Err(failed("time")),
    }
}

fn is_context(field: &Any<'_>, tag: u32) -> bool {
    field.class() == Class::ContextSpecific && field.tag() == Tag(tag)
}

/// The content of the one SEQUENCE `data` holds.
fn sequence<'a>(data: &'a [u8], what: &str) -> Result<&'a [u8], AppraisalError> {
    match Any::from_der(data) {
        Ok(([], any)) if any.tag() == Tag::Sequence => Ok(any.data),
        _ => Err(failed(what)),
    }
}

fn next<'a>(data: &mut &'a [u8], what: &str) -> Result<Any<'a>, AppraisalError> {
    next_raw(data, what).map(|(any, _)| any)
}

/// The next element and its whole encoding.
fn next_raw<'a>(data: &mut &'a [u8], what: &str) -> Result<(Any<'a>, &'a [u8]), AppraisalError> {
    let (rest, any) = Any::from_der(data).map_err(|_| failed(what))?;
    let raw = data
        .len()
        .checked_sub(rest.len())
        .and_then(|n| data.get(..n))
        .ok_or_else(|| failed(what))?;
    *data = rest;
    Ok((any, raw))
}

/// One DER TLV whose content is `parts` in order.
fn der(tag: u8, parts: &[&[u8]]) -> Result<Vec<u8>, AppraisalError> {
    let len = parts
        .iter()
        .try_fold(0usize, |n, p| n.checked_add(p.len()))
        .ok_or_else(|| failed("length"))?;
    let mut out = vec![tag];
    match (u8::try_from(len), u16::try_from(len)) {
        (Ok(n), _) if n < 0x80 => out.push(n),
        (Ok(n), _) => out.extend([0x81, n]),
        (_, Ok(n)) => {
            out.push(0x82);
            out.extend(n.to_be_bytes());
        }
        _ => return Err(failed("length")),
    }
    parts.iter().for_each(|p| out.extend_from_slice(p));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use p384::ecdsa::SigningKey;
    use p384::ecdsa::signature::Signer;
    use p384::pkcs8::DecodePrivateKey;
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, KeyUsagePurpose, PKCS_ECDSA_P384_SHA384,
    };

    use super::*;

    const NONCE: [u8; 32] = [0x5a; 32];

    fn ca() -> CertifiedIssuer<'static, KeyPair> {
        let mut params = CertificateParams::new(vec![]).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        CertifiedIssuer::self_signed(params, key).unwrap()
    }

    /// A response for `query` with `status`, from a responder `ca` issues with `eku` and `ku`.
    fn response(
        query: &OcspQuery,
        ca: &CertifiedIssuer<'_, KeyPair>,
        (eku, ku): (ExtendedKeyUsagePurpose, KeyUsagePurpose),
        status: &[u8],
    ) -> Vec<u8> {
        let mut params = CertificateParams::new(vec![]).unwrap();
        params.extended_key_usages = vec![eku];
        params.key_usages = vec![ku];
        let key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let responder = params.signed_by(&key, ca).unwrap();
        let signer: SigningKey = p384::SecretKey::from_pkcs8_der(&key.serialize_der())
            .unwrap()
            .into();
        let time = |t: &str| der(0x18, &[t.as_bytes()]).unwrap();
        let single = der(
            0x30,
            &[
                &query.parse().unwrap().2,
                status,
                &time("20261019100000Z"),
                &der(0xa0, &[&time("20261020100000Z")]).unwrap(),
            ],
        )
        .unwrap();
        let nonce = nonce_extension(&NONCE).unwrap();
        let tbs = der(
            0x30,
            &[
                &der(0xa2, &[&der(0x04, &[&[0; 20]]).unwrap()]).unwrap(),
                &time("20261019100000Z"),
                &der(0x30, &[&single]).unwrap(),
                &der(0xa1, &[&der(0x30, &[&nonce]).unwrap()]).unwrap(),
            ],
        )
        .unwrap();
        let signature: Signature = signer.sign(&tbs);
        let algorithm = der(0x06, &[OID_SIG_ECDSA_WITH_SHA384.as_bytes()]).unwrap();
        let basic = der(
            0x30,
            &[
                &tbs,
                &der(0x30, &[&algorithm]).unwrap(),
                &der(0x03, &[&[0], signature.to_der().as_bytes()]).unwrap(),
                &der(0xa0, &[&der(0x30, &[responder.der()]).unwrap()]).unwrap(),
            ],
        )
        .unwrap();
        let bytes = der(
            0x30,
            &[
                &der(0x06, &[&BASIC_OID]).unwrap(),
                &der(0x04, &[&basic]).unwrap(),
            ],
        )
        .unwrap();
        der(0x30, &[&[0x0a, 0x01, 0x00], &der(0xa0, &[&bytes]).unwrap()]).unwrap()
    }

    #[test]
    fn only_good_from_a_delegated_ocsp_signer_passes() {
        let ca = ca();
        let key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let cert = CertificateParams::new(vec![])
            .unwrap()
            .signed_by(&key, &ca)
            .unwrap();
        let query = OcspQuery::new(cert.der().to_vec(), ca.der().to_vec());
        let ocsp = || {
            (
                ExtendedKeyUsagePurpose::OcspSigning,
                KeyUsagePurpose::DigitalSignature,
            )
        };
        // 2026-10-19 12:00 UTC, inside the responses' validity.
        let now = std::time::UNIX_EPOCH + Duration::from_secs(1_792_411_200);
        let good = der(0x80, &[]).unwrap();
        let check = |response: Vec<u8>| query.check(&response, &NONCE, now);
        check(response(&query, &ca, ocsp(), &good)).unwrap();

        let revoked = |reason: u8| {
            der(
                0xa1,
                &[
                    &der(0x18, &[b"20261018000000Z"]).unwrap(),
                    &der(0xa0, &[&der(0x0a, &[&[reason]]).unwrap()]).unwrap(),
                ],
            )
            .unwrap()
        };
        let code_signing = (
            ExtendedKeyUsagePurpose::CodeSigning,
            KeyUsagePurpose::DigitalSignature,
        );
        let cert_signing = (
            ExtendedKeyUsagePurpose::OcspSigning,
            KeyUsagePurpose::KeyCertSign,
        );
        let cases = [
            (response(&query, &ca, ocsp(), &revoked(1)), "is revoked"),
            (response(&query, &ca, ocsp(), &revoked(6)), "is revoked"),
            (
                response(&query, &ca, ocsp(), &der(0x82, &[]).unwrap()),
                "does not know",
            ),
            (
                response(&query, &ca, code_signing, &good),
                "is not for OCSP signing",
            ),
            (response(&query, &ca, cert_signing, &good), "may not sign"),
            (
                response(&query, &self::ca(), ocsp(), &good),
                "is not issued by the issuer",
            ),
        ];
        for (response, fragment) in cases {
            let err = check(response).unwrap_err();
            assert!(err.to_string().contains(fragment), "{fragment}: {err}");
        }
    }
}

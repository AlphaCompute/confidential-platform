//! The collateral an SNP report needs from AMD's Key Distribution Service: the VCEK when the
//! evidence does not carry it, and the CRL. Only from the `kds_url` the release-signed
//! `snp_policy` names, and cached: a VCEK is fixed by its chip and TCB, so it is kept; a CRL is
//! fetched again after [`CRL_REFRESH`], and the cached one is used while KDS does not answer. Nothing
//! here is trusted: [`super::verify_report`] checks both under the pinned ARK and refuses a CRL
//! past its `nextUpdate`, so a stale cache fails closed.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use x509_cert::Certificate;
use x509_cert::der::Decode;

use super::{ReportHeader, SnpCollateral, SnpPolicy, SnpTcb, VekKind, header, hwid_len};
use crate::AppraisalError;

/// How long a fetched CRL is used before KDS is asked again. AMD's CRLs run for weeks.
pub const CRL_REFRESH: Duration = Duration::from_secs(3600);
/// Entries kept before the cache starts over: one VCEK per chip and TCB, one CRL per product.
pub const MAX_CACHED: usize = 1024;
/// A VCEK or CRL is about a kilobyte; anything much larger is not one.
const MAX_BODY: usize = 64 * 1024;
const TIMEOUT: Duration = Duration::from_secs(20);

pub type KdsFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<u8>, AppraisalError>> + Send + 'a>>;

/// One GET against KDS, returning the body of a `200`.
pub trait KdsClient: Send + Sync {
    fn get<'a>(&'a self, url: &'a str) -> KdsFuture<'a>;
}

/// KDS over HTTPS.
pub struct HttpKds {
    http: reqwest::Client,
}

impl HttpKds {
    pub fn new() -> Result<Self, AppraisalError> {
        let http = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .https_only(true)
            .build()
            .map_err(|e| AppraisalError::Failed(format!("kds client: {e}")))?;
        Ok(Self { http })
    }
}

impl KdsClient for HttpKds {
    fn get<'a>(&'a self, url: &'a str) -> KdsFuture<'a> {
        Box::pin(async move {
            let fail = |e: String| AppraisalError::Failed(format!("kds {url}: {e}"));
            let response = self
                .http
                .get(url)
                .send()
                .await
                .map_err(|e| fail(e.to_string()))?;
            if !response.status().is_success() {
                return Err(fail(format!("status {}", response.status())));
            }
            let body = response.bytes().await.map_err(|e| fail(e.to_string()))?;
            if body.len() > MAX_BODY {
                return Err(fail(format!("{} bytes", body.len())));
            }
            Ok(body.to_vec())
        })
    }
}

/// `{kds}/vcek/v1/{product}/{hwid}?blSPL=..&teeSPL=..&snpSPL=..&ucodeSPL=..` (and `fmcSPL` from
/// Turin on), as AMD's VCEK specification (57230) defines it.
pub fn vcek_url(kds: &str, product: &str, chip_id: &[u8; 64], tcb: &SnpTcb) -> String {
    let hwid = chip_id.get(..hwid_len(product)).unwrap_or(chip_id);
    let mut url = format!(
        "{}/vcek/v1/{product}/{}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
        kds.trim_end_matches('/'),
        hex::encode(hwid),
        tcb.bootloader,
        tcb.tee,
        tcb.snp,
        tcb.microcode
    );
    if let Some(fmc) = tcb.fmc {
        url.push_str(&format!("&fmcSPL={fmc:02}"));
    }
    url
}

/// `{kds}/{vcek|vlek}/v1/{product}/crl`.
pub fn crl_url(kds: &str, product: &str, kind: VekKind) -> String {
    format!(
        "{}/{}/v1/{product}/crl",
        kds.trim_end_matches('/'),
        kind.path()
    )
}

struct Cached {
    bytes: Vec<u8>,
    fetched: SystemTime,
}

/// KDS behind a cache, shared by every attestation a KMS node appraises.
pub struct Kds {
    client: Arc<dyn KdsClient>,
    cache: Mutex<HashMap<String, Cached>>,
}

impl Kds {
    pub fn new(client: Arc<dyn KdsClient>) -> Self {
        Self {
            client,
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn cached(&self, url: &str) -> Option<(Vec<u8>, SystemTime)> {
        let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.get(url).map(|c| (c.bytes.clone(), c.fetched))
    }

    fn store(&self, url: &str, bytes: &[u8], now: SystemTime) {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if cache.len() >= MAX_CACHED && !cache.contains_key(url) {
            cache.clear();
        }
        cache.insert(
            url.to_owned(),
            Cached {
                bytes: bytes.to_vec(),
                fetched: now,
            },
        );
    }

    /// `url`'s body: from the cache when younger than `refresh` (`None`: kept for good), else from
    /// KDS, falling back to a cached body when KDS fails.
    async fn fetch(
        &self,
        url: &str,
        refresh: Option<Duration>,
        now: SystemTime,
    ) -> Result<Vec<u8>, AppraisalError> {
        let cached = self.cached(url);
        if let Some((bytes, fetched)) = &cached {
            let fresh = refresh
                .is_none_or(|refresh| now.duration_since(*fetched).is_ok_and(|age| age < refresh));
            if fresh {
                return Ok(bytes.clone());
            }
        }
        match self.client.get(url).await {
            Ok(bytes) => {
                self.store(url, &bytes, now);
                Ok(bytes)
            }
            Err(e) => cached.map(|(bytes, _)| bytes).ok_or(e),
        }
    }

    /// The VEK and CRL for `report`: the VEK the evidence carries, else the VCEK from KDS; the CRL
    /// always from KDS. Refused when `snp_policy` names no KDS, since there is then no CRL.
    pub async fn collateral(
        &self,
        report: &[u8],
        vek: Option<&[u8]>,
        policy: &SnpPolicy,
        now: SystemTime,
    ) -> Result<SnpCollateral, AppraisalError> {
        use AppraisalError::*;

        let ReportHeader {
            signing_key,
            product,
            chip_id,
            reported_tcb,
        } = header(report)?;
        let kds = policy.kds_url.as_deref().ok_or_else(|| {
            Unknown("snp_policy names no kds_url, so AMD's CRL cannot be fetched".into())
        })?;
        let product = match (product, vek) {
            (Some(product), _) => product.to_owned(),
            (None, Some(vek)) => Certificate::from_der(vek)
                .ok()
                .and_then(|cert| super::product_name(&cert).ok().flatten())
                .ok_or_else(|| Failed("the evidence's VEK names no product".into()))?,
            (None, None) => {
                return Err(Failed(
                    "a version 2 SNP report names no product; the evidence must carry its VCEK"
                        .into(),
                ));
            }
        };
        let vek = match (vek, signing_key) {
            (Some(vek), _) => vek.to_vec(),
            (None, VekKind::Vcek) => {
                self.fetch(&vcek_url(kds, &product, &chip_id, &reported_tcb), None, now)
                    .await?
            }
            (None, VekKind::Vlek) => {
                return Err(Failed(
                    "a VLEK-signed SNP report must carry its VLEK; KDS does not serve VLEKs".into(),
                ));
            }
        };
        let crl = self
            .fetch(&crl_url(kds, &product, signing_key), Some(CRL_REFRESH), now)
            .await?;
        Ok(SnpCollateral { vek, crl })
    }
}

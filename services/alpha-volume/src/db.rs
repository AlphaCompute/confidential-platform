//! `alpha-volume open-db <name> <device> <mount dir>`: the trust-zone Postgres pod's init
//! container (PRD-05 M2(a), `docs/db-volume-key.md`). It is `open` with another key source:
//! instead of the App's `volume.<name>` key from `alpha-runtime`, it asks an unsealed KMS node for
//! the `db-volume` intermediate over `POST /v1/node/db-key`, through `alpha_client::db_key::fetch`.
//!
//! The Postgres pod has no `alpha-runtime`: its Revision is in the platform document's
//! `db_revisions`, not in the database the volume holds, so `keys/derive` (which needs the
//! Revision's row) cannot serve it. On a cold start the database does not exist yet when this runs.
//!
//! For each round, until one KMS node answers or [`Config::wait`] runs out:
//! 1. fetch the platform document and verify it under the compiled-in release key; refuse it below
//!    the measured minimum version;
//! 2. for each `ALPHACOMPUTE_KMS_ENDPOINTS` in turn: attest the node as a custodian's CLI does
//!    (`alpha_attest::node`, its build in `kms_revisions`, the TLS key equal to its runtime key),
//!    quote over `SHA-256(xwing ‖ nonce)` through the CoCo source, post the evidence, open the
//!    reply. The first node that answers gives the key.
//!
//! A node that is still sealed answers `sealed`; this waits for the custodians, which is the cold
//! start order **unseal → db key → database → serve**. Nothing is formatted or opened without
//! the key, and the key never leaves this process except on cryptsetup's stdin.

use std::future::Future;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime};

use alpha_attest::PlatformDocument;
use alpha_core::coco::{CPU_RUNTIME_CLASS, InitData};
use alpha_tsm::coco::QuoteSource;
use zeroize::Zeroizing;

use crate::Error;

pub const KMS_ENDPOINTS: &str = "ALPHACOMPUTE_KMS_ENDPOINTS";
pub const PLATFORM_DOCUMENT_URL: &str = "ALPHACOMPUTE_PLATFORM_DOCUMENT_URL";
pub const PCCS_URL: &str = "ALPHACOMPUTE_PCCS_URL";
pub const QUOTE_SOURCE: &str = "ALPHACOMPUTE_QUOTE_SOURCE";
pub const MIN_DOCUMENT_VERSION: &str = "ALPHACOMPUTE_PLATFORM_DOCUMENT_MIN_VERSION";
pub const WAIT_SECONDS: &str = "ALPHACOMPUTE_DB_KEY_WAIT_SECONDS";
/// How long the container waits for an unsealed node before it exits (and Kubernetes restarts
/// it): long enough for two custodians to run `alpha unseal` after the pod is scheduled.
pub const DEFAULT_WAIT: Duration = Duration::from_secs(30 * 60);
/// Between rounds over every endpoint.
pub const ROUND_EVERY: Duration = Duration::from_secs(5);

/// The init container's measured environment. Every value is in the agent policy inside the
/// init-data, which the pod's Revision v2 stands for, so none of it may be secret and none of it
/// is chosen by the host.
#[derive(Debug)]
pub struct Config {
    pub endpoints: Vec<String>,
    pub platform_document_url: String,
    pub pccs_url: String,
    pub quote: QuoteSource,
    /// QUESTION(PRD-05 Q2): the pod keeps no state, so without a measured floor the host could
    /// serve it an older, still-signed platform document listing a KMS build since dropped.
    /// Proposed: the renderer measures the version current at render time; a KMS build is
    /// revoked by a document above it, and the pod is re-rendered (a new Revision) when the
    /// floor must move. Unset means 0 (no floor) for now.
    pub min_document_version: u64,
    pub wait: Duration,
}

impl Config {
    pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Result<Self, Error> {
        let need = |name: &str| {
            get(name)
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
                .ok_or_else(|| Error::Invalid(format!("{name} is not set")))
        };
        let endpoints: Vec<String> = need(KMS_ENDPOINTS)?
            .split(',')
            .map(|s| s.trim().trim_end_matches('/').to_owned())
            .filter(|s| !s.is_empty())
            .collect();
        if let Some(bad) = endpoints.iter().find(|e| !e.starts_with("https://")) {
            return Err(Error::Invalid(format!(
                "{KMS_ENDPOINTS}: {bad:?} is not https://"
            )));
        }
        let platform_document_url = need(PLATFORM_DOCUMENT_URL)?;
        if !platform_document_url.starts_with("https://") {
            return Err(Error::Invalid(format!(
                "{PLATFORM_DOCUMENT_URL}: {platform_document_url:?} is not https://"
            )));
        }
        let quote = match need(QUOTE_SOURCE)?.as_str() {
            "coco-aa" => QuoteSource::AttestationAgent,
            "coco-tsm" => QuoteSource::ConfigfsTsm,
            other => {
                return Err(Error::Invalid(format!(
                    "{QUOTE_SOURCE}={other:?}: the Postgres pod is a Kata pod, coco-aa or coco-tsm"
                )));
            }
        };
        let number = |name: &str| -> Result<Option<u64>, Error> {
            get(name)
                .map(|v| {
                    v.trim()
                        .parse::<u64>()
                        .map_err(|_| Error::Invalid(format!("{name}={v:?}: not a whole number")))
                })
                .transpose()
        };
        Ok(Self {
            endpoints,
            platform_document_url,
            pccs_url: need(PCCS_URL)?,
            quote,
            min_document_version: number(MIN_DOCUMENT_VERSION)?.unwrap_or(0),
            wait: number(WAIT_SECONDS)?.map_or(DEFAULT_WAIT, Duration::from_secs),
        })
    }
}

/// What the pod may use a document for: at or above the floor, and listing a database build at
/// all (a document without `db_revisions` cannot admit this pod, so asking would only be refused).
pub fn check_document(doc: &PlatformDocument, min_version: u64) -> Result<(), String> {
    if doc.version < min_version {
        return Err(format!(
            "platform document version {} is below the measured minimum {min_version}",
            doc.version
        ));
    }
    if doc.db_revisions.is_empty() {
        return Err("the platform document lists no db_revisions".into());
    }
    if doc.kms_revisions.is_empty() {
        return Err("the platform document lists no kms_revisions".into());
    }
    Ok(())
}

/// The pod's own init-data must stand for a CPU-class Revision v2 with no GPU: the KMS refuses
/// any other database pod, so this fails before asking.
pub fn check_initdata(initdata: &[u8]) -> Result<String, Error> {
    let revision = InitData::parse(initdata)
        .and_then(|d| d.revision())
        .map_err(|e| Error::Invalid(format!("init-data: {e}")))?;
    if revision.runtime_class != CPU_RUNTIME_CLASS || revision.gpu.is_some() {
        return Err(Error::Invalid(format!(
            "init-data: the database pod runs on {CPU_RUNTIME_CLASS} with no GPU, not {}",
            revision.runtime_class
        )));
    }
    Ok(revision.runtime_class)
}

/// Rounds over `endpoints` until `attempt` gives a key or `wait` has passed. Each failure is
/// logged with its endpoint; the error after the deadline names the last one.
pub async fn first_key<F, Fut>(
    endpoints: &[String],
    wait: Duration,
    every: Duration,
    mut attempt: F,
) -> Result<Zeroizing<[u8; 32]>, Error>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Result<Zeroizing<[u8; 32]>, String>>,
{
    if endpoints.is_empty() {
        return Err(Error::Invalid(format!("{KMS_ENDPOINTS} names no endpoint")));
    }
    let start = Instant::now();
    let mut last = String::new();
    loop {
        for endpoint in endpoints {
            match attempt(endpoint.clone()).await {
                Ok(key) => return Ok(key),
                Err(e) => {
                    eprintln!("alpha-volume: db key from {endpoint}: {e}");
                    last = format!("{endpoint}: {e}");
                }
            }
        }
        if start.elapsed().saturating_add(every) > wait {
            return Err(Error::Key(format!(
                "no KMS node released the db-volume key within {}s; last: {last}",
                wait.as_secs()
            )));
        }
        tokio::time::sleep(every).await;
    }
}

/// The whole open-db key exchange, against the real KMS nodes and the pod's CoCo source.
pub async fn fetch_key(config: &Config) -> Result<Zeroizing<[u8; 32]>, Error> {
    let release_key =
        alpha_channel::platform::release_key().map_err(|e| Error::Invalid(e.to_string()))?;
    let initdata = alpha_tsm::coco::initdata(Path::new(alpha_tsm::coco::INITDATA_PATH))
        .map_err(|e| Error::Invalid(format!("init-data: {e}")))?;
    let runtime_class = check_initdata(&initdata)?;
    let quote = config.quote;
    first_key(&config.endpoints, config.wait, ROUND_EVERY, |endpoint| {
        let initdata = initdata.clone();
        let runtime_class = runtime_class.clone();
        async move {
            // Fetched every attempt: a document the release key publishes while this waits (one
            // listing this pod's build, say) is used without a restart.
            let doc = alpha_client::platform::fetch(
                &config.platform_document_url,
                &release_key,
                SystemTime::now(),
            )
            .await
            .map_err(|e| e.to_string())?;
            check_document(&doc, config.min_document_version)?;
            let source = alpha_tsm::coco::Source {
                quote,
                initdata,
                runtime_class,
                gpu_count: 0,
            };
            alpha_client::db_key::fetch(
                &endpoint,
                &doc,
                &config.pccs_url,
                |report_data| {
                    source
                        .evidence(report_data)
                        .map(Into::into)
                        .map_err(|e| e.to_string())
                },
                SystemTime::now(),
            )
            .await
            .map_err(|e| e.to_string())
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use super::*;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name| map.get(name).cloned()
    }

    const BASE: [(&str, &str); 4] = [
        (
            KMS_ENDPOINTS,
            "https://alpha-kms-0.alpha-kms-nodes:8443/, https://alpha-kms-1.alpha-kms-nodes:8443",
        ),
        (
            PLATFORM_DOCUMENT_URL,
            "https://release.example/platform.json",
        ),
        (
            PCCS_URL,
            "https://pccs.site1.alphacompute.internal:8081/sgx/certification/v4/",
        ),
        (QUOTE_SOURCE, "coco-aa"),
    ];

    #[test]
    fn config_reads_the_measured_env() {
        let config = Config::from_env(env(&BASE)).unwrap();
        assert_eq!(
            config.endpoints,
            [
                "https://alpha-kms-0.alpha-kms-nodes:8443",
                "https://alpha-kms-1.alpha-kms-nodes:8443"
            ]
        );
        assert_eq!(config.quote, QuoteSource::AttestationAgent);
        assert_eq!(config.min_document_version, 0);
        assert_eq!(config.wait, DEFAULT_WAIT);

        let mut more = BASE.to_vec();
        more.push((MIN_DOCUMENT_VERSION, "12"));
        more.push((WAIT_SECONDS, "60"));
        more.push((QUOTE_SOURCE, "coco-tsm"));
        let config = Config::from_env(env(&more)).unwrap();
        assert_eq!(config.min_document_version, 12);
        assert_eq!(config.wait, Duration::from_secs(60));
        assert_eq!(config.quote, QuoteSource::ConfigfsTsm);
    }

    #[test]
    fn config_refuses_what_a_database_pod_cannot_use() {
        let with = |name: &'static str, value: &'static str| {
            let mut pairs: Vec<(&str, &str)> =
                BASE.iter().filter(|(k, _)| *k != name).copied().collect();
            if !value.is_empty() {
                pairs.push((name, value));
            }
            Config::from_env(env(&pairs)).unwrap_err().to_string()
        };
        assert!(with(KMS_ENDPOINTS, "").contains("not set"));
        assert!(with(KMS_ENDPOINTS, "http://kms:8443").contains("not https"));
        assert!(with(PLATFORM_DOCUMENT_URL, "http://release/p.json").contains("not https"));
        assert!(with(PCCS_URL, "").contains("not set"));
        assert!(with(QUOTE_SOURCE, "").contains("not set"));
        assert!(with(QUOTE_SOURCE, "dstack").contains("Kata pod"));
        let mut bad = BASE.to_vec();
        bad.push((MIN_DOCUMENT_VERSION, "-1"));
        assert!(Config::from_env(env(&bad)).is_err());
    }

    fn document(version: u64, db: bool) -> PlatformDocument {
        let revision = serde_json::json!({
            "compose_hash": format!("sha256:{}", "a".repeat(64)),
            "build": "b", "source_url": "https://example", "kind": "kata-tdx"
        });
        serde_json::from_value(serde_json::json!({
            "version": version, "issued_at": "2026-10-12T00:00:00Z",
            "policy": { "tcb_statuses": ["UpToDate"], "tolerated_advisories": [] },
            "reference_values": [], "kms_ca_pem": "",
            "kms_revisions": [revision],
            "db_revisions": if db { vec![revision.clone()] } else { vec![] },
        }))
        .unwrap()
    }

    #[test]
    fn a_document_below_the_floor_or_without_database_builds_is_not_used() {
        assert!(check_document(&document(7, true), 7).is_ok());
        assert!(
            check_document(&document(6, true), 7)
                .unwrap_err()
                .contains("below")
        );
        assert!(
            check_document(&document(7, false), 0)
                .unwrap_err()
                .contains("db_revisions")
        );
    }

    fn wrapped_initdata(output_json: &str) -> Vec<u8> {
        use base64::Engine;
        let out: serde_json::Value = serde_json::from_str(output_json).unwrap();
        base64::prelude::BASE64_STANDARD
            .decode(out["initdata"].as_str().unwrap())
            .unwrap()
    }

    #[test]
    fn only_cpu_class_init_data_without_gpus_is_a_database_pod() {
        let cpu = wrapped_initdata(include_str!(
            "../../../testdata/coco/wrap/02-cpu/output.json"
        ));
        assert_eq!(check_initdata(&cpu).unwrap(), CPU_RUNTIME_CLASS);
        let gpu = wrapped_initdata(include_str!(
            "../../../testdata/coco/wrap/01-gpu/output.json"
        ));
        assert!(
            check_initdata(&gpu)
                .unwrap_err()
                .to_string()
                .contains("no GPU")
        );
        assert!(check_initdata(b"not toml").is_err());
    }

    #[tokio::test]
    async fn the_first_node_that_answers_gives_the_key() {
        let endpoints = vec!["https://a".to_owned(), "https://b".to_owned()];
        let asked = Arc::new(Mutex::new(Vec::new()));
        let log = asked.clone();
        let key = first_key(
            &endpoints,
            Duration::from_secs(5),
            Duration::from_millis(1),
            |e| {
                log.lock().unwrap().push(e.clone());
                async move {
                    if e == "https://b" {
                        Ok(Zeroizing::new([9u8; 32]))
                    } else {
                        Err("sealed".to_owned())
                    }
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(*key, [9u8; 32]);
        assert_eq!(*asked.lock().unwrap(), ["https://a", "https://b"]);
    }

    #[tokio::test]
    async fn it_waits_for_the_custodians_then_gives_up_naming_the_last_refusal() {
        let endpoints = vec!["https://a".to_owned()];
        let rounds = Arc::new(Mutex::new(0u32));
        let count = rounds.clone();
        let key = first_key(
            &endpoints,
            Duration::from_secs(5),
            Duration::from_millis(1),
            |_| {
                let count = count.clone();
                async move {
                    let mut n = count.lock().unwrap();
                    *n += 1;
                    if *n < 3 {
                        Err("sealed".to_owned())
                    } else {
                        Ok(Zeroizing::new([1u8; 32]))
                    }
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(*key, [1u8; 32]);
        assert_eq!(*rounds.lock().unwrap(), 3);

        let refused = first_key(
            &endpoints,
            Duration::from_millis(30),
            Duration::from_millis(10),
            |_| async {
                Err::<Zeroizing<[u8; 32]>, _>(
                    "not_found: this database has no db-volume key".to_owned(),
                )
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(refused.contains("https://a: not_found"), "{refused}");
        assert!(
            first_key(&[], Duration::ZERO, Duration::ZERO, |_| async {
                Ok(Zeroizing::new([0u8; 32]))
            })
            .await
            .is_err()
        );
    }
}

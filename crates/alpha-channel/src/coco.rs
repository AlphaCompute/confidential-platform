//! A Revision v2 as a page shows it before an organization approves it. The Revision carries only
//! digests of the init-data and its agent policy, so what the pod may run is shown only from
//! init-data bytes that rebuild exactly the Revision asked for: their SHA-256 is its
//! `initdata_sha256`, and `InitData::revision` over them gives its canonical bytes, policy digest,
//! runtime class and GPUs included.

use alpha_core::AppId;
use alpha_core::agent_policy::{self, PolicySummary};
use alpha_core::coco::{CocoRevision, InitData};
use serde::Serialize;

use crate::{Error, sha256_label};

/// What the init-data says the pod runs, read from bytes that rebuild the Revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Pod {
    pub policy: PolicySummary,
    /// The agent policy's Rego, as the pod runs it.
    pub policy_text: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RevisionView {
    pub revision: CocoRevision,
    /// `None` when no init-data was given.
    pub pod: Option<Pod>,
}

fn malformed(e: impl std::fmt::Display) -> Error {
    Error::Malformed(format!("revision v2: {e}"))
}

/// The view of `text`, a Revision v2 that registration accepts for `app_id`. Init-data that is
/// given must rebuild `text` exactly, or this is `compose_mismatch`.
pub fn view(text: &str, app_id: AppId, initdata: Option<&[u8]>) -> Result<RevisionView, Error> {
    let revision = CocoRevision::check_registered(text, app_id).map_err(malformed)?;
    let Some(bytes) = initdata else {
        return Ok(RevisionView {
            revision,
            pod: None,
        });
    };
    if sha256_label(bytes) != revision.initdata_sha256.to_string() {
        return Err(Error::ComposeMismatch);
    }
    let init = InitData::parse(bytes).map_err(malformed)?;
    let rebuilt = init
        .revision()
        .and_then(|r| r.canonical())
        .map_err(malformed)?;
    if rebuilt != text {
        return Err(Error::ComposeMismatch);
    }
    let policy_text = init.policy().map_err(malformed)?.to_owned();
    let policy = agent_policy::summarize(&policy_text).map_err(malformed)?;
    Ok(RevisionView {
        revision,
        pod: Some(Pod {
            policy,
            policy_text,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alpha_core::agent_policy::Verdict;

    /// One B300 pod's init-data, with a genpolicy-shaped policy naming three images, and the
    /// Revision v2 it stands for. The signer page's tests use the same files.
    const INITDATA: &str = include_str!("../../../testdata/coco/b300x1/initdata.toml");
    const REVISION: &str = include_str!("../../../testdata/coco/b300x1/revision.json");

    fn app() -> AppId {
        "01994b3e-5c8a-7d3e-9a1b-2c3d4e5f6a7b".parse().unwrap()
    }

    #[test]
    fn the_vector_is_the_revision_of_its_initdata() {
        let init = InitData::parse(INITDATA.as_bytes()).unwrap();
        assert_eq!(init.revision().unwrap().canonical().unwrap(), REVISION);
        assert_eq!(
            alpha_core::check_registration(REVISION, app())
                .unwrap()
                .to_string(),
            "sha256:bf327e9207f3855cad8404eeaccb1b67700dad8d71d4bc20b153f7d711e659f5"
        );
    }

    #[test]
    fn initdata_that_rebuilds_the_revision_is_shown() {
        let shown = view(REVISION, app(), Some(INITDATA.as_bytes())).unwrap();
        let pod = shown.pod.clone().unwrap();
        assert_eq!(shown.revision.gpu.as_ref().unwrap().count, 1);
        assert_eq!(pod.policy.exec, Verdict::Denied);
        assert_eq!(pod.policy.logs, Verdict::Denied);
        assert_eq!(
            pod.policy.images,
            [
                format!("registry.k8s.io/pause@sha256:{}", "5c".repeat(32)),
                format!(
                    "ghcr.io/alphacompute/alpha-runtime@sha256:{}",
                    "7d".repeat(32)
                ),
                format!("docker.io/vllm/vllm-openai@sha256:{}", "e1".repeat(32)),
            ]
        );
        assert!(pod.policy_text.starts_with("package agent_policy\n"));

        let bare = view(REVISION, app(), None).unwrap();
        assert_eq!(bare.pod, None);
        assert_eq!(bare.revision, shown.revision);
    }

    #[test]
    fn initdata_of_another_pod_is_a_mismatch() {
        let edited = INITDATA.replace(
            "default ExecProcessRequest := false",
            "default ExecProcessRequest := true",
        );
        assert!(matches!(
            view(REVISION, app(), Some(edited.as_bytes())),
            Err(Error::ComposeMismatch)
        ));
        // The init-data's own hash, but another policy digest in the Revision: the rebuilt
        // Revision differs.
        let mut revision: serde_json::Value = serde_json::from_str(REVISION).unwrap();
        revision["policy_sha256"] = alpha_core::compose_hash("other").to_string().into();
        let other = String::from_utf8(alpha_core::jcs(&revision).unwrap()).unwrap();
        assert!(matches!(
            view(&other, app(), Some(INITDATA.as_bytes())),
            Err(Error::ComposeMismatch)
        ));
    }

    #[test]
    fn what_registration_refuses_is_malformed() {
        let spaced = REVISION.replacen(',', ", ", 1);
        let other_app = AppId::mint();
        for (text, app) in [(spaced.as_str(), app()), (REVISION, other_app)] {
            assert!(matches!(view(text, app, None), Err(Error::Malformed(_))));
        }
        // Init-data whose policy cannot be read is not shown, though it rebuilds the Revision.
        let init = INITDATA.replace("package agent_policy", "package other");
        let revision = InitData::parse(init.as_bytes())
            .unwrap()
            .revision()
            .unwrap()
            .canonical()
            .unwrap();
        assert!(matches!(
            view(&revision, app(), Some(init.as_bytes())),
            Err(Error::Malformed(_))
        ));
    }
}

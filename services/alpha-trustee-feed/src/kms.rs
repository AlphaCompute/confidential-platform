//! The four alpha-kms routes the feed calls, behind a trait so the gate is tested without a KMS.

use std::future::Future;
use std::sync::Arc;

use alpha_trustee::wire;

/// Why the KMS gave no answer: it refused (its answer, final) or could not be asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KmsError {
    Refused { code: String, message: String },
    Unreachable(String),
}

impl std::fmt::Display for KmsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused { code, message } => write!(f, "refused: {code}: {message}"),
            Self::Unreachable(m) => write!(f, "unreachable: {m}"),
        }
    }
}

impl From<alpha_client::Error> for KmsError {
    fn from(e: alpha_client::Error) -> Self {
        match e {
            alpha_client::Error::Api(api) if api.status < 500 => Self::Refused {
                code: api.code,
                message: api.message,
            },
            other => Self::Unreachable(other.to_string()),
        }
    }
}

pub trait Kms: Send + Sync + 'static {
    fn attested(
        &self,
        body: wire::Attestation,
    ) -> impl Future<Output = Result<wire::Admitted, KmsError>> + Send;
    fn release(
        &self,
        body: wire::Release,
    ) -> impl Future<Output = Result<wire::Released, KmsError>> + Send;
    fn state(&self) -> impl Future<Output = Result<wire::State, KmsError>> + Send;
}

/// The KMS over the runtime's current leaf.
pub struct RuntimeKms(pub Arc<alpha_runtime::Runtime>);

impl RuntimeKms {
    fn client(&self) -> Result<alpha_client::Client, KmsError> {
        self.0
            .attested()
            .map(|a| a.client().clone())
            .ok_or_else(|| KmsError::Unreachable("no valid leaf".into()))
    }
}

impl Kms for RuntimeKms {
    async fn attested(&self, body: wire::Attestation) -> Result<wire::Admitted, KmsError> {
        Ok(self
            .client()?
            .post_json("/v1/trustee/attestations", &body)
            .await?)
    }

    async fn release(&self, body: wire::Release) -> Result<wire::Released, KmsError> {
        Ok(self
            .client()?
            .post_json("/v1/trustee/releases", &body)
            .await?)
    }

    async fn state(&self) -> Result<wire::State, KmsError> {
        Ok(self.client()?.get_json("/v1/trustee/state").await?)
    }
}

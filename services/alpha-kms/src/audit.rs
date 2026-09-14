use serde_json::Value;
use sqlx::PgExecutor;
use uuid::Uuid;

/// One `audit_log` row; the caller decides the executor, so a row lands in the same
/// transaction as the action it records.
pub struct Audit<'a> {
    pub actor_kind: &'a str,
    pub actor: &'a str,
    pub action: &'a str,
    pub org_id: Option<Uuid>,
    pub object: Option<String>,
    pub outcome: &'a str,
    pub details: Value,
    pub evidence_sha256: Option<Vec<u8>>,
}

impl Audit<'_> {
    pub async fn insert(self, exec: impl PgExecutor<'_>) -> sqlx::Result<()> {
        sqlx::query!(
            "insert into audit_log (actor_kind, actor, action, org_id, object, outcome, details, evidence_sha256)
             values ($1, $2, $3, $4, $5, $6, $7, $8)",
            self.actor_kind,
            self.actor,
            self.action,
            self.org_id,
            self.object,
            self.outcome,
            self.details,
            self.evidence_sha256,
        )
        .execute(exec)
        .await?;
        Ok(())
    }
}

pub fn node<'a>(action: &'a str, outcome: &'a str, details: Value) -> Audit<'a> {
    Audit {
        actor_kind: "node",
        actor: "node",
        action,
        org_id: None,
        object: None,
        outcome,
        details,
        evidence_sha256: None,
    }
}

//! An organization's own model servers, kept in the database so that a new server or a new
//! Revision of one needs no new Revision of the front. A row is seen only by keys of its
//! organization. Its MAC under the App's `api-keys` key covers every column, so a database
//! writer can neither add a row nor point one elsewhere. The connection is pinned to the row's
//! organization too, so not even the admin bearer can send an organization's prompts to an App
//! of another organization.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use alpha_client::tls::Pin;
use alpha_core::ComposeHash;
use hmac::{Hmac, KeyInit, Mac};
use rustls::client::ResolvesClientCert;
use rustls::pki_types::CertificateDer;
use sha2::Sha256;
use sqlx::PgPool;
use uuid::Uuid;

use crate::Error;
use crate::own::{self, ModelServer};

const MAC_CONTEXT: &[u8] = b"alphacompute/inference/model-server/v1";
const MODEL_MAX: usize = 256;

fn mac(
    k: &[u8; 32],
    org_id: Uuid,
    model: &str,
    server: &ModelServer,
) -> Result<Hmac<Sha256>, Error> {
    // JSON escapes every string, so no two rows encode to the same bytes.
    let fields = serde_json::to_vec(&(org_id, model, &server.url, &server.revisions))
        .map_err(|e| Error::internal(format!("model server mac: {e}")))?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(k).map_err(|e| Error::internal(format!("hmac: {e}")))?;
    mac.update(MAC_CONTEXT);
    mac.update(&fields);
    Ok(mac)
}

pub async fn put(
    pool: &PgPool,
    k: &[u8; 32],
    org_id: Uuid,
    model: &str,
    mut server: ModelServer,
) -> Result<(), Error> {
    if model.is_empty() || model.len() > MODEL_MAX {
        return Err(Error::BadRequest(format!(
            "model must be 1 to {MODEL_MAX} bytes"
        )));
    }
    server.url = own::origin(&server.url)
        .ok_or_else(|| Error::BadRequest("url must be an https origin without a path".into()))?;
    if server.revisions.is_empty() {
        return Err(Error::BadRequest("revisions names no Revision".into()));
    }
    let tag = mac(k, org_id, model, &server)?.finalize().into_bytes();
    let revisions: Vec<String> = server.revisions.iter().map(ToString::to_string).collect();
    sqlx::query(
        "insert into model_servers (org_id, model, url, revisions, mac) values ($1, $2, $3, $4, $5)
         on conflict (org_id, model)
         do update set url = excluded.url, revisions = excluded.revisions, mac = excluded.mac",
    )
    .bind(org_id)
    .bind(model)
    .bind(&server.url)
    .bind(revisions)
    .bind(tag.as_slice())
    .execute(pool)
    .await?;
    Ok(())
}

/// True when the row existed.
pub async fn delete(pool: &PgPool, org_id: Uuid, model: &str) -> Result<bool, Error> {
    let done = sqlx::query("delete from model_servers where org_id = $1 and model = $2")
        .bind(org_id)
        .bind(model)
        .execute(pool)
        .await?;
    Ok(done.rows_affected() > 0)
}

type Row = (String, String, Vec<String>, Vec<u8>);

/// The row's server, or `None` when its MAC does not match.
fn verified(k: &[u8; 32], org_id: Uuid, row: Row) -> Result<Option<(String, ModelServer)>, Error> {
    let (model, url, revisions, tag) = row;
    let Ok(revisions) = revisions
        .iter()
        .map(|r| r.parse::<ComposeHash>())
        .collect::<Result<Vec<_>, _>>()
    else {
        return Ok(None);
    };
    let server = ModelServer { url, revisions };
    let live = mac(k, org_id, &model, &server)?.verify_slice(&tag).is_ok();
    Ok(live.then_some((model, server)))
}

pub async fn find(
    pool: &PgPool,
    k: &[u8; 32],
    org_id: Uuid,
    model: &str,
) -> Result<Option<ModelServer>, Error> {
    let row: Option<Row> = sqlx::query_as(
        "select model, url, revisions, mac from model_servers where org_id = $1 and model = $2",
    )
    .bind(org_id)
    .bind(model)
    .fetch_optional(pool)
    .await?;
    match row {
        Some(row) => Ok(verified(k, org_id, row)?.map(|(_, server)| server)),
        None => Ok(None),
    }
}

/// The models of the organization's rows whose MAC matches.
pub async fn names(pool: &PgPool, k: &[u8; 32], org_id: Uuid) -> Result<Vec<String>, Error> {
    let rows: Vec<Row> = sqlx::query_as(
        "select model, url, revisions, mac from model_servers where org_id = $1 order by model",
    )
    .bind(org_id)
    .fetch_all(pool)
    .await?;
    let mut models = Vec::new();
    for row in rows {
        if let Some((model, _)) = verified(k, org_id, row)? {
            models.push(model);
        }
    }
    Ok(models)
}

type Pinned = (ModelServer, Arc<own::Server>);

/// This replica's pinned client per row. Each request still reads its row, so a changed or
/// deleted row takes effect on the next request on every replica.
pub struct Clients {
    kms_ca: CertificateDer<'static>,
    leaf: Arc<dyn ResolvesClientCert>,
    completion_timeout: Duration,
    cached: parking_lot::Mutex<HashMap<(Uuid, String), Pinned>>,
}

impl Clients {
    pub fn new(
        kms_ca: CertificateDer<'static>,
        leaf: Arc<dyn ResolvesClientCert>,
        completion_timeout: Duration,
    ) -> Self {
        Self {
            kms_ca,
            leaf,
            completion_timeout,
            cached: Default::default(),
        }
    }

    pub fn get(
        &self,
        org_id: Uuid,
        model: &str,
        server: &ModelServer,
    ) -> Result<Arc<own::Server>, Error> {
        let mut cached = self.cached.lock();
        let slot = (org_id, model.to_owned());
        if let Some((pinned, client)) = cached.get(&slot)
            && pinned == server
        {
            return Ok(client.clone());
        }
        let pin = Pin::CaOrgAndInstanceRevisions(
            self.kms_ca.clone(),
            org_id.into(),
            server.revisions.clone(),
        );
        let client = Arc::new(own::Server::new(
            &server.url,
            pin,
            self.leaf.clone(),
            self.completion_timeout,
        )?);
        cached.insert(slot, (server.clone(), client.clone()));
        Ok(client)
    }
}

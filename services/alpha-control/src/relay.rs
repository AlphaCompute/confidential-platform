//! `POST /v1/tickets/{ticket}/kms/{op}`: carries a body a roster key signed to the KMS and back.
//! The relay can drop a body, never change one, and it records a step only after the KMS receipt
//! for exactly that body verifies under the platform document's KMS CA. A ticket drives each
//! state-changing step once, and only while it is open.

use std::sync::Arc;

use alpha_attest::PlatformDocument;
use alpha_channel::receipt::{self, Expected};
use alpha_client::{Client, Pin, Signed};
use alpha_core::ComposeHash;
use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use data_encoding::BASE64URL_NOPAD;
use reqwest::Method;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::tickets::{self, Ticket, hash};
use crate::{AppState, Error, platform, stale};

/// One relayed call: the KMS and the document it is pinned to, the ticket, its locked row.
struct Relay<'a> {
    state: &'a AppState,
    document: PlatformDocument,
    version: i64,
    ticket: &'a str,
    found: Ticket,
    tx: Transaction<'static, Postgres>,
    /// The key a claim step registered, named in its audit row.
    key_id: Option<Uuid>,
}

pub async fn relay(
    State(state): State<Arc<AppState>>,
    Path((ticket, op)): Path<(String, String)>,
    headers: HeaderMap,
    body: Result<Json<Value>, JsonRejection>,
) -> Result<Json<Value>, Error> {
    let Json(body) = body?;
    // Refused cheaply before the platform document is fetched: anyone can reach this route.
    let early = tickets::usable(&mut state.pool.begin().await?, &ticket).await?;
    if !allowed(&early.kind, &op) || early.disabled {
        return Err(Error::Forbidden);
    }
    // Fetched before the transaction, so a relay never holds one pool connection while it waits
    // for another.
    let (version, document) = platform(&state).await?;
    // The handshake only opens a sealed channel to a node for the Secret puts that follow; it
    // records nothing, so it holds no lock.
    if op == "channel" {
        let reply = send(&state, &document, Method::POST, "/v1/channel", &body).await?;
        return Ok(Json(reply));
    }
    // ponytail: the ticket and Organization rows stay locked across the KMS call, up to 60 s per
    // endpoint, so a step and a disable of one Organization wait for each other that long. The
    // upgrade is a ticket state `sending` committed before the call and settled after it.
    // The row stays locked until the step is recorded, so two relays of one step cannot both run.
    let mut tx = state.pool.begin().await?;
    let found = tickets::usable(&mut tx, &ticket).await?;
    if found.disabled {
        return Err(Error::Forbidden);
    }
    let mut relay = Relay {
        document,
        version,
        state: &state,
        ticket: &ticket,
        found,
        tx,
        key_id: None,
    };
    let kind = relay.found.kind.clone();
    let (tag, reply) = match (kind.as_str(), op.as_str()) {
        ("claim", "root" | "key") => relay.key(&op, &headers, body).await?,
        ("approve", "secret") => relay.secret(body).await?,
        ("approve", "revision") => relay.revision(body).await?,
        ("approve" | "revoke", "revoke") => relay.revoke(body).await?,
        _ => return Err(Error::Forbidden),
    };
    relay.finish(&op, tag).await?;
    Ok(Json(reply))
}

fn kms_revisions(document: &PlatformDocument) -> Vec<ComposeHash> {
    document
        .kms_revisions
        .iter()
        .map(|r| r.compose_hash)
        .collect()
}

/// One KMS call, pinned to the document's CA and KMS builds. A KMS refusal keeps its code.
async fn send(
    state: &AppState,
    document: &PlatformDocument,
    method: Method,
    path: &str,
    body: &Value,
) -> Result<Value, Error> {
    // The error text names the endpoint, so the caller gets a fixed message and the log the kind.
    let unavailable = |e: alpha_client::Error| {
        alpha_client::warn!("kms_unavailable", error = e.kind());
        Error::Unavailable("the KMS is unavailable".into())
    };
    let ca = alpha_client::tls::cert_from_pem(&document.kms_ca_pem).map_err(unavailable)?;
    let pin = Pin::CaAndRevisions(ca, kms_revisions(document));
    let client = Client::new(state.kms_endpoints.clone(), pin).map_err(unavailable)?;
    client
        .request(method, path, Some(body))
        .await
        .map_err(|e| match &e {
            alpha_client::Error::Api(api) => Error::Kms {
                status: StatusCode::from_u16(api.status).unwrap_or(StatusCode::BAD_GATEWAY),
                code: e.kind(),
            },
            _ => unavailable(e),
        })
}

fn allowed(kind: &str, op: &str) -> bool {
    matches!(
        (kind, op),
        ("claim", "root" | "key")
            | ("approve", "channel" | "secret" | "revision" | "revoke")
            | ("revoke", "revoke")
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyBody {
    credential_id: String,
    registration: Value,
}

/// The signed document of a body; a Secret put carries its value beside it.
fn signed(body: &Value) -> Result<Signed, Error> {
    let part = |name| body.get(name).cloned().unwrap_or_default();
    Signed::deserialize(json!({ "payload": part("payload"), "signature": part("signature") }))
        .map_err(|e| Error::Malformed(format!("body: {e}")))
}

impl Relay<'_> {
    fn fresh(&self, tag: String) -> Result<String, Error> {
        if self.found.used.contains(&tag) {
            return Err(Error::TicketClosed);
        }
        Ok(tag)
    }

    /// Only a passkey the relay carried for this Organization acts through its tickets, so no
    /// other Organization's key can register, revoke or put anything on a ticket of this one.
    async fn own_signer(&mut self, signed: &Signed) -> Result<(), Error> {
        let key_id = signed.signature.key_id.ok_or(Error::Forbidden)?;
        let own: bool = sqlx::query_scalar(
            "select exists (select 1 from credentials where key_id = $1 and org_id = $2)",
        )
        .bind(Uuid::from(key_id))
        .bind(self.found.org_id)
        .fetch_one(&mut *self.tx)
        .await?;
        if !own {
            return Err(Error::Forbidden);
        }
        Ok(())
    }

    /// `root` makes the owner's passkey the Organization's first key; `key` adds one that a key
    /// already in the roster signed.
    async fn key(
        &mut self,
        op: &str,
        headers: &HeaderMap,
        body: Value,
    ) -> Result<(String, Value), Error> {
        let tag = self.fresh(op.to_owned())?;
        let KeyBody {
            credential_id,
            registration,
        } = serde_json::from_value(body).map_err(|e| Error::Malformed(format!("body: {e}")))?;
        if credential_id.is_empty()
            || credential_id.len() > 1024
            || BASE64URL_NOPAD.decode(credential_id.as_bytes()).is_err()
        {
            return Err(Error::Malformed("credential_id is not base64url".into()));
        }
        let signed = signed(&registration)?;
        let org_id = self.found.org_id;
        let expected = if op == "root" {
            // A ticket alone never roots: the owner's sign-in must stand behind this request.
            let presented = headers
                .get("alpha-claim-session")
                .map(|v| Sha256::digest(v.as_bytes()));
            let bound = matches!((presented, &self.found.session_sha256), (Some(p), Some(s))
                if alpha_client::bearer_matches(&p, s));
            if !bound || self.found.rooted {
                return Err(Error::SessionRefused);
            }
            if signed.signature.key_id.is_some()
                || signed.payload.get("org_id") != Some(&json!(org_id))
                || signed.payload.get("principal_id") != self.found.owner.map(|o| json!(o)).as_ref()
            {
                return Err(Error::Malformed(
                    "a root registration is self-signed for this Organization and its owner".into(),
                ));
            }
            // The KMS answers a repeated key with its stored row, which may name another holder.
            json!({
                "org_id": org_id, "public_key": signed.payload.get("public_key"),
                "principal_id": self.found.owner,
            })
        } else {
            // Without a signer in the roster the KMS would take it as a root claim; and the key is
            // the one of the holder the ticket names.
            if signed.payload.get("principal_id")
                != self.found.principal_id.map(|p| json!(p)).as_ref()
            {
                return Err(Error::Forbidden);
            }
            self.own_signer(&signed).await?;
            json!({ "org_id": org_id })
        };
        // A repeated root is answered with its stored row; a repeated other key is
        // `already_exists`, so only a root may be checked after the call.
        let reply = if op == "root" {
            self.repeatable(Method::POST, "/v1/keys", &registration)
                .await?
        } else {
            self.kms(Method::POST, "/v1/keys", &registration).await?
        };
        let response = self.confirm("key.register", &registration, expected, &reply)?;
        let key_id: Uuid = response
            .get("id")
            .and_then(|id| Uuid::deserialize(id).ok())
            .filter(|id| reply.get("id") == Some(&json!(id)))
            .ok_or(Error::UpstreamInvalid)?;
        self.key_id = Some(key_id);
        sqlx::query(
            "insert into credentials (key_id, org_id, credential_id) values ($1, $2, $3) \
             on conflict (key_id) do nothing",
        )
        .bind(key_id)
        .bind(org_id)
        .bind(&credential_id)
        .execute(&mut *self.tx)
        .await?;
        if op == "root" {
            sqlx::query("update organizations set rooted_at = now() where id = $1")
                .bind(org_id)
                .execute(&mut *self.tx)
                .await?;
            // The owner may add one more key on this ticket, as the holder it now names.
            sqlx::query("update tickets set principal_id = $1 where ticket = $2")
                .bind(self.found.owner)
                .bind(self.ticket)
                .execute(&mut *self.tx)
                .await?;
        }
        Ok((tag, reply))
    }

    /// A Secret of the ticket's App, named `<app_id>.<name>` at the KMS and readable by that App
    /// alone.
    async fn secret(&mut self, body: Value) -> Result<(String, Value), Error> {
        let signed = signed(&body)?;
        let app_id = self.found.app_id.ok_or(Error::Forbidden)?;
        let full = signed
            .payload
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let name = full
            .strip_prefix(&format!("{app_id}."))
            .filter(|name| alpha_core::is_secret_name(name))
            .ok_or_else(|| Error::Malformed(format!("name must be {app_id}.<name>")))?;
        if signed.payload.get("app_ids") != Some(&json!([app_id])) {
            return Err(Error::Malformed(format!("app_ids must be [{app_id}]")));
        }
        let tag = self.fresh(format!("secret:{name}"))?;
        self.own_signer(&signed).await?;
        let reply = self
            .kms(Method::PUT, &format!("/v1/secrets/{full}"), &body)
            .await?;
        let expected = json!({ "name": full, "org_id": self.found.org_id });
        self.confirm("secret.put", &body, expected, &reply)?;
        sqlx::query(
            "insert into app_secrets (app_id, name) values ($1, $2) on conflict do nothing",
        )
        .bind(app_id)
        .bind(name)
        .execute(&mut *self.tx)
        .await?;
        Ok((tag, reply))
    }

    /// The ticket's Revision, exactly the bytes the approval names.
    async fn revision(&mut self, body: Value) -> Result<(String, Value), Error> {
        let tag = self.fresh("revision".into())?;
        let signed = signed(&body)?;
        let hash = hash(self.found.compose_hash.as_deref()).ok_or(Error::Forbidden)?;
        let app_id = self.found.app_id.ok_or(Error::Forbidden)?;
        if signed.payload.get("app_id") != Some(&json!(app_id))
            || signed.payload.get("digest") != Some(&json!(hash))
        {
            return Err(Error::Malformed(
                "the payload must name the ticket's App and Revision".into(),
            ));
        }
        self.own_signer(&signed).await?;
        // The KMS answers a revoked Revision's registration with its stored row, so the relay
        // must not record an approval that would bring nothing back to life.
        let revoked: bool = sqlx::query_scalar(
            "select revoked_at is not null from revisions where compose_hash = $1 for share",
        )
        .bind(hash.as_bytes().as_slice())
        .fetch_one(&mut *self.tx)
        .await?;
        if revoked {
            return Err(Error::Conflict("the Revision is revoked"));
        }
        let reply = self
            .repeatable(Method::POST, "/v1/revisions", &body)
            .await?;
        let expected =
            json!({ "compose_hash": hash, "app_id": app_id, "org_id": self.found.org_id });
        self.confirm("revision.register", &body, expected, &reply)?;
        sqlx::query(
            "update revisions set registered_at = coalesce(registered_at, clock_timestamp()) \
             where compose_hash = $1",
        )
        .bind(hash.as_bytes().as_slice())
        .execute(&mut *self.tx)
        .await?;
        Ok((tag, reply))
    }

    /// An approval revokes only the Revision it replaces; a `revoke` ticket only its own.
    async fn revoke(&mut self, body: Value) -> Result<(String, Value), Error> {
        let signed = signed(&body)?;
        let approve = self.found.kind == "approve";
        let allowed = hash(if approve {
            self.found.predecessor.as_deref()
        } else {
            self.found.compose_hash.as_deref()
        });
        let hash = allowed
            .filter(|h| signed.payload.get("compose_hash") == Some(&json!(h)))
            .ok_or(Error::Forbidden)?;
        if approve && !self.found.used.iter().any(|u| u == "revision") {
            return Err(Error::Conflict(
                "the replacement Revision is not registered yet",
            ));
        }
        let tag = self.fresh(format!("revoke:{hash}"))?;
        self.own_signer(&signed).await?;
        let reply = self
            .repeatable(Method::POST, &format!("/v1/revisions/{hash}/revoke"), &body)
            .await?;
        let expected = json!({ "compose_hash": hash });
        self.confirm("revision.revoke", &body, expected, &reply)?;
        sqlx::query(
            "update revisions set revoked_at = coalesce(revoked_at, clock_timestamp()) where compose_hash = $1",
        )
        .bind(hash.as_bytes().as_slice())
        .execute(&mut *self.tx)
        .await?;
        Ok((tag, reply))
    }

    /// Records the step; the ticket is done once its last step ran: the key of a claim, the
    /// registration and the predecessor's revocation of an approval, the revocation of a revoke.
    async fn finish(mut self, op: &str, tag: String) -> Result<(), Error> {
        let mut used = std::mem::take(&mut self.found.used);
        used.push(tag.clone());
        let revoked =
            |hash: Option<ComposeHash>| hash.is_none_or(|h| used.contains(&format!("revoke:{h}")));
        let done = match self.found.kind.as_str() {
            "claim" => tag == "key",
            "approve" => {
                used.iter().any(|u| u == "revision")
                    && revoked(hash(self.found.predecessor.as_deref()))
            }
            _ => revoked(hash(self.found.compose_hash.as_deref())),
        };
        sqlx::query(
            "update tickets set used = $1, state = case when $2 then 'done' else state end \
             where ticket = $3",
        )
        .bind(&used)
        .bind(done)
        .bind(self.ticket)
        .execute(&mut *self.tx)
        .await?;
        sqlx::query(
            "insert into audit_log (actor, org_id, action, object) values ('ticket', $1, $2, $3)",
        )
        .bind(self.found.org_id)
        .bind(format!("relay.{op}"))
        .bind(self.key_id.map_or(tag, |id| id.to_string()))
        .execute(&mut *self.tx)
        .await?;
        self.tx.commit().await?;
        Ok(())
    }

    async fn kms(&mut self, method: Method, path: &str, body: &Value) -> Result<Value, Error> {
        self.current().await?;
        send(self.state, &self.document, method, path, body).await
    }

    /// For a call the KMS answers the same way when repeated (a root for the same key, a
    /// registered Revision, a revocation): the version and the expiry are checked after the
    /// reply, so the `platform_version` lock is not held across the call, and a step refused
    /// there records nothing and succeeds on a retry.
    async fn repeatable(
        &mut self,
        method: Method,
        path: &str,
        body: &Value,
    ) -> Result<Value, Error> {
        let reply = send(self.state, &self.document, method, path, body).await?;
        self.current().await?;
        Ok(reply)
    }

    /// Refuses a step checked under a document older than the accepted one, or a ticket that
    /// expired while the lock waited. The share lock holds to the commit, so no newer version is
    /// accepted before the step is recorded.
    async fn current(&mut self) -> Result<(), Error> {
        let accepted: i64 =
            sqlx::query_scalar("select version from platform_version where one = 1 for share")
                .fetch_one(&mut *self.tx)
                .await?;
        if self.version < accepted {
            return Err(stale(self.version, accepted));
        }
        // The version lock may have waited past the ticket's expiry.
        let open: bool = sqlx::query_scalar(
            "select expires_at > clock_timestamp() from tickets where ticket = $1",
        )
        .bind(self.ticket)
        .fetch_one(&mut *self.tx)
        .await?;
        if !open {
            return Err(Error::TicketExpired);
        }
        Ok(())
    }

    /// The response the receipt signs for `request` at `route`, if it carries every `expected`
    /// value.
    fn confirm(
        &self,
        route: &str,
        request: &Value,
        expected: Value,
        reply: &Value,
    ) -> Result<Value, Error> {
        let receipt = reply.get("receipt").ok_or(Error::UpstreamInvalid)?;
        let expected = Expected {
            route: route.into(),
            request_sha256: receipt::request_sha256(request).map_err(|_| Error::UpstreamInvalid)?,
            response: expected.as_object().cloned().unwrap_or_default(),
        };
        let receipt = serde_json::to_vec(receipt).map_err(|_| Error::UpstreamInvalid)?;
        receipt::verify(
            &receipt,
            &self.document.kms_ca_pem,
            &kms_revisions(&self.document),
            &expected,
        )
        .map_err(|_| Error::UpstreamInvalid)
    }
}

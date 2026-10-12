//! Who holds what in a DSM account: parsed from an export, or read live with a read-only login.
//!
//! The export is three DSM REST replies side by side, so the customer's security admin can make
//! it with three calls (`docs/fortanix-tenancy-check.md`):
//!
//! ```json
//! {"users": <GET /sys/v1/users>, "apps": <GET /sys/v1/apps>, "groups": <GET /sys/v1/groups>}
//! ```
//!
//! The field names read here (`user_id`, `user_email`, `account_role`, `groups`, `app_id`,
//! `name`, `group_id`) are from DSM's published REST reference as we read it, not confirmed
//! against a pilot account: assumption `dsm-listing` (F3). Unknown fields are ignored, because
//! the shape is Fortanix's; a role or permission value this module does not know becomes
//! [`Right::Unknown`], which counts as admin.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use rustls::ClientConfig;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use super::{Error, Grant, Listing, Principal, PrincipalKind, Right, Service, ServiceAccount};
use crate::KeyExchange;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
/// Page size for the live read, and how many pages before the read gives up rather than
/// report on a partial listing.
const PAGE: usize = 100;
const MAX_PAGES: usize = 200;

/// `account_role` is an array in the reference; a lone string is accepted as one role.
#[derive(Deserialize)]
#[serde(untagged)]
enum Roles {
    Many(Vec<String>),
    One(String),
}

#[derive(Deserialize)]
struct User {
    user_id: String,
    #[serde(default)]
    user_email: Option<String>,
    #[serde(default)]
    account_role: Option<Roles>,
    /// group id → the user's roles in that group.
    #[serde(default)]
    groups: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
struct App {
    app_id: String,
    #[serde(default)]
    name: Option<String>,
    /// group id → the App's permissions in that group.
    #[serde(default)]
    groups: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
struct Group {
    group_id: String,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize)]
struct Export {
    users: Vec<User>,
    apps: Vec<App>,
    #[serde(default)]
    groups: Vec<Group>,
}

/// QUESTION(PRD-06 Q1), assumption `dsm-roles` (F3).
fn user_right(role: &str) -> Right {
    match super::normalize(role).as_str() {
        "ACCOUNTADMINISTRATOR" | "GROUPADMINISTRATOR" => Right::Admin,
        "ACCOUNTAUDITOR" | "GROUPAUDITOR" => Right::ReadOnly,
        "ACCOUNTMEMBER" => Right::Member,
        _ => Right::Unknown,
    }
}

/// QUESTION(PRD-06 Q2), assumption `dsm-app-permissions` (F3).
fn app_right(permission: &str) -> Right {
    match super::normalize(permission).as_str() {
        "SIGN" | "VERIFY" | "ENCRYPT" | "DECRYPT" | "WRAPKEY" | "UNWRAPKEY" | "DERIVEKEY"
        | "MACGENERATE" | "MACVERIFY" | "EXPORT" | "AGREEKEY" | "MASKDECRYPT" | "TRANSFORM" => {
            Right::KeyUse
        }
        "AUDIT" => Right::ReadOnly,
        "MANAGE" => Right::Admin,
        _ => Right::Unknown,
    }
}

/// The strings in a group entry; anything but an array of strings is one unknown grant, so a
/// shape this module does not understand fails closed instead of reading as "no rights".
fn group_values(value: &Value) -> Vec<String> {
    match value {
        Value::Array(items) if items.iter().all(Value::is_string) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        other => vec![format!("<unparsed: {}>", truncate(&other.to_string()))],
    }
}

fn truncate(s: &str) -> String {
    s.chars().take(80).collect()
}

fn scope(group_names: &BTreeMap<&str, &str>, id: &str) -> String {
    match group_names.get(id) {
        Some(name) => format!("group {name} ({id})"),
        None => format!("group {id}"),
    }
}

/// Parses an export (see the module docs). `source` names it in the report.
pub fn parse_export(bytes: &[u8], source: String) -> Result<Listing, Error> {
    let export: Export =
        serde_json::from_slice(bytes).map_err(|e| Error::Input(format!("DSM listing: {e}")))?;
    let names: BTreeMap<&str, &str> = export
        .groups
        .iter()
        .filter_map(|g| g.name.as_deref().map(|n| (g.group_id.as_str(), n)))
        .collect();
    let mut principals = Vec::new();
    for u in &export.users {
        let mut grants = Vec::new();
        let account_roles = u
            .account_role
            .as_ref()
            .map(|r| match r {
                Roles::Many(v) => v.clone(),
                Roles::One(s) => vec![s.clone()],
            })
            .unwrap_or_default();
        for role in account_roles {
            grants.push(Grant {
                scope: "account".into(),
                right: user_right(&role),
                role,
                assumption: "dsm-roles",
            });
        }
        for (group, roles) in &u.groups {
            for role in group_values(roles) {
                grants.push(Grant {
                    scope: scope(&names, group),
                    right: user_right(&role),
                    role,
                    assumption: "dsm-roles",
                });
            }
        }
        principals.push(Principal {
            service: Service::Dsm,
            kind: PrincipalKind::User,
            id: u.user_id.clone(),
            name: None,
            email: u.user_email.clone(),
            grants,
        });
    }
    for a in &export.apps {
        let mut grants = Vec::new();
        for (group, permissions) in &a.groups {
            for permission in group_values(permissions) {
                grants.push(Grant {
                    scope: scope(&names, group),
                    right: app_right(&permission),
                    role: permission,
                    assumption: "dsm-app-permissions",
                });
            }
        }
        principals.push(Principal {
            service: Service::Dsm,
            kind: PrincipalKind::App,
            id: a.app_id.clone(),
            name: a.name.clone(),
            email: None,
            grants,
        });
    }
    // TODO(draft): DSM plugins, account-level quorum (approval) policies and external-KMS
    // groups can also move or release keys; F3 should say whether any of them is a key-admin
    // right that this listing misses.
    Ok(Listing {
        service: Service::Dsm,
        source,
        sha256: super::sha256_hex(bytes),
        assumptions: vec!["dsm-listing"],
        principals,
    })
}

/// A read-only login the customer granted for this check (purpose `audit` in the account
/// record). Read from a file, never from the command line.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditorLogin {
    pub email: String,
    pub password: Zeroizing<String>,
}

impl std::fmt::Debug for AuditorLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditorLogin")
            .field("email", &self.email)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct Session {
    #[serde(default)]
    access_token: Option<Zeroizing<String>>,
    /// A user with two-factor auth gets a challenge instead of a usable session.
    #[serde(default)]
    mfa_challenge: Option<Value>,
}

#[derive(Serialize)]
struct SelectAccount<'a> {
    acct_id: &'a str,
}

fn http(account: &ServiceAccount, key_exchange: KeyExchange) -> Result<reqwest::Client, Error> {
    let ca_pem = account.ca_pem.as_deref().ok_or_else(|| {
        Error::Input("a live DSM read needs the DSM's CA in the account record (dsm.ca_pem)".into())
    })?;
    let versions = match key_exchange {
        KeyExchange::Hybrid => ClientConfig::builder_with_provider(alpha_client::tls::provider())
            .with_protocol_versions(&[&rustls::version::TLS13]),
        KeyExchange::ClassicalAllowed => ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions(),
    };
    let tls = versions
        .map_err(|e| crate::Error::Config(format!("tls: {e}")))?
        .with_root_certificates(crate::roots(ca_pem)?)
        .with_no_client_auth();
    reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|e| Error::Dsm(crate::Error::Config(format!("http client: {e}"))))
}

async fn get_all(http: &reqwest::Client, url: &str, token: &str) -> Result<Vec<Value>, Error> {
    let mut all = Vec::new();
    for page in 0..MAX_PAGES {
        let offset = page.saturating_mul(PAGE);
        let reply = http
            .get(format!("{url}?limit={PAGE}&offset={offset}"))
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| crate::Error::Transport(e.to_string()))?;
        let items: Vec<Value> = crate::read(reply).await?;
        let last = items.len() < PAGE;
        all.extend(items);
        if last {
            return Ok(all);
        }
    }
    Err(Error::Input(format!(
        "{url}: more than {} entries; refusing to report on a partial listing",
        MAX_PAGES.saturating_mul(PAGE)
    )))
}

/// Reads users, apps and groups live and returns them in the export's shape, so the same parser
/// reads both and the bytes can be kept with the audit record.
///
/// QUESTION(PRD-06 Q4), assumption `dsm-listing` (F3): the endpoints, the paging, and whether an
/// ACCOUNTAUDITOR login may list every principal.
/// QUESTION(PRD-06 Q6): whether AlphaCompute should hold this login at all.
pub async fn fetch(
    account: &ServiceAccount,
    login: &AuditorLogin,
    key_exchange: KeyExchange,
) -> Result<Vec<u8>, Error> {
    let http = http(account, key_exchange)?;
    let base = account.endpoint.trim_end_matches('/');
    let reply = http
        .post(format!("{base}/sys/v1/session/auth"))
        .basic_auth(&login.email, Some(login.password.as_str()))
        .send()
        .await
        .map_err(|e| crate::Error::Transport(e.to_string()))?;
    let session: Session = crate::read(reply).await?;
    if session.mfa_challenge.is_some() {
        // TODO(draft): an auditor login with two-factor auth. Until then, use an export.
        return Err(Error::NotImplemented(
            "the DSM login asks for a second factor; ask the customer for an export instead".into(),
        ));
    }
    let token = session
        .access_token
        .ok_or_else(|| Error::Input("DSM session: no access_token".into()))?;
    let result = async {
        let reply = http
            .post(format!("{base}/sys/v1/session/select_account"))
            .bearer_auth(token.as_str())
            .json(&SelectAccount {
                acct_id: &account.account_id,
            })
            .send()
            .await
            .map_err(|e| crate::Error::Transport(e.to_string()))?;
        let _: Value = crate::read(reply).await?;
        let users = get_all(&http, &format!("{base}/sys/v1/users"), &token).await?;
        let apps = get_all(&http, &format!("{base}/sys/v1/apps"), &token).await?;
        let groups = get_all(&http, &format!("{base}/sys/v1/groups"), &token).await?;
        serde_json::to_vec_pretty(&serde_json::json!({
            "users": users, "apps": apps, "groups": groups,
        }))
        .map_err(|e| Error::Input(format!("DSM listing: {e}")))
    }
    .await;
    // Best effort: the session ends whether or not the read succeeded.
    let _ = http
        .post(format!("{base}/sys/v1/session/terminate"))
        .bearer_auth(token.as_str())
        .send()
        .await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_users_apps_and_groups_and_classifies_each_grant() {
        let export = br#"{
          "users": [
            {"user_id":"u-1","user_email":"sec@acme.example","account_role":["ACCOUNTADMINISTRATOR"],"groups":{}},
            {"user_id":"u-2","user_email":"aud@acme.example","account_role":"ACCOUNTAUDITOR",
             "groups":{"g-1":["GROUPAUDITOR"],"g-2":{"weird":true}}},
            {"user_id":"u-3","account_role":["0f9c-custom-role"]}
          ],
          "apps": [
            {"app_id":"a-1","name":"I1 workload","groups":{"g-1":["EXPORT","ENCRYPT"]},"extra":1},
            {"app_id":"a-2","name":"manager","groups":{"g-1":["MANAGE","AUDIT"]}}
          ],
          "groups": [{"group_id":"g-1","name":"pilot keys"}]
        }"#;
        let l = parse_export(export, "export:x".into()).unwrap();
        assert_eq!(l.principals.len(), 5);
        let by = |id: &str| l.principals.iter().find(|p| p.id == id).unwrap();
        assert_eq!(by("u-1").strongest(), Some(Right::Admin));
        // An unparsed group entry fails closed.
        assert_eq!(by("u-2").strongest(), Some(Right::Unknown));
        assert!(
            by("u-2")
                .grants
                .iter()
                .any(|g| g.scope == "group pilot keys (g-1)")
        );
        // A custom role is unknown.
        assert_eq!(by("u-3").strongest(), Some(Right::Unknown));
        assert_eq!(by("a-1").strongest(), Some(Right::KeyUse));
        assert_eq!(by("a-2").strongest(), Some(Right::Admin));
        assert_eq!(l.sha256.len(), 64);
    }

    #[test]
    fn a_listing_missing_users_or_apps_is_refused() {
        assert!(parse_export(br#"{"apps":[]}"#, "x".into()).is_err());
        assert!(parse_export(br#"{"users":[]}"#, "x".into()).is_err());
        assert!(parse_export(b"not json", "x".into()).is_err());
    }

    #[test]
    fn the_login_password_stays_out_of_debug() {
        let login: AuditorLogin =
            serde_json::from_str(r#"{"email":"a@b","password":"hunter2"}"#).unwrap();
        assert!(!format!("{login:?}").contains("hunter2"));
    }
}

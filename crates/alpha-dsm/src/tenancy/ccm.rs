//! Who holds what in a CCM account.
//!
//! CCM's listing API is not known to us, so this draft reads only an export in a shape of its
//! own, `alphacompute-ccm-listing/0`, which the customer's security admin fills in from CCM:
//!
//! ```json
//! {"format": "alphacompute-ccm-listing/0",
//!  "users": [{"id": "...", "email": "...", "roles": ["ACCOUNT_ADMINISTRATOR"]}],
//!  "service_principals": [{"id": "...", "name": "...", "roles": ["..."]}]}
//! ```
//!
//! QUESTION(PRD-06 Q5), assumption `ccm-listing` (F3): what CCM lists and how. Once Fortanix
//! answers, this module reads CCM's own export or API, like [`super::dsm`].
//! QUESTION(PRD-06 Q3), assumption `ccm-roles` (F3): the role names and which are policy rights.

use serde::Deserialize;

use super::{Error, Grant, Listing, Principal, PrincipalKind, Right, Service, ServiceAccount};

pub const LISTING_FORMAT: &str = "alphacompute-ccm-listing/0";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    id: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    name: Option<String>,
    roles: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Export {
    format: String,
    users: Vec<Entry>,
    service_principals: Vec<Entry>,
}

/// Assumption `ccm-roles`. ACCOUNT_MEMBER counts as a policy right until F3 says a member
/// cannot approve builds, apps or nodes.
fn right(role: &str) -> Right {
    match super::normalize(role).as_str() {
        "ACCOUNTADMINISTRATOR" | "ACCOUNTMEMBER" => Right::Admin,
        "READONLY" | "ACCOUNTAUDITOR" => Right::ReadOnly,
        _ => Right::Unknown,
    }
}

fn principal(kind: PrincipalKind, e: Entry) -> Principal {
    Principal {
        service: Service::Ccm,
        kind,
        grants: e
            .roles
            .into_iter()
            .map(|role| Grant {
                scope: "account".into(),
                right: right(&role),
                role,
                assumption: "ccm-roles",
            })
            .collect(),
        id: e.id,
        name: e.name,
        email: e.email,
    }
}

pub fn parse_export(bytes: &[u8], source: String) -> Result<Listing, Error> {
    let export: Export =
        serde_json::from_slice(bytes).map_err(|e| Error::Input(format!("CCM listing: {e}")))?;
    if export.format != LISTING_FORMAT {
        return Err(Error::Input(format!(
            "CCM listing: format is {:?}, not {LISTING_FORMAT}",
            export.format
        )));
    }
    let principals = export
        .users
        .into_iter()
        .map(|e| principal(PrincipalKind::User, e))
        .chain(
            export
                .service_principals
                .into_iter()
                .map(|e| principal(PrincipalKind::App, e)),
        )
        .collect();
    Ok(Listing {
        service: Service::Ccm,
        source,
        sha256: super::sha256_hex(bytes),
        assumptions: vec!["ccm-listing"],
        principals,
    })
}

/// A live CCM read. Not implemented: it refuses, naming the question that blocks it.
pub async fn fetch(_account: &ServiceAccount) -> Result<Vec<u8>, Error> {
    // TODO(draft): read CCM's users and API principals live once F3 names the API and a
    // read-only role that may call it (QUESTION(PRD-06 Q5)).
    Err(Error::NotImplemented(
        "a live CCM read: CCM's listing API and a read-only role are Fortanix question F3; \
         use --ccm-listing with the customer's export"
            .into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_draft_shape_and_counts_members_as_policy_holders() {
        let l = parse_export(
            br#"{"format":"alphacompute-ccm-listing/0",
                 "users":[{"id":"c-1","email":"a@acme.example","roles":["Account Member"]},
                          {"id":"c-2","email":"b@acme.example","roles":["READ_ONLY"]}],
                 "service_principals":[{"id":"s-1","name":"ci","roles":["BUILD_APPROVER"]}]}"#,
            "export:c".into(),
        )
        .unwrap();
        let by = |id: &str| l.principals.iter().find(|p| p.id == id).unwrap();
        assert_eq!(by("c-1").strongest(), Some(Right::Admin));
        assert_eq!(by("c-2").strongest(), Some(Right::ReadOnly));
        assert_eq!(by("s-1").strongest(), Some(Right::Unknown));
    }

    #[test]
    fn refuses_another_shape() {
        assert!(
            parse_export(
                br#"{"format":"x","users":[],"service_principals":[]}"#,
                "c".into()
            )
            .is_err()
        );
        assert!(
            parse_export(
                br#"{"format":"alphacompute-ccm-listing/0","users":[{"id":"x","roles":[],"extra":1}],"service_principals":[]}"#,
                "c".into()
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn the_live_read_refuses_naming_f3() {
        let account = ServiceAccount {
            endpoint: "https://ccm.example".into(),
            account_id: "a".into(),
            ca_pem: None,
        };
        let e = fetch(&account).await.unwrap_err().to_string();
        assert!(e.contains("F3"), "{e}");
    }
}

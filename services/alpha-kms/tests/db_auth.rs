//! D10 (draft): a KMS node's client certificate against a real Postgres configured as
//! `docs/db-client-auth.md` says. Both tests are skipped unless their variable is set; the shared
//! CI Postgres uses password authentication, so CI runs neither. `docs/db-client-auth.md`, "Trying
//! it", starts the cert-auth Postgres they need.

#![allow(clippy::unwrap_used)]

use std::time::SystemTime;

use alpha_kms::db_auth::{self, ClientCa, ROLE};
use sqlx::Connection;
use sqlx::postgres::{PgConnectOptions, PgConnection, PgSslMode};

/// The volume key the cert-auth Postgres is set up for.
const KEY: [u8; 32] = [0x5a; 32];

/// With `ALPHACOMPUTE_DB_AUTH_PG_DIR`, writes the Postgres pod's side for [`KEY`] there:
/// `root.crt` (the derived CA), `server.crt`, `server.key`, `pg_hba.conf`, `pg_ident.conf`.
#[test]
fn write_postgres_side() {
    let Ok(dir) = std::env::var("ALPHACOMPUTE_DB_AUTH_PG_DIR") else {
        eprintln!("ALPHACOMPUTE_DB_AUTH_PG_DIR unset; skipped");
        return;
    };
    let dir = std::path::Path::new(&dir);
    let ca = ClientCa::derive(&KEY).unwrap();
    let server = db_auth::issue_server(&ca, &["localhost"], SystemTime::now()).unwrap();
    let key_pem = pem::encode(&pem::Pem::new("PRIVATE KEY", server.key_pkcs8.to_vec()));
    std::fs::write(dir.join("root.crt"), ca.cert_pem()).unwrap();
    std::fs::write(
        dir.join("server.crt"),
        alpha_kms::certs::pem(&server.cert_der),
    )
    .unwrap();
    std::fs::write(dir.join("server.key"), key_pem).unwrap();
    std::fs::write(dir.join("pg_hba.conf"), db_auth::PG_HBA).unwrap();
    std::fs::write(dir.join("pg_ident.conf"), db_auth::PG_IDENT).unwrap();
}

/// With `ALPHACOMPUTE_DB_AUTH_URL` (e.g. `postgres://alpha_kms_node@localhost:55433/alpha`), a node
/// leaf from [`KEY`]'s CA connects as `alpha_kms_node`; no certificate, another key's leaf, and a
/// server outside the CA are each refused.
#[tokio::test]
async fn a_node_leaf_reaches_a_cert_auth_postgres_and_nothing_else_does() {
    let Ok(url) = std::env::var("ALPHACOMPUTE_DB_AUTH_URL") else {
        eprintln!("ALPHACOMPUTE_DB_AUTH_URL unset; skipped");
        return;
    };
    let base: PgConnectOptions = url.parse().unwrap();
    let ca = ClientCa::derive(&KEY).unwrap();
    let leaf = db_auth::issue_client(&ca, b"node a", SystemTime::now()).unwrap();
    let options = db_auth::connect_options(&base, &ca, &leaf);
    let mut conn = PgConnection::connect_with(&options).await.unwrap();
    let user: String = sqlx::query_scalar("select current_user::text")
        .fetch_one(&mut conn)
        .await
        .unwrap();
    assert_eq!(user, ROLE);
    conn.close().await.unwrap();

    // No client certificate: the server's CA pinned, but nothing to present.
    let bare = base
        .clone()
        .username(ROLE)
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert_from_pem(ca.cert_pem().into_bytes());
    let refused = PgConnection::connect_with(&bare).await.err().unwrap();
    assert!(refused.to_string().contains("certificate"), "{refused}");

    // A leaf from another volume key's CA, server still pinned to the right one.
    let other = ClientCa::derive(&[0x11; 32]).unwrap();
    let foreign = db_auth::issue_client(&other, b"node b", SystemTime::now()).unwrap();
    let mixed = db_auth::connect_options(&base, &ca, &foreign)
        .ssl_client_cert_from_pem(alpha_kms::certs::pem(&foreign.cert_der));
    assert!(PgConnection::connect_with(&mixed).await.is_err());

    // The node pins the server to its own CA: a Postgres outside it is never sent a query.
    let wrong_server = db_auth::connect_options(&base, &other, &foreign);
    assert!(PgConnection::connect_with(&wrong_server).await.is_err());
}

# D10 (proposed): how a KMS node authenticates to the trust-zone Postgres

**Status: proposed, awaiting Ryan Tharp's security sign-off. Nothing here has run in a Kata pod.** Code: `services/alpha-kms/src/db_auth.rs`, wired into `main.rs`, `db_volume::enter`, `node::bootstrap`, `node::join_request` / `finish_join` and the platform tick. Tests: the unit tests in `db_auth.rs`; `services/alpha-kms/tests/db_auth.rs` and the client-cert join in `services/alpha-kms/tests/kata_node.rs` against a real cert-auth Postgres (below; CI's db-tests job starts one).

## The problem

A prototype KMS node read its database password from its encrypted, unmeasured env. A Kata KMS node has no such env: its agent policy allows measured env only, and `GET /v1/node/evidence` serves its init-data, and so every env value, to anyone (#87). A password there is published. Kubernetes Secrets are refused in attested namespaces.

## The proposal: mutual TLS under a CA only attested parties hold

```
db-volume key (#103) ──HKDF-SHA256 "alphacompute-kms/db-client-ca/v1"──▶ P-256 CA key ("alpha-kms db client CA")
        │                                                                     │
        ├─ custodian share files (wrapped under the root KEK)                  ├─ each KMS node: a one-hour client leaf, CN kms-node-<16 hex>
        ├─ join reply                                                          └─ the Postgres pod: its server certificate, root.crt
        └─ POST /v1/node/db-key → the attested Postgres pod
```

- **Who can hold the CA key.** Exactly the parties that can hold the db-volume key: a node unsealed by custodians, a node that joined, a node that ran genesis, and the Postgres pod `POST /v1/node/db-key` appraised as a listed `db_revisions` build. Each was attested first. "Presents a leaf from this CA" therefore means "was attested", without Postgres appraising anything itself.
- **The node's leaf.** A fresh P-256 key generated in memory on every issue, never written anywhere; CN `kms-node-<first 16 hex of SHA-256(runtime SPKI)>`, URI SAN `alphacompute://kms-db-client/<SHA-256(runtime SPKI)>`, EKU clientAuth, one hour. It is renewed on the five-minute platform tick and in the wait-for-database loop once less than 30 minutes are left.
- **The server.** The node's connection uses `sslmode=verify-full` with the derived CA as its only root, so it never sends a query to a database other than one holding the volume key. `db_auth::issue_server` makes that certificate; nothing in the Postgres pod calls it yet.
- **No password exists** anywhere: not in the env, not in a Secret, not in the database.
- **Cold start works**: the CA exists as soon as the volume key does, before the database opens, so the order stays **unseal → db key → database → serve**, and the node's first connection already carries its leaf (`db_volume::enter`).
- **The CA never rotates**: the volume key's value never changes (#102, #103). A leaked leaf expires within an hour; a leaked CA key is a leaked volume key, which is already the worse problem.

### Postgres

`pg_hba.conf` (`db_auth::PG_HBA`):

```
local   all  all                    trust
hostssl all  alpha_kms_node  0.0.0.0/0   cert  clientcert=verify-full  map=alpha-kms
hostssl all  alpha_kms_node  ::/0        cert  clientcert=verify-full  map=alpha-kms
```

`pg_ident.conf` (`db_auth::PG_IDENT`):

```
alpha-kms  /^kms-node-[0-9a-f]{16}$     alpha_kms_node
```

`postgresql.conf`: `ssl = on`, `ssl_ca_file = root.crt` (the derived CA), `ssl_cert_file`/`ssl_key_file` from `issue_server`, `ssl_min_protocol_version = TLSv1.3`, `log_connections = authentication` (each connection is then logged with the node's CN). The role: `create role alpha_kms_node login in role alpha_kms;` (`alpha_kms` is the migration's `nologin` group role).

### The KMS

`ALPHACOMPUTE_DATABASE_AUTH=client-cert` and a URL without a password, e.g. `postgres://alpha_kms_node@postgres.alpha-verifier.svc:5432/alpha`. The node refuses a URL with a password, an `sslmode` other than `verify-full`, `sslcert`/`sslkey`/`sslrootcert`, and a user other than `alpha_kms_node`. In the default `url` mode a Kata node (`ALPHACOMPUTE_QUOTE_SOURCE` set) still refuses a URL with a password.

### Join

A joining node used to write its own `node.join.request` row before the join, and the serving node refuses a join without one: the row proved the joiner reaches *this* deployment's database. A client-cert joiner has no database credential until the join reply hands it the volume key, so it cannot write it. Q46 is implemented as proposed (subject to Ryan Tharp's sign-off):

1. A Kata node in client-cert mode writes no row; its `POST /v1/node/join` request sets `db_client_cert: true`. In `url` mode the field is left out and the joiner writes its row as before, so that request is unchanged on the wire.
2. The serving node refuses `db_client_cert` with prototype evidence (`policy_denied`, before appraisal): a prototype node's env is not measured, so it always writes its own row. A prototype node in client-cert mode refuses to join for the same reason.
3. Otherwise the serving node appraises the joiner as before. Only once it is an attested Kata node whose Revision v2 is a `kata-tdx` entry of the release-signed `kms_revisions` does the serving node write the `node.join.request` row itself (`recorded_by: "serving node"`, `database_auth: "client-cert"`, the joiner's runtime key and Revision, sealed like any serving node's row). The row's job moves into attestation: the joiner's database URL, auth mode and KMS endpoints are measured env, fixed by that Revision. A joiner the appraisal refuses gets no row and no key.
4. The reply carries the volume key as before. The joiner derives the CA, issues itself a leaf, points its pool at it (`finish_join`) and serves.

An older serving node refuses `db_client_cert` as an unknown field, so a client-cert Kata node joins only a serving node from this release on.

## What is not done

- **Migrations.** `alpha-kms migrate` needs a connection before any node holds the volume key; in client-cert mode it refuses (open question Q49).
- **The Postgres pod side.** `alpha-volume open-db` (the init container, separate PRD-05 draft PR) opens the volume; it should also write `root.crt`, `server.crt` and `server.key` with `issue_server`, and `postgresql.conf` should name them. Not wired.
- **Databases from before M2(a)** have no volume key, so client-cert mode cannot reach them; the share files must carry `db_volume_wrapped` (`enter` refuses otherwise).
- **No in-process test of cold start in client-cert mode** (custodian unseal → wait → leaf → serve) against the cert-auth Postgres; join is tested end to end there, and the leaf path by itself.

## Open questions

Numbered program-wide (Q44–Q50); the numbers match `QUESTION(PRD-05 Qn)` in the code and the PR.

- **Q44.** Which CA issues the client certificate? Proposed: the CA derived from the volume key, not the KMS CA, whose key lives in the database it would unlock (M4) and which also signs every tenant leaf.
- **Q45.** Rotation? Proposed: node leaves one hour, renewed on the tick; the server certificate bounded at 30 days, renewed on pod restart; the CA never rotates.
- **Q46.** What replaces `node.join.request` for a client-cert joiner? Implemented as proposed, subject to sign-off: the serving node writes it once it has appraised the joiner as a listed `kata-tdx` build ("Join" above).
- **Q47.** Does Postgres verify the KMS's attestation or trust the CA? Proposed: trust the CA (possession of it is the attestation proxy).
- **Q48.** Should a Kata node refuse `url` mode outright once D10 is decided? Proposed: yes.
- **Q49.** Who runs migrations against the client-cert Postgres? Proposed: a serving node, at `start_serving`, under an advisory lock.
- **Q50.** Restrict `pg_hba.conf` to the verifier pool's CIDR? Proposed: yes once PRD-01 names it.

## Trying it

```sh
D=$(mktemp -d); mkdir $D/init
echo "create role alpha_kms nologin; create role alpha_kms_node login in role alpha_kms;" > $D/init/01-role.sql
ALPHACOMPUTE_DB_AUTH_PG_DIR=$D cargo test -p alpha-kms --test db_auth write_postgres_side
docker run -d --name pg-cert -p 127.0.0.1:55433:5432 -e POSTGRES_USER=alpha -e POSTGRES_PASSWORD=alpha \
  -e POSTGRES_DB=alpha -v $D:/certs-src:ro -v $D/init:/docker-entrypoint-initdb.d:ro --entrypoint bash postgres:18 \
  -c 'mkdir -p /certs && cp /certs-src/*.* /certs/ && chown -R postgres /certs && chmod 600 /certs/server.key &&
      exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/certs/server.crt -c ssl_key_file=/certs/server.key \
      -c ssl_ca_file=/certs/root.crt -c hba_file=/certs/pg_hba.conf -c ident_file=/certs/pg_ident.conf \
      -c ssl_min_protocol_version=TLSv1.3 -c log_connections=authentication'
export ALPHACOMPUTE_DB_AUTH_URL=postgres://alpha_kms_node@localhost:55433/alpha
export ALPHACOMPUTE_DB_AUTH_ADMIN_URL='postgres://alpha:alpha@localhost:55433/alpha?sslmode=require'
cargo test -p alpha-kms --test db_auth
cargo test -p alpha-kms --test kata_node client_cert   # with DATABASE_URL set as for the other db tests
docker logs pg-cert 2>&1 | grep 'method=cert'   # identity="CN=kms-node-…"
```

The `pg_hba.conf` the test writes adds a password login for `alpha` over TLS: the test's migrations, and the serving prototype node in `url` mode, as prototype nodes run during the migration.

# D10 (draft): how a KMS node authenticates to the trust-zone Postgres

**Status: draft for Ryan Tharp's security sign-off. Nothing here has run in a Kata pod.** Code: `services/alpha-kms/src/db_auth.rs`, wired into `main.rs`, `db_volume::enter`, `node::bootstrap`, `node::join_request` / `finish_join` and the platform tick. Tests: the unit tests in `db_auth.rs`, and `services/alpha-kms/tests/db_auth.rs` against a real cert-auth Postgres (below).

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

## What is not done

- **Join.** A joining node writes `node.join.request` before the join reply gives it the volume key, so in client-cert mode it has no credential to write it with. `join_request` refuses with an explicit error (open question 3). Custodian unseal and genesis work.
- **Migrations.** `alpha-kms migrate` needs a connection before any node holds the volume key; in client-cert mode it refuses (open question 6).
- **The Postgres pod side.** `alpha-volume open-db` (the init container, separate PRD-05 draft PR) opens the volume; it should also write `root.crt`, `server.crt` and `server.key` with `issue_server`, and `postgresql.conf` should name them. Not wired.
- **Databases from before M2(a)** have no volume key, so client-cert mode cannot reach them; the share files must carry `db_volume_wrapped` (`enter` refuses otherwise).
- **No in-process node test** of client-cert mode: the shared CI Postgres uses passwords, so only the certificate path is tested against a real server, locally.

## Open questions

The numbers match `QUESTION(PRD-05 Qn)` in the code and the PR.

1. Which CA issues the client certificate? Proposed: the CA derived from the volume key, not the KMS CA, whose key lives in the database it would unlock (M4) and which also signs every tenant leaf.
2. Rotation? Proposed: node leaves one hour, renewed on the tick; the server certificate bounded at 30 days, renewed on pod restart; the CA never rotates.
3. What replaces `node.join.request` for a client-cert joiner? Proposed: the serving node writes it when it appraises the joiner.
4. Does Postgres verify the KMS's attestation or trust the CA? Proposed: trust the CA (possession of it is the attestation proxy).
5. Should a Kata node refuse `url` mode outright once D10 is decided? Proposed: yes.
6. Who runs migrations against the client-cert Postgres? Proposed: a serving node, at `start_serving`, under an advisory lock.
7. Restrict `pg_hba.conf` to the verifier pool's CIDR? Proposed: yes once PRD-01 names it.

## Trying it

```sh
D=$(mktemp -d); mkdir $D/init
echo "create role alpha_kms nologin; create role alpha_kms_node login in role alpha_kms;" > $D/init/01-role.sql
ALPHACOMPUTE_DB_AUTH_PG_DIR=$D cargo test -p alpha-kms --test db_auth write_postgres_side
docker run -d --name pg-cert -p 127.0.0.1:55433:5432 -e POSTGRES_USER=alpha -e POSTGRES_PASSWORD=alpha \
  -e POSTGRES_DB=alpha -v $D:/certs-src:ro -v $D/init:/docker-entrypoint-initdb.d:ro --entrypoint bash postgres:18 \
  -c 'mkdir -p /certs && cp /certs-src/*.* /certs/ && chown -R postgres /certs && chmod 600 /certs/server.key &&
      exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/certs/server.crt -c ssl_key_file=/certs/server.key
      -c ssl_ca_file=/certs/root.crt -c hba_file=/certs/pg_hba.conf -c ident_file=/certs/pg_ident.conf
      -c ssl_min_protocol_version=TLSv1.3 -c log_connections=authentication'
ALPHACOMPUTE_DB_AUTH_URL=postgres://alpha_kms_node@localhost:55433/alpha cargo test -p alpha-kms --test db_auth
docker logs pg-cert 2>&1 | grep 'method=cert'   # identity="CN=kms-node-…"
```

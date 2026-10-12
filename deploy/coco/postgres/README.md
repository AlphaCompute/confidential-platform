# The trust-zone Postgres on Kata (PRD-05 draft)

`alpha-postgres.yaml` is the Postgres pod `docs/db-volume-key.md` describes: a Kata TDX pod on the verifier pool whose data directory is a LUKS2 volume opened by the init container `alpha-volume open-db` (`services/alpha-volume/src/db.rs`) with the KMS's `db-volume` key.

1. Render it: `alpha coco render --for-genpolicy`, genpolicy 4.1.0, review, `alpha coco render --policy`, with `env/alpha-postgres.env`.
2. The release key lists the printed Revision v2 in the platform document's `db_revisions` with `"kind": "kata-tdx"`. A KMS refuses the key to a pod listed anywhere else.
3. Rafay deploys it through the restricted platform project. The pod waits in its init container until custodians unseal a KMS node; then Postgres starts and the KMS serves.

**Not ready to deploy** (TODO(draft)):
- Authentication is D10. The draft answer (#105) needs the init container to write the TLS files and a Postgres image with `pg_hba.conf`/`pg_ident.conf` baked in. Until then the stock entrypoint refuses to initialise a database without `POSTGRES_PASSWORD`, and a password cannot go in the measured env.
- The broker's database lives on the prototype trust-zone Postgres too (`deploy/postgres/docker-compose.yml`). Whether it moves here, and how the broker authenticates, is not drafted.
- Moving the prototype database (PRD-05 migration step 4) is a dump and restore into this pod during the write freeze: an operations step.

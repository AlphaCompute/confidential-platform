# Backing up and restoring the trust-zone Postgres

The trust-db ([`kata/trust-db.yaml`](kata/trust-db.yaml)) is untrusted storage, and so are its
backups: `wal-g` encrypts every object with libsodium before it leaves the pod.

## What is backed up

The whole Postgres cluster, so both databases, `alpha` and `alpha_broker`, and the roles:

- every WAL segment, as soon as it is full and at least once every 60 seconds (`archive_timeout`);
- a base backup every day at 03:00 UTC, by the CronJob `postgres-backup`, streamed over a
  replication connection;
- beside it, `pg_dumpall --globals-only` as `globals/<day of month>.sql.lz4`, encrypted the same
  way, so each day's roles stay for about a month;
- the last 30 base backups and the WAL since the oldest of them; the CronJob deletes the rest.

A restore loses at most the last 60 seconds of commits.

## The backup key

`WALG_LIBSODIUM_KEY` is a deploy secret, not a trust key: what it opens is what the Postgres
operator already holds (ciphertext, metadata, the audit log). Keep it with the owner password,
outside the cluster: a restore after the cluster is lost needs both. A backup together with two
custodians' shares opens the root, so after the custodians' shares are rotated, delete every
backup taken before the rotation:
`kubectl -n alpha-trust-db exec postgres-0 -c postgres -- /wal-g/wal-g delete before FIND_FULL <first backup after the rotation> --confirm`.

## Setup

The bucket and its credentials are the operator's. Before applying `trust-db.yaml`
(Day 0 step 2 in [`kata/README.md`](kata/README.md#day-0)), in the same `umask 077` shell:

```sh
openssl rand -hex 32 | tr -d '\n' > backup-key
kubectl -n alpha-trust-db create secret generic postgres-backup \
  --from-file=WALG_LIBSODIUM_KEY=backup-key \
  --from-literal=WALG_S3_PREFIX=s3://<bucket>/<path> \
  --from-literal=AWS_REGION=<region> \
  --from-literal=AWS_ACCESS_KEY_ID=<access key id> \
  --from-file=AWS_SECRET_ACCESS_KEY=<file with the secret access key>
```

Any S3-compatible store works; add `AWS_ENDPOINT` and `AWS_S3_FORCE_PATH_STYLE=true` for one that
is not AWS. Postgres does not start without this Secret.

## Watch

- `select failed_count, last_failed_wal, last_failed_time from pg_stat_archiver;` as `postgres`.
  While archiving fails, WAL stays on the volume until it fills.
- `kubectl -n alpha-trust-db get jobs`: one `postgres-backup-*` Job completes every day.
- `kubectl -n alpha-trust-db exec postgres-0 -c postgres -- /wal-g/wal-g backup-list` lists the
  base backups.

## Restore

When the trust-db's volume or host is lost. The Secrets `postgres`, `postgres-tls` and
`postgres-backup` must exist (recreate them from the operator's files as in Day 0 step 2 and
Setup); `postgres` holds the owner password the backup was taken with. If the host is lost, label
and taint a new one for the `trust-db` pool (Day 0 step 1).

```sh
kubectl -n alpha-trust-db scale statefulset postgres --replicas=0
kubectl -n alpha-trust-db delete pvc data-postgres-0 --ignore-not-found
: "${TRUST_DB_STORAGE_CLASS:?}" "${TRUST_DB_STORAGE_SIZE:?}" &&
  export TRUST_DB_STORAGE_CLASS TRUST_DB_STORAGE_SIZE TRUST_DB_BACKUP=LATEST &&
  envsubst '$TRUST_DB_STORAGE_CLASS $TRUST_DB_STORAGE_SIZE $TRUST_DB_BACKUP' < kata/trust-db-restore.yaml | kubectl create -f -
kubectl -n alpha-trust-db wait --for=condition=complete job/postgres-restore --timeout=2h
kubectl -n alpha-trust-db delete job postgres-restore
kubectl -n alpha-trust-db scale statefulset postgres --replicas=1
kubectl -n alpha-trust-db rollout status statefulset/postgres --timeout=2h
```

`TRUST_DB_BACKUP` is `LATEST` or a name from `backup-list`. The Job refuses a volume that already
holds a database. Postgres replays the archived WAL to its end, then serves at the same Service
name, `postgres.alpha-trust-db.svc`, on a new timeline that is archived as before.

Then the KMS:

1. A node that kept serving reconnects by itself. If both nodes were lost, unseal as in
   [All nodes lost](kata/README.md#restart-upgrade-loss).
2. `curl -sk https://localhost:8443/ready` through a port-forward to `pod/kms-0` answers 200.
3. An Instance gets its Secrets: `kubectl -n alpha-broker delete pod <a broker pod>`; the new pod
   turns ready only after its runtime fetched them from the KMS.
4. `join` works: `kubectl -n alpha-kms delete pod kms-1`; it comes back ready, and the audit log
   shows a new `node.join ok`.

## A restore is a security event

Everything committed after the restore point is gone, revocations included: a revoked Revision
(`/v1/revisions/{compose_hash}/revoke`) or principal key (`/v1/keys/{id}/revoke`) is valid again.
`select max(ts) from audit_log;` on the restored `alpha` is the restore point. Every revocation
after it is applied again before tenants use the KMS, from the external log sink that keeps the
KMS's audit events outside this database. That sink is not chosen yet, which is why it has to
exist before the first tenant.

## Drills

- **Locally**, `deploy/postgres/backup-drill.sh` runs the same commands against a local S3: a base
  backup, rows that reach the restore only through archived WAL, a wipe and a restore, then the
  same `pg_dumpall` as before the wipe, a passing `alpha-kms migrate`, and a roles object that
  opens under the backup key and not under another. It needs docker and cargo, and CI runs it.
- **On staging, before the first production tenant**: Restore above, end to end, with both KMS
  nodes deleted, so the unseal runs too. Record the times and every step that needed a change.

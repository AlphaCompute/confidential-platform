#!/usr/bin/env bash
# Backs the trust-db up to a local S3, wipes it, restores it and checks that every row and role
# came back and the KMS migration still passes. Needs docker and cargo, no cloud.
set -euo pipefail
cd "$(dirname "$0")"

WALG_LIBSODIUM_KEY=$(openssl rand -hex 32)
export WALG_LIBSODIUM_KEY
dc() { docker compose -p trust-db-drill -f backup-drill.yml "$@"; }
sql() { dc exec -T postgres psql -X -v ON_ERROR_STOP=1 -U postgres -At "$@"; }
dump() { dc exec -T postgres pg_dumpall -U postgres --restrict-key=drill; }
# `dev-root`: the production build refuses the placeholder release key set, which migrate never reads.
migrate() {
  ALPHACOMPUTE_DATABASE_URL="postgres://postgres:drill@$(dc port postgres 5432)/alpha?sslmode=require" \
    cargo run -q -p alpha-kms --features dev-root -- migrate
}
globals() { dc run --rm -T "$@" --entrypoint /wal-g/wal-g backup st cat "globals/$(date -u +%d).sql.lz4" --decrypt --decompress; }
trap 'dc --profile run down -v' EXIT

dc up -d --wait --wait-timeout 300 postgres
sql -c 'create database alpha_broker'
migrate
dc run --rm backup

# Rows written after the base backup come back only through the archived WAL.
for db in alpha alpha_broker; do
  sql -d "$db" -c 'create table drill as select generate_series(1, 1000) as n'
done
segment=$(sql -c 'select pg_walfile_name(pg_switch_wal())')
for i in $(seq 120); do
  [ "$(sql -c 'select last_archived_wal from pg_stat_archiver')" = "$segment" ] && break
  [ "$i" -lt 120 ] || { echo "WAL segment $segment was not archived" >&2; exit 1; }
  sleep 1
done
before=$(dump)

dc rm -sf postgres
docker volume rm trust-db-drill_pgdata
dc run --rm restore
dc up -d --wait --wait-timeout 300 --no-deps postgres

[ "$before" = "$(dump)" ] || { echo "the restored database differs" >&2; exit 1; }
migrate
# No `grep -q`: it exits at the first match and pipefail fails on the broken pipe.
globals | grep '^CREATE ROLE postgres;' >/dev/null
if globals -e WALG_LIBSODIUM_KEY="$(openssl rand -hex 32)" >/dev/null; then
  echo 'the roles object opened under another key' >&2
  exit 1
fi
echo 'restore drill passed'

create type principal_key_revocation as enum ('retired', 'compromised');
create table principal_keys (
  id                uuid primary key,
  org_id            uuid not null,
  principal_id      uuid not null,
  public_key        bytea not null unique,
  document          jsonb not null,
  registered_by_key uuid references principal_keys(id),
  signature         jsonb,
  anchor_check      bytea,
  created_at        timestamptz not null default now(),
  revoked_at        timestamptz,
  revocation_reason principal_key_revocation,
  check (revoked_at is null or revocation_reason is not null),
  check ((registered_by_key is null) = (signature is null)),
  check ((registered_by_key is null) = (anchor_check is not null))
);
create unique index on principal_keys (org_id) where registered_by_key is null;

create table revisions (
  compose_hash    bytea primary key,
  app_id          uuid not null,
  org_id          uuid not null,
  compose         text not null,
  created_by_key  uuid not null references principal_keys(id),
  signature       jsonb not null,
  created_at      timestamptz not null default now(),
  revoked_at      timestamptz
);
create index on revisions (app_id) where revoked_at is null;

create table secrets (
  id              uuid primary key,
  org_id          uuid not null,
  name            text not null,
  app_ids         uuid[] not null,
  ciphertext      bytea not null,
  content_sha256  bytea not null,
  document        jsonb not null,
  signed_by_key   uuid not null references principal_keys(id),
  signature       jsonb not null,
  issued_at       timestamptz not null,
  unique (org_id, name)
);

create table platform_document (
  one           smallint primary key default 1 check (one = 1),
  version       integer not null,
  document      jsonb not null,
  signature     bytea not null,
  verified_at   timestamptz not null default now()
);

create type intermediate_purpose as enum ('tenant-kek-root', 'ca');
create table intermediate_keys (
  purpose       intermediate_purpose primary key,
  wrapped       bytea not null,
  public_part   bytea,
  created_at    timestamptz not null default now()
);

create table audit_log (
  seq             bigint generated always as identity primary key,
  ts              timestamptz not null default now(),
  actor_kind      text not null check (actor_kind in ('instance', 'principal', 'node')),
  actor           text not null,
  action          text not null,
  org_id          uuid,
  object          text,
  outcome         text not null check (outcome in ('ok', 'denied', 'error')),
  details         jsonb not null default '{}',
  evidence_sha256 bytea
);
create index on audit_log (org_id, ts);

-- The service role: insert and select on the audit log, never update or delete.
do $$ begin
  if not exists (select from pg_roles where rolname = 'alpha_kms') then
    create role alpha_kms nologin;
  end if;
end $$;
grant select, insert, update on principal_keys, revisions, secrets, platform_document, intermediate_keys to alpha_kms;
grant select, insert on audit_log to alpha_kms;
grant usage on sequence audit_log_seq_seq to alpha_kms;
revoke update, delete on audit_log from alpha_kms;

create table pending_connects (
  state             text primary key,
  member_key_sha256 bytea not null check (length(member_key_sha256) = 32),
  provider          text not null,
  enc_pkce_verifier bytea not null,
  exp               timestamptz not null
);

create table connections (
  id                uuid primary key,
  member_key_sha256 bytea not null check (length(member_key_sha256) = 32),
  provider          text not null,
  account           text not null,
  enc_refresh_token bytea,
  scopes            text not null,
  created_at        timestamptz not null default now(),
  dead_at           timestamptz,
  revoked_at        timestamptz,
  check ((enc_refresh_token is null) = (revoked_at is not null))
);
create unique index on connections (member_key_sha256, provider, account) where revoked_at is null;

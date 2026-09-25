-- Earlier rows name a member by the tenant's own reference, which no member key can be shown to
-- own, so they go with their tokens and members link again.
delete from pending_connects;
delete from connections;

alter table pending_connects
  drop column member_key_sha256,
  add column member_key bytea not null,
  add column member_key_sha256 bytea not null generated always as (sha256(member_key)) stored;
alter table connections
  drop column member_key_sha256,
  add column member_key bytea not null,
  add column member_key_sha256 bytea not null generated always as (sha256(member_key)) stored;
create unique index on connections (member_key_sha256, provider, subject) where revoked_at is null;

create table member_nonces (
  nonce bytea primary key check (length(nonce) = 32),
  exp   timestamptz not null
);

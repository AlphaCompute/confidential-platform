-- Earlier rows name a member by the tenant's own reference, which no member key can be shown to
-- own, so they go with their tokens and members link again.
delete from pending_connects;
delete from connections;

alter table pending_connects
  add column member_key bytea not null check (member_key_sha256 = sha256(member_key));
alter table connections
  add column member_key bytea not null check (member_key_sha256 = sha256(member_key));

create table member_nonces (
  nonce bytea primary key check (length(nonce) = 32),
  exp   timestamptz not null
);

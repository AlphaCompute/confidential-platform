alter table revisions
  add column registered_at timestamptz,
  add column revoked_at    timestamptz;

-- predecessor: the Revision an approval also revokes, unless its signer keeps it.
alter table tickets
  add column predecessor bytea references revisions(compose_hash),
  drop constraint tickets_kind_check,
  add constraint tickets_kind_check check (kind in ('approve', 'claim', 'revoke'));

-- The Secret names the relay put for each App, so an approval can say which are already held.
create table app_secrets (
  app_id uuid not null references apps(id),
  name   text not null,
  primary key (app_id, name)
);

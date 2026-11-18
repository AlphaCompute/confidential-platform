alter table organizations add column rooted_at timestamptz;

-- principal_id: the holder a claim ticket of a rooted Organization adds a key for.
-- used: the state-changing relay ops the ticket already drove, each at most once.
alter table tickets
  add column principal_id uuid,
  add column used         text[] not null default '{}';

-- The KMS keeps no passkey credential ids, so the relay records each key it carried.
create table credentials (
  key_id        uuid primary key,
  org_id        uuid not null references organizations(id),
  credential_id text not null,
  created_at    timestamptz not null default now()
);
create index on credentials (org_id);

create table api_keys (
  id         uuid primary key,
  org_id     uuid not null,
  name       text not null,
  mac        bytea not null check (length(mac) = 32),
  created_at timestamptz not null default now(),
  revoked_at timestamptz
);
create index on api_keys (org_id);

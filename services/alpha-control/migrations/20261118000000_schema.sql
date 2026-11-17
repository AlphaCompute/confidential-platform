create table principals (
  id         uuid primary key,
  issuer     text not null,
  subject    text not null,
  email      text,
  created_at timestamptz not null default now(),
  unique (issuer, subject)
);

create table organizations (
  id                 uuid primary key,
  name               text not null,
  owner_principal_id uuid references principals(id),
  owner_email        text not null,
  rooted_at          timestamptz,
  root_fingerprint   text,
  created_by         text not null,
  created_at         timestamptz not null default now(),
  disabled_at        timestamptz
);

create table org_links (
  issuer      text not null,
  external_id text not null,
  org_id      uuid not null references organizations(id),
  primary key (issuer, external_id)
);

-- org_id is null for an onboarding key.
create table api_keys (
  id           uuid primary key,
  org_id       uuid references organizations(id),
  token_sha256 bytea not null unique check (length(token_sha256) = 32),
  scopes       text[] not null,
  app_id       uuid,
  label        text not null,
  created_by   text not null,
  created_at   timestamptz not null default now(),
  revoked_at   timestamptz
);

-- A slug is never reused: a deleted App keeps its row.
create table apps (
  id         uuid primary key,
  org_id     uuid not null references organizations(id),
  slug       text not null unique,
  created_at timestamptz not null default now(),
  deleted_at timestamptz
);

create table audit_log (
  seq     bigint generated always as identity primary key,
  ts      timestamptz not null default now(),
  actor   text not null,
  org_id  uuid,
  action  text not null,
  object  text,
  outcome text not null check (outcome in ('ok', 'denied', 'error')),
  details jsonb not null default '{}'
);

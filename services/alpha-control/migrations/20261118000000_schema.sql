create table organizations (
  id                 uuid primary key,
  name               text not null,
  owner_email        text not null,
  created_at         timestamptz not null default now()
);

create table org_links (
  issuer      text not null,
  external_id text not null,
  org_id      uuid not null references organizations(id),
  primary key (issuer, external_id)
);

-- org_id is null for an onboarding key; issuer is the only link issuer it may claim.
create table api_keys (
  id           uuid primary key,
  org_id       uuid references organizations(id),
  token_sha256 bytea not null unique check (length(token_sha256) = 32),
  scopes       text[] not null,
  issuer       text,
  created_at   timestamptz not null default now()
);

create table apps (
  id         uuid primary key,
  org_id     uuid not null references organizations(id),
  slug       text not null unique,
  created_at timestamptz not null default now()
);

create table audit_log (
  seq     bigint generated always as identity primary key,
  ts      timestamptz not null default now(),
  actor   text not null,
  org_id  uuid not null,
  action  text not null,
  object  text,
  details jsonb not null default '{}'
);

create table principals (
  id         uuid primary key,
  issuer     text not null,
  subject    text not null,
  created_at timestamptz not null default now(),
  unique (issuer, subject)
);

alter table organizations add column owner_principal_id uuid references principals(id);

-- The ticket itself is stored, not its digest, because a typed code must lead back to it.
create table tickets (
  ticket         text primary key,
  code           text not null unique,
  kind           text not null check (kind in ('approve', 'claim')),
  org_id         uuid not null references organizations(id),
  compose_hash   bytea references revisions(compose_hash),
  principal_id   uuid,
  session_sha256 bytea check (length(session_sha256) = 32),
  state          text not null default 'open' check (state in ('open', 'done', 'declined')),
  expires_at     timestamptz not null,
  created_at     timestamptz not null default now()
);

alter table organizations
  add column created_by  text,
  add column disabled_at timestamptz;

-- label 'deploy' marks the key an Organization's create minted, which a retry of that create
-- replaces.
alter table api_keys
  add column label      text,
  add column revoked_at timestamptz;

-- The highest platform document version accepted, so neither a restart nor another replica takes
-- an older one again.
create table platform_version (
  one     int primary key check (one = 1),
  version bigint not null
);

create table revisions (
  compose_hash bytea primary key check (length(compose_hash) = 32),
  app_id       uuid not null references apps(id),
  init_data    text not null,
  pod          text not null,
  shape        jsonb not null,
  catalog      jsonb not null
);

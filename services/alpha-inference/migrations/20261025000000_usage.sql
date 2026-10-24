create table usage (
  id                uuid primary key,
  key_id            uuid not null,
  org_id            uuid not null,
  model             text not null,
  status            smallint not null,
  prompt_tokens     bigint,
  completion_tokens bigint,
  started_at        timestamptz not null,
  ended_at          timestamptz not null
);
create index on usage (key_id);
create index on usage (started_at);

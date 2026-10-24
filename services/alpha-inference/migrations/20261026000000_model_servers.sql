create table model_servers (
  org_id    uuid not null,
  model     text not null,
  url       text not null,
  revisions text[] not null,
  mac       bytea not null check (length(mac) = 32),
  primary key (org_id, model)
);

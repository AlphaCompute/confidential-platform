-- A Revision is either a dstack compose or a Kata init-data TOML; compose_hash is the SHA-256 of
-- whichever bytes are present.
alter table revisions alter column compose drop not null;
alter table revisions add column init_data text;
alter table revisions add constraint revisions_one_content
  check ((compose is null) <> (init_data is null));

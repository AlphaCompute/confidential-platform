-- A Revision is either a dstack compose or a Kata init-data TOML; compose_hash is the SHA-256 of
-- whichever bytes are present.
alter table revisions alter column compose drop not null;
alter table revisions add column init_data text;
-- revisions_one_form (added by 20261012000000_sealed_metadata) checked (sealed is null) =
-- (compose is not null); now that init_data is another plaintext form, replace it.
alter table revisions drop constraint if exists revisions_one_form;
alter table revisions add constraint revisions_one_form
  check ((sealed is null) = (compose is not null or init_data is not null));
alter table revisions add constraint revisions_one_content
  check ((compose is null) <> (init_data is null));

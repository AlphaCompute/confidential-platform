-- D4 / M2(b): the trust-zone Postgres is an untrusted store. Each row keeps only what a query
-- needs (random ids, keyed HMAC blind indexes, the compose hash, timestamps) beside `sealed`, an
-- AES-256-GCM blob under a key derived from tenant-kek-root, which exists only after custodian
-- unseal. The plaintext columns stay, nullable, for rows an earlier release wrote: a serving node
-- seals and clears them (`alpha_kms::store::seal_plaintext`). docs/metadata-encryption.md has the
-- column classification.

alter table principal_keys
  add column org_index        bytea,
  add column public_key_index bytea,
  add column sealed           bytea,
  alter column org_id drop not null,
  alter column principal_id drop not null,
  alter column public_key drop not null,
  alter column document drop not null,
  alter column signature drop not null,
  -- A sealed row keeps `registered_by_key` inside `sealed`; `anchor_check` alone marks the root.
  drop constraint principal_keys_check1,
  add constraint principal_keys_one_form check ((sealed is null) = (org_id is not null)),
  add constraint principal_keys_sealed_indexed check (
    sealed is null or (org_index is not null and public_key_index is not null));
create unique index principal_keys_public_key_index on principal_keys (public_key_index);
create unique index principal_keys_root_org_index on principal_keys (org_index)
  where anchor_check is not null;

alter table revisions
  add column app_index bytea,
  add column org_index bytea,
  add column sealed    bytea,
  alter column app_id drop not null,
  alter column org_id drop not null,
  alter column compose drop not null,
  alter column created_by_key drop not null,
  alter column signature drop not null,
  add constraint revisions_one_form check ((sealed is null) = (compose is not null)),
  add constraint revisions_sealed_indexed check (
    sealed is null or (app_index is not null and org_index is not null));
create index revisions_app_index on revisions (app_index);

alter table secrets
  add column name_index bytea,
  add column sealed     bytea,
  alter column org_id drop not null,
  alter column name drop not null,
  alter column app_ids drop not null,
  alter column content_sha256 drop not null,
  alter column document drop not null,
  alter column signed_by_key drop not null,
  alter column signature drop not null,
  alter column issued_at drop not null,
  add constraint secrets_one_form check ((sealed is null) = (document is not null)),
  add constraint secrets_sealed_indexed check (sealed is null or name_index is not null);
create unique index secrets_name_index on secrets (name_index);

-- The audit log: a row is either sealed (written by a serving node) or plaintext in the original
-- columns (a node fact written before unseal, or a row of an earlier release). `link` chains every
-- row a node of this release wrote; a sealed row's AEAD covers the link before it.
alter table audit_log
  add column sealed bytea,
  add column link   bytea,
  alter column actor_kind drop not null,
  alter column actor drop not null,
  alter column action drop not null,
  alter column outcome drop not null,
  alter column details drop not null,
  add constraint audit_log_one_form check ((sealed is null) = (action is not null)),
  add constraint audit_log_sealed_linked check (sealed is null or link is not null);
create index audit_log_link_head on audit_log (seq) where link is not null;

-- A row an earlier release wrote has no link and nothing authenticates it. Once a serving node
-- has appended its sealed copy (`audit.import`), the service role may replace its content with a
-- pointer to that copy. Rows with a link stay out of reach: the role still cannot update them.
create function audit_log_scrub(legacy bigint, imported bigint) returns boolean
language sql security definer set search_path = pg_catalog, public as $$
  update public.audit_log
     set actor_kind = 'node', actor = 'node', action = 'audit.imported', org_id = null,
         object = null, outcome = 'ok', details = jsonb_build_object('imported_as', imported),
         evidence_sha256 = null
   where seq = legacy and link is null and sealed is null and action <> 'audit.imported'
     and imported > legacy
     and exists (select 1 from public.audit_log where seq = imported and sealed is not null)
  returning true
$$;
revoke all on function audit_log_scrub(bigint, bigint) from public;
grant execute on function audit_log_scrub(bigint, bigint) to alpha_kms;

-- Option B (PRD-02 deliverable 26): the Trustee pods the KMS feeds (docs/trustee.md).

-- A tenant's opt-in, one per App: the App's resources a Trustee pod may release to the App's own
-- attested pods. Signed under alphacompute/trustee-grant/v1; an empty list opts the App out.
create table trustee_grants (
  app_id          uuid primary key,
  org_id          uuid not null,
  resources       jsonb not null,
  document        jsonb not null,
  signed_by_key   uuid not null references principal_keys(id),
  signature       jsonb not null,
  issued_at       timestamptz not null
);

-- Every KBS attestation a Trustee pod reported and the KMS admitted: the attested pod's Revision
-- and MRCONFIGID, by the digest of the token the pod's KBS issued. A release names the token.
create table trustee_attestations (
  token_sha256      bytea primary key,
  trustee_revision  bytea not null,
  revision          bytea not null references revisions(compose_hash),
  app_id            uuid not null,
  org_id            uuid not null,
  mrconfigid        bytea not null,
  expires_at        timestamptz not null,
  created_at        timestamptz not null default now()
);
create index on trustee_attestations (revision);

grant select, insert, update on trustee_grants to alpha_kms;
grant select, insert, delete on trustee_attestations to alpha_kms;

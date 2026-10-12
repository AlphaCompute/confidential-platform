-- PRD-06 I5: the Fortanix CCM identities an organization allow-lists. A CCM-attested workload
-- gets a leaf only for an identity its organization registered here, inside a CCM zone the
-- release-signed platform document pins; the leaf names the row, never a Revision.
create table ccm_identities (
  id                    uuid primary key,
  org_id                uuid not null,
  name                  text not null,
  zone_ca_spki_sha256   bytea not null check (length(zone_ca_spki_sha256) = 32),
  identity              text not null,
  document              jsonb not null,
  created_by_key        uuid not null references principal_keys(id),
  signature             jsonb not null,
  created_at            timestamptz not null default now(),
  revoked_at            timestamptz,
  unique (org_id, zone_ca_spki_sha256, identity)
);

grant select, insert, update on ccm_identities to alpha_kms;

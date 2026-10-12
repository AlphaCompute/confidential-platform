-- PRD-06 I3: the KMS root KEK's DSM co-factor, held beside the custodians' shares. With a row
-- here the intermediates are wrapped under HKDF(root ‖ co-factor): unsealing needs two
-- custodian shares and our DSM's decryption, never one without the other.
create table root_cofactor (
  one               smallint primary key default 1 check (one = 1),
  dsm_endpoint      text not null,
  dsm_key           jsonb not null,
  -- The DSM App's API key, AES-GCM under the custodians' root (not the co-factor KEK), so it is
  -- reachable only once two shares have combined.
  api_key_wrapped   bytea not null,
  -- DSM's AES-GCM ciphertext of the co-factor, as DSM returned it.
  cofactor          jsonb not null,
  created_at        timestamptz not null default now()
);

grant select, insert on root_cofactor to alpha_kms;

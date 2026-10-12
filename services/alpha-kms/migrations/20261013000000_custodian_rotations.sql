-- Custodian re-share with root rotation (`alpha custodians rotate`). Two current custodians
-- approve a proposal naming three new X-Wing keys over a KMS nonce; the node generates a new root
-- KEK, re-wraps every `intermediate_keys` row under it and records the rotation here, in one
-- transaction. The row keeps what the new custodians need if the reply is lost: the proposal, the
-- new shares sealed to their keys, and the node's signed receipt over both. Nothing here opens
-- without a custodian's private key; `nonce` is unique, so one nonce rotates once.
create table custodian_rotations (
  id         uuid primary key,
  nonce      bytea not null unique,
  rotation   jsonb not null,
  created_at timestamptz not null default now()
);

grant select, insert on custodian_rotations to alpha_kms;

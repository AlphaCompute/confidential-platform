-- A deleted secret stays as a tombstone, so a put replayed inside the issued_at window cannot
-- bring back what the delete erased.
alter table secrets add column deleted_at timestamptz;

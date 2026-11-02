alter table usage alter column key_id drop not null;
alter table usage add column app_id uuid;
alter table usage add check (num_nonnulls(key_id, app_id) = 1);

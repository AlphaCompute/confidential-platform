-- The platform document carries a list of release signatures, each naming its key. A row from
-- before keeps its single signature until the next reload replaces it.
alter table platform_document add column signatures jsonb;
alter table platform_document alter column signature drop not null;

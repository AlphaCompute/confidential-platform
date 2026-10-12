-- M2(a): the trust-zone Postgres's data volume key, a third intermediate wrapped under the root
-- KEK beside tenant-kek-root and the CA key. Its wrapped form is also in every custodian's share
-- file, so a node can open it while this database is still closed (docs/db-volume-key.md).
alter type intermediate_purpose add value if not exists 'db-volume';

-- D12 item 2: a custodian rotation also replaces the data key. The new key is random, wrapped
-- under the new root KEK beside tenant-kek-root and the CA key, and in the same transaction every
-- sealed row, blind index and Secret value is re-encrypted under it, so two old shares and a copy
-- taken before the rotation open nothing written after it. `epoch` counts the rotations, in the
-- clear: under the chain lock every node checks that its keys are the database's (a node whose
-- keys a rotation replaced joins again). The wrapped key carries the epoch it trusts. No row means
-- epoch 0: a database no rotation has re-keyed, its keys derived from tenant-kek-root.
alter type intermediate_purpose add value if not exists 'data-key';
alter table intermediate_keys add column epoch integer;

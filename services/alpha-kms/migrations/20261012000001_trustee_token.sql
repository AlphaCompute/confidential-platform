-- The token each Trustee attestation was admitted on, kept so that a release verifies it again
-- under the reporting Trustee App's key and holds its claims to the platform document as it is
-- then, rather than trusting the admitted row alone. Rows admitted before this have no token to
-- check and are dropped; their pods attest again (an admission lives at most an hour).
delete from trustee_attestations;
alter table trustee_attestations add column token text not null;

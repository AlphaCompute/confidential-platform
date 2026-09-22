# Database integrity and rollback decision

Decision: `trusted-operators-v1`. Database administrators, schema owners, storage administrators and backup/restore operators are part of the trusted computing base. KMS startup requires `ALPHACOMPUTE_DATABASE_INTEGRITY=trusted-operators-v1`; absence or another value fails closed. This is a scope restriction, not cryptographic rollback protection.

The KMS authenticates customer documents, binds ciphertext to organization, secret UUID and full signed document, and checks the plaintext digest before release. These controls reject ciphertext substitution, policy/ciphertext mixing and unauthorized API requests. They do **not** stop a database superuser restoring a complete old valid database, clearing a revocation, or removing a newer record. TLS, TDX, AEAD and an audit table in that database do not provide an independent monotonic witness.

`tests/security.rs::trusted_database_model_does_not_claim_superuser_rollback_resistance` revokes a revision, observes denial, clears its database revocation as an administrator, and demonstrates that access returns. Customers requiring protection against these administrators cannot use this profile. They require an independently administered append-only witness/checkpoint with freshness enforced on every KMS release and join; that system is not implemented here.

## Operation and restore

Use a dedicated service principal belonging to `alpha_kms`, separate from the migration/schema owner. Restrict privileged access, protect backups and audit privileged changes outside the database. Local disposable test credentials are not a production configuration.

Before a restore, fence **all** KMS instances and block peer join. Keep restored nodes sealed and unavailable. Trusted operators must reconcile the backup against externally retained customer approvals, key/revision revocations and secret versions through the incident cutoff. If authoritative history is unavailable, do not unseal: recover customer approvals and rotate affected secrets/identities through a new authorized deployment. A healthy peer must not silently rejoin or unseal stale state. Verify release denial for each restored revocation before restoring service. This is an operator procedure, not an automated witness or a completed restore drill.

Rafay stores neither customer signing keys nor unseal shares. Independent custodians perform bootstrap/unseal from their own systems after checking the current release document, attestation and node keys. Catalogue actions cannot authorize recovery, reset freshness state or substitute trust anchors.

## Ciphertext migration

New ciphertext is `AKS2 || AEAD(...)`. Associated data is `alphacompute-kms/secret/v2\0 || org_uuid || secret_uuid || signing_digest(SECRET, full_document)`. Legacy ciphertext has no permissive read fallback. Customers must upload each secret again under a fresh customer-signed document after upgrading. Export/re-encrypt through Rafay is prohibited. Back up, inventory legacy records, rehearse customer re-upload in staging, and confirm revocations remain denied. Do not downgrade after migration.

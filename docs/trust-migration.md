# Customer approval, freshness and identity migration

Customer root/signing keys and custodian unseal shares stay on customer-controlled systems. Rafay receives already approved compose bytes, hashes and public pins. It may request deployment and inspect readiness; it cannot create customer signatures, reset the platform journal, replace a CA or unseal KMS. Provider credentials, independent KMS signer pins and worker/payment/meter keys belong to Alpha's operational boundary, outside customer-editable catalogue variables.

## Provisioning encryption

Shroud and the Python helper require an independently installed compressed secp256k1 KMS signer pin. A v1 signed environment key must bind the expected 20-byte provider app ID, match the offered 32-byte key and be at most five minutes old or one minute in the future. Unsigned/legacy-only responses fail before credential encryption/commit. Install the Alpha-owned adapter from `integrations/dstack-tee` before running `deploy/phala.py`. Its SDK is pinned to `c12e96adaeea51d1c79608123d41a6f521db46cd`; transitive Python packages still need a fully hashed release lock before production qualification.

# CPU HMAC application

This Rust service uses runtime secrets without disclosing them. It listens on TLS port 8443; an approved compose maps external port 443 to 8443 and mounts `alpha-run:/run/alpha`. Register the customer-signed secret `cpu-app-key` with at least 32 random bytes, authorized only for this application and approved revision.

`GET /healthz?challenge=<fresh value>` confirms org/app/revision and a successful KMS-authorized runtime secret read. `POST /v1/hmac` returns HMAC-SHA256 for at most 64 KiB of input. Certificates/keys come from `/run/alpha/runtime.sock`. Every new connection and request rechecks runtime identity and secret authorization. No secret cache is persisted. Runtime failure/revocation denies access; connections have a 60-second deadline and runtime requests have five-second deadlines.

`alpha-kms/tests/runtime.rs::cpu_application_uses_real_kms_secret_over_runtime_socket_and_pinned_tls` uses real PostgreSQL, KMS HTTPS, runtime Unix socket and application TLS. It tests HMAC, health, wrong revision, application restart and policy revocation. Attestation uses the checked-in DCAP capture and test clock, not live hardware.

Build with `cargo build --locked --release -p alpha-cpu-app` or `images/cpu-app/Dockerfile`. Image approval requires its OCI digest, reviewed dependencies and release provenance. Durable provider create/delete/reconcile, real crash recovery, live gateway deployment and invoice qualification remain separate gates. This application alone does not complete them.

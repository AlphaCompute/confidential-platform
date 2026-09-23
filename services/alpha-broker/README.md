# alpha-broker

The platform's connector broker: an App of its own that connects a member's provider account and then reads from it for the member's chats. It exchanges the provider's authorization code with a PKCE verifier only it holds, keeps each refresh token sealed (AES-256-GCM, the connection id as associated data) under the `connectors` key that only Instances of this App derive from the KMS, and proxies reads inside a fixed allowlist with the member's access token attached. No token leaves the broker: the tenant's backend relays an opaque code, and the caller of `/proxy` gets the provider's answer only. Google is the one provider today.

A member is named by a member reference, the lowercase hex SHA-256 of the tenant's user id (64 characters). A connection is keyed by the provider account's stable subject; the email is only what the member sees.

## Configuration (environment only)

| Variable | Meaning |
|---|---|
| `GOOGLE_CLIENT_ID` | the tenant's OAuth client id at Google |
| `GOOGLE_REDIRECT_URI` | the tenant's OAuth callback, `https://` only; the tenant's page relays the code from there |

Secrets, read from the runtime socket at start and every five minutes (`database-url` only at start): `google-client-secret` (the tenant's OAuth client secret), `connect-bearer` (the tenant backend's bearer for the connect routes), `proxy-bearer` (the bearer of the App that calls `/proxy`, the Corpus worker's supervisor), `database-url`. The key purpose is `connectors`. A renewal that fails, as it does once the runtime removes its socket after the Revision is revoked, drains the listener and exits non-zero.

## Database

The broker has its own database and login role, `alpha_broker`, on the trust-zone Postgres, with no grant on the KMS's tables; `deploy/README.md` "The broker's database" says how they are created. It applies its migrations every time it starts (`alpha-broker migrate` applies them and stops). Two tables: `pending_connects` (a connect's state, the member, the sealed PKCE verifier, ten minutes of life, consumed once) and `connections` (member, provider, subject, email, sealed refresh token, scopes, `dead_at`, `revoked_at`). Access tokens are never written: each process caches them per connection until a minute before they expire.

## Listener

One port, 8443, TLS 1.3 with `X25519MLKEM768` and this Instance's KMS-issued leaf. A client certificate is requested and not required: when one is presented it must chain to the KMS CA (the last certificate of the broker's own chain from the runtime) or the handshake fails.

## Routes

Every error is `{"error": {"code", "message"}}`.

With `Authorization: Bearer <connect-bearer>` (else 401 `unauthorized`), called by the tenant's backend:

- `POST /connect/{provider}` `{"member"}` → `{"url"}`: the provider's authorization URL with PKCE S256, offline access and consent. An unknown provider answers 404 `not_found`.
- `POST /connect/finish` `{"member", "code", "state"}` → `{"id", "provider", "account"}`. A state that is unknown, expired, used or another member's answers 400 `state_invalid`; a refused exchange or account lookup answers 502 `exchange_failed`. Connecting the same account again keeps its id and clears its dead mark.
- `GET /connections?member=<ref>` → `{"connections": [{"id", "provider", "account", "dead"}]}`, live connections only. `dead: true` means the provider refused the refresh token and the member must reconnect.
- `DELETE /connections/{id}?member=<ref>` → 204; revoked locally, then at the provider best effort. An unknown, revoked or foreign id answers 404 `not_found`.

With a client certificate carrying an Instance's two URI SANs (else 401 `cert_invalid`; a KMS node's leaf is refused the same way) and `Authorization: Bearer <proxy-bearer>` (else 401 `unauthorized`):

- `POST /proxy` `{"member", "connection_id", "method", "url", "body"?}`. The checks run in this order, and each refuses before anything later happens: the connection is live and the member's (else 404 `not_found`); the method, host and path are in the allowlist (else 403 `not_allowed`); the connection is not dead (else 409 `reconnect_required`); an access token is cached or obtained by refreshing (the provider's `invalid_grant` marks the connection dead and answers 409 `reconnect_required`; any other failure answers 502 `upstream`). The request sent is the parsed URL with its query, the method, the access token and the JSON body when one was given; a 401 from the provider drops the token, refreshes once and retries once. The reply is the provider's status, `content-type` and body; a body over 16 MiB answers 502 `too_large`, an unreachable provider 502 `upstream`. A refresh token the provider rotates is sealed and stored.

Malformed input anywhere, unknown fields included, answers 400 `malformed`. `GET /healthz` (the process) and `GET /ready` (200 once the database answers) need nothing.

## The read allowlist

All `GET` on `https://www.googleapis.com`, default port, no userinfo or fragment, matched segment by segment on the parsed URL (so `..` and its encoded forms are resolved before the check, and the checked path is the path sent); `{id}` is one segment of 1 to 256 characters of `[A-Za-z0-9_-]`:

- `/drive/v3/drives`, `/drive/v3/files`, `/drive/v3/files/{id}` (metadata, or the content with `alt=media`), `/drive/v3/files/{id}/export` (Docs, Sheets and Slides as text)
- `/gmail/v1/users/me/messages`, `/gmail/v1/users/me/messages/{id}`
- `/calendar/v3/calendars/primary/events`

Nothing writes or uploads, and the Docs, Sheets and Slides APIs are not reachable. The list and the 16 MiB cap are constants in `src/proxy.rs`, not configuration. The connect asks Google for `drive.readonly`, `gmail.readonly`, `calendar.readonly`, `drive.file`, `openid` and `email`; the last two only name the account.

## What it does not promise yet

The broker trusts two bearers. Whoever holds the connect bearer can start and finish a connect for any member reference, and whoever holds the proxy bearer and any attested Instance leaf from the KMS can read any connected account inside the allowlist: the broker pins no caller Revision. Both bearers are released to Apps the Corpus operator runs, so the Corpus operator can use members' connected Google accounts until a key the member holds signs each request. What the broker does keep: tokens stay inside this App's CVMs and its sealed rows, and nothing outside the allowlist reaches Google.

## Tests

`DATABASE_URL=postgres://… cargo test -p alpha-broker` creates a fresh database per test and runs the routes against a TLS stand-in for Google reached through Google's real host names; the `/proxy` tests go through the real mTLS listener with a stand-in KMS CA. Every reply is checked for any token, code, verifier or the client secret. They cover the connect flow and its refusals, every caller the proxy refuses (no certificate, another CA, a KMS node's leaf, crossed bearers), malformed bodies, foreign and revoked connections, each request outside the allowlist, `invalid_grant` and other refresh failures, rotation, the retry after a 401, a body of exactly the cap and one byte over, and two concurrent calls sharing one refresh. Without `DATABASE_URL` the database tests return early.

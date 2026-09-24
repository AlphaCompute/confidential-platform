# alpha-broker

The platform's connector broker: an App of its own that connects a member's provider account, reads from it for the member's chats and writes the member's exports into it. It exchanges the provider's authorization code with a PKCE verifier only it holds, keeps each refresh token sealed (AES-256-GCM, the connection id as associated data) under the `connectors` key that only Instances of this App derive from the KMS, and forwards requests inside fixed lists with the member's access token attached. No token leaves the broker: the tenant's backend relays an opaque code, and the callers of `/proxy` and `/write` get the provider's answer only.

Every provider is one row of a fixed table in `src/oauth.rs`: its OAuth endpoints and scopes, how the account is named, how a grant is revoked, its read list, its write list and the request headers a caller may set. Google and Dropbox are the rows today; nothing outside the table names a provider.

A member is named by a member reference, the lowercase hex SHA-256 of the tenant's user id (64 characters). A connection is keyed by the provider account's stable subject; the email is only what the member sees.

## Configuration (environment only)

| Variable | Meaning |
|---|---|
| `GOOGLE_CLIENT_ID` | the tenant's OAuth client id at Google |
| `DROPBOX_CLIENT_ID` | the tenant's app key at Dropbox |
| `OAUTH_REDIRECT_BASE` | `https://` only; each provider's redirect URI is `<base>/<provider>/callback`, the tenant's page that relays the code |

Every row of the table needs its `<NAME>_CLIENT_ID`; a missing one is named in the error and the broker does not start.

Secrets, read from the runtime socket at start and every five minutes (`database-url` only at start): `<provider>-client-secret` for every row (`google-client-secret`, `dropbox-client-secret`: the tenant's OAuth client secrets), `connect-bearer` (the tenant backend's bearer for the connect routes and `/write`), `proxy-bearer` (the bearer of the App that calls `/proxy`, the Corpus worker's supervisor), `database-url`. The key purpose is `connectors`. A renewal that fails, as it does once the runtime removes its socket after the Revision is revoked, drains the listener and exits non-zero.

## Database

The broker has its own database and login role, `alpha_broker`, on the trust-zone Postgres, with no grant on the KMS's tables; `deploy/README.md` "The broker's database" says how they are created. It applies its migrations every time it starts (`alpha-broker migrate` applies them and stops). Two tables: `pending_connects` (a connect's state, the member, the sealed PKCE verifier, ten minutes of life, consumed once) and `connections` (member, provider, subject, email, sealed refresh token, scopes, `dead_at`, `revoked_at`). Access tokens are never written: each process caches them per connection until a minute before they expire.

## Listener

One port, 8443, TLS 1.3 with `X25519MLKEM768` and this Instance's KMS-issued leaf. A client certificate is requested and not required: when one is presented it must chain to the KMS CA (the last certificate of the broker's own chain from the runtime) or the handshake fails.

## Routes

Every error is `{"error": {"code", "message"}}`.

With `Authorization: Bearer <connect-bearer>` (else 401 `unauthorized`), called by the tenant's backend:

- `POST /connect/{provider}` `{"member"}` → `{"url"}`: the provider's authorization URL with PKCE S256 and the row's offline parameters (Google `access_type=offline` and `prompt=consent`, Dropbox `token_access_type=offline`). An unknown provider answers 404 `not_found`.
- `POST /connect/finish` `{"member", "code", "state"}` → `{"id", "provider", "account"}`. A state that is unknown, expired, used or another member's answers 400 `state_invalid`; a refused exchange or account lookup answers 502 `exchange_failed`. Connecting the same account again keeps its id and clears its dead mark.
- `GET /connections?member=<ref>` → `{"connections": [{"id", "provider", "account", "dead"}]}`, live connections only. `dead: true` means the provider refused the refresh token and the member must reconnect.
- `DELETE /connections/{id}?member=<ref>` → 204; revoked locally, then at the provider best effort (Google with the refresh token, Dropbox with a freshly refreshed access token as bearer), within five seconds and whatever the provider answers. An unknown, revoked or foreign id answers 404 `not_found`.
- `POST /write` `{"member", "connection_id", "method", "url", "content_type", "body_base64", "headers"?}`: one export into the member's account. The body is limited to 12 MiB (413 past it), enough for an 8 MiB file encoded inside its envelope. `url` must parse, `content_type` must be a valid header value and `body_base64` standard base64 (else 400 `malformed`); then the same checks as `/proxy` below, against the provider's write list instead of its read list. The decoded bytes are sent with that content type, and the reply is relayed as `/proxy` relays it.

With a client certificate carrying an Instance's two URI SANs (else 401 `cert_invalid`; a KMS node's leaf is refused the same way) and `Authorization: Bearer <proxy-bearer>` (else 401 `unauthorized`):

- `POST /proxy` `{"member", "connection_id", "method", "url", "body"?, "headers"?}`, where `headers` is an object of names to values. The checks run in this order, and each refuses before anything later happens: the connection is live and the member's (else 404 `not_found`); the method, host and path match one entry of the provider's read list (else 403 `not_allowed`); every header name, compared lowercase, is on the provider's header list (else 403 `not_allowed`) and every value is a valid header value, with no CR or LF (else 400 `malformed`); the connection is not dead (else 409 `reconnect_required`); an access token is cached or obtained by refreshing (the provider's `invalid_grant` marks the connection dead and answers 409 `reconnect_required`; any other failure answers 502 `upstream`). The request sent is the parsed URL with its query, the matched entry's method, the access token, the caller's allowed headers and the JSON body when one was given; a 401 from the provider drops the token, refreshes once and retries once. The reply is the provider's status, `content-type` and body, and no other response header; a body over 16 MiB answers 502 `too_large`, an unreachable provider 502 `upstream`. A refresh token the provider rotates is sealed and stored.

Malformed input anywhere, unknown fields included, answers 400 `malformed`. `GET /healthz` (the process) and `GET /ready` (200 once the database answers) need nothing.

## The read and write lists

Every entry is a method, an exact `https` host on the default port and a path; URLs with userinfo or a fragment are refused. Paths are matched segment by segment on the parsed URL (so `..` and its encoded forms are resolved before the check, and the checked path is the path sent); `{id}` is one segment of 1 to 256 characters of `[A-Za-z0-9_-]`. The lists, the header lists and the 16 MiB cap are constants, not configuration. `/proxy` consults only read lists and `/write` only write lists.

Google reads, all `GET` on `www.googleapis.com`:

- `/drive/v3/drives`, `/drive/v3/files`, `/drive/v3/files/{id}` (metadata, or the content with `alt=media`), `/drive/v3/files/{id}/export` (Docs, Sheets and Slides as text)
- `/gmail/v1/users/me/messages`, `/gmail/v1/users/me/messages/{id}`
- `/calendar/v3/calendars/primary/events`

The Docs, Sheets and Slides APIs are not reachable. The connect asks Google for `drive.readonly`, `gmail.readonly`, `calendar.readonly`, `drive.file`, `openid` and `email`; the last two only name the account. A caller may set no request header on a Google connection.

Dropbox reads, all `POST`: on `api.dropboxapi.com` `/2/files/list_folder`, `/2/files/list_folder/continue`, `/2/files/get_metadata`, `/2/files/search_v2`, `/2/files/search/continue_v2`, `/2/sharing/list_folders`, `/2/sharing/list_folders/continue`, `/2/users/get_current_account`; on `content.dropboxapi.com` `/2/files/download` and `/2/files/export`. A caller may set `Dropbox-API-Arg` (a content-host call's arguments) and `Dropbox-API-Path-Root` (a team space). The connect asks Dropbox for `account_info.read` (names the account by `account_id` and email), `files.metadata.read`, `files.content.read`, `files.content.write` and `sharing.read`.

The write list, all `POST`, for exports only: Google `www.googleapis.com` `/upload/drive/v3/files` (a file, `uploadType` in the query) and `/drive/v3/files` (a folder); Dropbox `content.dropboxapi.com` `/2/files/upload` and `api.dropboxapi.com` `/2/files/create_folder_v2`. Nothing deletes, moves, updates, overwrites by id or shares.

## What it does not promise yet

The broker trusts two bearers. Whoever holds the connect bearer can start and finish a connect for any member reference, and whoever holds the proxy bearer and any attested Instance leaf from the KMS can read any connected account inside the allowlist: the broker pins no caller Revision. The connect bearer also opens `/write`, so whoever holds it can upload into any connected Drive (only into files and folders this client created, which is what `drive.file` reaches) or anywhere in a connected Dropbox. The broker does not read an upload's arguments either: a Dropbox `Dropbox-API-Arg` asking to overwrite is forwarded as given, and choosing `mode: add` is the caller's. Both bearers are released to Apps the Corpus operator runs, so the Corpus operator can use members' connected accounts, reading and writing, until a key the member holds signs each request. What the broker does keep: tokens stay inside this App's CVMs and its sealed rows, the chat's credential never reaches a write entry, and nothing outside the lists reaches a provider.

## Tests

`DATABASE_URL=postgres://… cargo test -p alpha-broker` creates a fresh database per test and runs the routes against a TLS stand-in for Google and Dropbox reached through their real host names; the `/proxy` and `/write` tests go through the real mTLS listener with a stand-in KMS CA. Every reply, headers included, is checked for any token, code, verifier or client secret. `tests/connect.rs` and `tests/proxy.rs` cover the connect flow and its refusals, every caller the proxy refuses (no certificate, another CA, a KMS node's leaf, crossed bearers), malformed bodies, foreign and revoked connections, each request outside the read list, `invalid_grant` and other refresh failures, rotation, the retry after a 401, a body of exactly the cap and one byte over, and two concurrent calls sharing one refresh. `tests/dropbox.rs` covers a Dropbox connect and folder listing with a team-space header, each of the ten reads, the header list and line breaks in values, a dead refresh token, the download cap, disconnect with and without Dropbox's revoke answering, and each row's authorization URL. `tests/write.rs` covers the four write entries with their exact bytes and Dropbox's 409, the bearers `/write` refuses, every read entry refused on `/write`, every write entry and every delete, move, share or update refused on `/proxy`, malformed bodies, dead and foreign connections, and an 8 MiB file forwarded whole while a body over 12 MiB answers 413. Without `DATABASE_URL` the database tests return early.

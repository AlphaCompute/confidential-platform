# alpha-broker

The platform's connector broker: an App of its own that connects a member's provider account, reads from it for the member's chats and writes the member's exports into it. It exchanges the provider's authorization code with a PKCE verifier only it holds, keeps each refresh token sealed (AES-256-GCM, the connection id as associated data) under the `connectors` key that only Instances of this App derive from the KMS, and forwards requests inside fixed lists with the member's access token attached. No token leaves the broker: the tenant's backend relays sealed frames, and the callers of `/proxy` and `/write` get the provider's answer only.

Every provider is one row of a fixed table in `src/oauth.rs`: its OAuth endpoints and scopes, how the broker authenticates as the tenant's client, where the exchange reply keeps the tokens, which refresh errors mean the member must reconnect, how the account is named, how a grant is revoked, its read list, its write list, the request headers a caller may set and, for an MCP server, its tool list. Google, Dropbox, Slack, Figma, HubSpot and Notion are the rows today; nothing outside the table names a provider.

A member is the P-256 key its browser holds in WebCrypto and cannot export, never anything the tenant says about its users: a connection belongs to the key that signed its connect, and only that key can finish, list or remove it. Within a member, a connection is keyed by the provider account's stable subject; the email is only what the member sees.

## Configuration (environment only)

| Variable | Meaning |
|---|---|
| `GOOGLE_CLIENT_ID` | the tenant's OAuth client id at Google |
| `DROPBOX_CLIENT_ID` | the tenant's app key at Dropbox |
| `SLACK_CLIENT_ID` | the tenant's Slack app's client id |
| `FIGMA_CLIENT_ID` | the tenant's Figma app's client id |
| `HUBSPOT_CLIENT_ID` | the tenant's HubSpot MCP app's client id |
| `NOTION_CLIENT_ID` | the client id Notion's MCP server issued when the tenant registered its redirect URI |
| `OAUTH_REDIRECT_BASE` | `https://` only; each provider's redirect URI is `<base>/<provider>/callback`, the tenant's page that relays the code |

Every row of the table needs its `<NAME>_CLIENT_ID`; a missing one is named in the error and the broker does not start.

Secrets, read from the runtime socket at start and every five minutes (`database-url` only at start): `<provider>-client-secret` for every row that authenticates with one (`google-client-secret`, `dropbox-client-secret`, `slack-client-secret`, `figma-client-secret`: the tenant's OAuth client secrets; Slack needs its secret even with PKCE, since it refuses a refresh without one; `hubspot-client-secret` too; Notion has none, since the tenant registered a public client with Notion's MCP server once, and PKCE alone binds each code to the broker), `connect-bearer` (the tenant backend's bearer, which admits its relay to the channel and the member's routes and opens `/write`), `proxy-bearer` (the bearer of the App that calls `/proxy`, the Corpus worker's supervisor), `database-url`. The key purpose is `connectors`. A renewal that fails, as it does once the runtime removes its socket after the Revision is revoked, drains the listener and exits non-zero.

## Database

The broker has its own database and login role, `alpha_broker`, on the trust-zone Postgres, with no grant on the KMS's tables; `deploy/README.md` "The broker's database" says how they are created. It applies its migrations every time it starts (`alpha-broker migrate` applies them and stops). Three tables: `pending_connects` (a connect's state, the member's key, the sealed PKCE verifier, ten minutes of life, consumed once), `connections` (the member's key, provider, subject, email, sealed refresh token, scopes, `dead_at`, `revoked_at`) and `member_nonces` (every signed request's nonce, kept two minutes, past the last moment its document is fresh). Both of the first two hold the key's SPKI in `member_key` beside `member_key_sha256`, which a database check requires to be its SHA-256. The migration that added `member_key` deleted every earlier row, which named a member by the tenant's own reference to its user, so those members link their accounts again. Access tokens are never written: each process caches them per connection until a minute before they expire, or for an hour when the provider's refresh reply states no lifetime.

## Listener

One port, 8443, TLS 1.3 with `X25519MLKEM768` and this Instance's KMS-issued leaf. A client certificate is requested and not required: when one is presented it must chain to the KMS CA (the last certificate of the broker's own chain from the runtime) or the handshake fails.

## Routes

Every error is `{"error": {"code", "message"}}`.

### The member's routes

The page opens an attested channel to this Instance and sends each route below as one request frame on it; the tenant's backend relays frames and sealed replies and can read, forge or move neither. `docs/inner-channel.md` has the handshake, the frames and the member documents. Every route here needs `Authorization: Bearer <connect-bearer>` (else 401 `unauthorized`), which admits the tenant's relay and authorises nothing on a member's behalf.

- `POST /channel` `ClientHello` → `ServerHello`, signed by this Instance's current leaf and carrying its measured compose, so the page checks the Revision it reached before it sends anything. Channels live in this process only: at most 1024, each dropped after an hour unused or, when the table is full, least recently used first.

The four member routes each take one request frame. Before anything runs they refuse in plaintext: a body that is not a frame, or one that does not open on this method and path, with 400 `frame_invalid`; a frame whose sequence number was already opened with 409 `replayed`; a channel this process does not hold (expired, evicted or opened before a restart) with 409 `channel_unknown`, on which the page opens a new channel. Once a frame opens, the reply is one sealed line, refusals included; its HTTP status only mirrors the sealed one for the relay's logs. The opened body is `{"document", "member_key", "signature"}`, the document signed under `alphacompute/connector-request/v1` by the P-256 key whose SPKI (base64url DER) is `member_key`. The signature must verify under that key (else 401 `signature_invalid`); the document must be this route's `op` with no unknown field (else 400 `malformed`); its `issued_at` must be within a minute of the broker's clock (else 401 `request_stale`); and its nonce must be new (else 409 `nonce_replayed`). Nonces are kept in the database, so a restart does not reopen a replay.

- `POST /connect/{provider}`, `{"op": "connect", "provider"}` naming the path's provider → `{"url"}`: the provider's authorization URL with PKCE S256 and the row's offline parameters (Google `access_type=offline` and `prompt=consent`, Dropbox `token_access_type=offline`). HubSpot is sent no scope parameter, since the member picks a preset at consent; Notion is asked for `scope=default`. Slack is asked for `user_scope` only, comma-separated, so it issues a user token and never a bot token. An unknown provider answers 404 `not_found`.
- `POST /connect/finish`, `{"op": "finish", "state", "code"}` → `{"id", "provider", "account"}`. A state that is unknown, expired, used or started by another key answers 400 `state_invalid` and is spent either way; a refused exchange or account lookup answers 502 `exchange_failed`. The exchange authenticates as the row says: Google, Dropbox, Slack and HubSpot with the client secret in the form, Figma only in HTTP Basic, Notion with the client id and the verifier alone; Slack's user token is read from `authed_user`. Connecting the same account again keeps its id and clears its dead mark. A Slack account is the user within its team (`auth.test`, shown as `<user> @ <team>`), so a member in two workspaces has two connections; a Figma account is `/v1/me`'s id, shown as its email. HubSpot and Notion are named by a tool call on their MCP server, since HubSpot's introspection carries no account: HubSpot's `get_user_details` gives the subject `<accountId>:<userId>` (the hub and the user within it) and the email; Notion's `notion-fetch` of `self` gives `<workspace id>:<user id>` and the user's email, or its name when it has none.
- `POST /connections`, `{"op": "list"}` → `{"connections": [{"id", "provider", "account", "dead"}]}`, the signing key's live connections only. `dead: true` means the provider refused the refresh token and the member must reconnect.
- `DELETE /connections/{id}`, `{"op": "disconnect", "connection_id"}` naming the path's id → `{}`; revoked locally, then at the provider best effort (Google with the refresh token, Dropbox and Slack with a freshly refreshed access token as bearer, Notion with a freshly refreshed access token posted with the client id to its token endpoint; Figma and HubSpot offer no revoke, so their grant is ended locally only and stays valid there until the member removes the app or it expires), within five seconds and whatever the provider answers. An unknown, revoked or another key's id answers 404 `not_found`.

### Reads and writes

In `/write` and `/proxy`, `member` is the lowercase hex SHA-256 of the member's key (64 characters).

With `Authorization: Bearer <connect-bearer>` (else 401 `unauthorized`), called by the tenant's backend:

- `POST /write` `{"member", "connection_id", "method", "url", "content_type", "body_base64", "headers"?}`: one export into the member's account. The body is limited to 12 MiB (413 past it), enough for an 8 MiB file encoded inside its envelope. `url` must parse, `content_type` must be a valid header value and `body_base64` standard base64 (else 400 `malformed`); then the same checks as `/proxy` below, against the provider's write list instead of its read list. The decoded bytes are sent with that content type, and the reply is relayed as `/proxy` relays it.

With a client certificate carrying an Instance's two URI SANs (else 401 `cert_invalid`; a KMS node's leaf is refused the same way) and `Authorization: Bearer <proxy-bearer>` (else 401 `unauthorized`):

- `POST /proxy` `{"member", "connection_id", "method", "url", "body"?, "headers"?}`, where `headers` is an object of names to values. The checks run in this order, and each refuses before anything later happens: the connection is live and the member's (else 404 `not_found`); the method, host and path match one entry of the provider's read list (else 403 `not_allowed`); every header name, compared lowercase, is on the provider's header list (else 403 `not_allowed`) and every value is a valid header value, with no CR or LF (else 400 `malformed`); on an MCP row, the body passes the tool check below (else 403 `not_allowed`); the connection is not dead (else 409 `reconnect_required`); an access token is cached or obtained by refreshing (an error code on the row's list, `invalid_grant`, Slack's `invalid_refresh_token` or Notion's `invalid_token`, whatever the HTTP status, marks the connection dead and answers 409 `reconnect_required`; any other failure answers 502 `upstream`). The request sent is the parsed URL with its query, the matched entry's method, the access token, the caller's allowed headers (and, on an MCP row, the broker's own `Accept`) and the JSON body when one was given; a 401 from the provider drops the token, refreshes once and retries once. The reply is the provider's status, `content-type` and body, and no other response header; a body over 16 MiB answers 502 `too_large`, an unreachable provider 502 `upstream`. A refresh token the provider rotates, as Slack does on every refresh, is sealed and stored before the next call can use it. Slack answers every failure, its data calls included, with HTTP 200 and `{"ok": false, "error"}`, which is relayed as it is.

Malformed input anywhere, unknown fields included, answers 400 `malformed`. `GET /healthz` (the process) and `GET /ready` (200 once the database answers) need nothing.

## The read and write lists

Every entry is a method, an exact `https` host on the default port and a path; URLs with userinfo or a fragment are refused. Paths are matched segment by segment on the parsed URL (so `..` and its encoded forms are resolved before the check, and the checked path is the path sent); `{id}` is one segment of 1 to 256 characters of `[A-Za-z0-9_-]`. The lists, the header lists and the 16 MiB cap are constants, not configuration. `/proxy` consults only read lists and `/write` only write lists.

Google reads, all `GET` on `www.googleapis.com`:

- `/drive/v3/drives`, `/drive/v3/files`, `/drive/v3/files/{id}` (metadata, or the content with `alt=media`), `/drive/v3/files/{id}/export` (Docs, Sheets and Slides as text)
- `/gmail/v1/users/me/messages`, `/gmail/v1/users/me/messages/{id}`
- `/calendar/v3/calendars/primary/events`

The Docs, Sheets and Slides APIs are not reachable. The connect asks Google for `drive.readonly`, `gmail.readonly`, `calendar.readonly`, `drive.file`, `openid` and `email`; the last two only name the account. A caller may set no request header on a Google connection.

Dropbox reads, all `POST`: on `api.dropboxapi.com` `/2/files/list_folder`, `/2/files/list_folder/continue`, `/2/files/get_metadata`, `/2/files/search_v2`, `/2/files/search/continue_v2`, `/2/sharing/list_folders`, `/2/sharing/list_folders/continue`, `/2/users/get_current_account`; on `content.dropboxapi.com` `/2/files/download` and `/2/files/export`. A caller may set `Dropbox-API-Arg` (a content-host call's arguments) and `Dropbox-API-Path-Root` (a team space). The connect asks Dropbox for `account_info.read` (names the account by `account_id` and email), `files.metadata.read`, `files.content.read`, `files.content.write` and `sharing.read`.

Slack reads, all `GET` on `slack.com` with the caller's query: `/api/conversations.list`, `/api/conversations.history`, `/api/users.info`. Nothing that posts, reacts, joins or marks as read; threads (`conversations.replies`) are not on the list either. The connect asks for `channels:read`, `channels:history`, `groups:read`, `groups:history`, `im:read`, `im:history`, `mpim:read`, `mpim:history` and `users:read`, so direct messages are in reach.

Figma reads, all `GET` on `api.figma.com`: `/v1/me`, `/v2/teams/{id}/folders`, `/v2/folders/{id}/folders`, `/v2/folders/{id}/files`, `/v1/files/{id}`, `/v1/files/{id}/nodes`, `/v1/images/{id}`, `/v1/files/{id}/comments`. Nothing that writes (comments, reactions, variables, dev resources, webhooks). The connect asks for `current_user:read`, `file_content:read`, `file_metadata:read`, `file_comments:read` and `folders:read`; the exchange goes to `/v1/oauth/token` and refreshes to `/v1/oauth/refresh`, which returns no new refresh token.

HubSpot reads one entry, `POST` `mcp.hubspot.com` `/` (with or without the slash), and Notion one, `POST` `mcp.notion.com` `/mcp`; the broker sets `Accept: application/json, text/event-stream` on both, and a caller may set no header, `Accept` and `Mcp-Session-Id` included. Both servers answer `tools/list` and `tools/call` without a session, HubSpot in JSON and Notion in server-sent events, and the reply is relayed byte for byte like any other. HubSpot's scopes cannot be narrowed to reads, so for these rows the tool list is the fence.

## Tool calls

On an MCP row the broker reads the body only to hold `tools/call` to the row's tool list: the body must be one JSON object (a batch array, a string or no body is refused) whose `method` is `initialize`, `notifications/initialized`, `ping`, `tools/list` or `tools/call`; resources, prompts and completions are refused, since nothing has classified what they reach. A `tools/call` must name in `params.name` a string exactly on the list; no prefix, pattern, case change or the server's own annotations admit a tool. The other four methods pass unread. What is sent is the parsed JSON value the broker checked, never the caller's bytes, so a duplicated key is judged and sent by the same last value. A tool the provider renames or adds is refused until the list in `src/oauth.rs` changes.

- `HUBSPOT_READ_TOOLS`: `get_user_details`, `get_organization_details`, `discover_hubspot_schema`, `search_crm_objects`, `get_crm_objects`, `query_crm_data`, `search_properties`, `get_properties`, `search_owners`, `search_intent_signals`, `get_campaign_attribution_reports`, `read_campaign_data`, `search_conversations`, `get_conversation_channel_metadata`, `get_marketing_email_analytics`, `get_content_analytics_report`, `get_aeo_metrics`, `tool_guidance`. Every `manage_*` tool, `submit_feedback` and the `render_*` tools are off.
- `NOTION_READ_TOOLS`: `notion-search`, `notion-fetch`, `notion-query-data-sources`, `notion-query-multiple-data-sources`, `notion-query-meeting-notes`, `notion-get-comments`, `notion-get-users`, `notion-get-teams`, `notion-download-attachment`, `notion-get-tool-access`, `notion-get-async-task`, `notion-list-private-pages`, `notion-list-shared-pages`, `notion-list-favorite-pages`, `notion-list-recent-pages`. Off: every tool that creates, updates, moves or comments; `notion-ai-search`, which reaches the member's other apps connected to Notion; the skills tools; and the custom-agent tools, which start or read an agent acting in the workspace.

The write list, all `POST`, for exports only: Google `www.googleapis.com` `/upload/drive/v3/files` (a file, `uploadType` in the query) and `/drive/v3/files` (a folder); Dropbox `content.dropboxapi.com` `/2/files/upload` and `api.dropboxapi.com` `/2/files/create_folder_v2`. Nothing deletes, moves, updates, overwrites by id or shares.

## What it does not promise yet

Connecting, listing and disconnecting need the member's key, but reads and writes still rest on two bearers. Whoever holds the proxy bearer and any attested Instance leaf from the KMS can read any connected account inside the allowlist, a member's Slack direct messages included: the broker pins no caller Revision. The connect bearer opens `/write`, so whoever holds it can upload into any connected Drive (only into files and folders this client created, which is what `drive.file` reaches) or anywhere in a connected Dropbox. The broker does not read an upload's arguments either: a Dropbox `Dropbox-API-Arg` asking to overwrite is forwarded as given, and choosing `mode: add` is the caller's. Both bearers are released to Apps the Corpus operator runs, so the Corpus operator can use members' connected accounts, reading and writing, until a key the member holds signs each request. What the broker does keep: tokens stay inside this App's CVMs and its sealed rows, the chat's credential never reaches a write entry, and nothing outside the lists reaches a provider.

## Tests

`DATABASE_URL=postgres://… cargo test -p alpha-broker` creates a fresh database per test and runs the routes against a TLS stand-in for every provider reached through their real host names; members are fixed P-256 keys that sign their requests and send them sealed on a channel the test opens and checks as a page does, against a broker leaf from a stand-in KMS CA; the `/proxy` and `/write` tests go through the real mTLS listener with a stand-in KMS CA. Every reply, headers included, is checked for any token, code, verifier or client secret. `tests/connect.rs` holds the connect routes, `tests/proxy.rs` the read path, `tests/dropbox.rs`, `tests/slack.rs`, `tests/figma.rs`, `tests/hubspot.rs` and `tests/notion.rs` their rows, and `tests/write.rs` the write route and the refusals across the two routes. Without `DATABASE_URL` the database tests return early.

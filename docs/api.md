# bysyc API

The REST surface and the WebSocket gateway of `bysyc-server`. Every
value that crosses the network is defined exactly once in
`common/src/protocol.rs`; this document cites those types rather than
restate their fields, except where a route's request body is a bare
JSON shape the protocol file describes in prose. Route registration
lives in `server/src/routes.rs`, with each module owning its own
`router()`.

## Auth model

- **REST**: a session token in the `Authorization` header as
  `Bearer <token>`. The `Authed` extractor (`server/src/session.rs`)
  validates it against Redis (session keys are `GETEX`-read with a
  sliding TTL) and resolves to the account id; an invalid or missing
  token yields `ErrorCode::Unauthorized` (401). Every route below is
  authed unless noted.
- **WebSocket**: the gateway opens with
  `GET /ws?token=<token>&protocol=<PROTOCOL_VERSION>` where
  `PROTOCOL_VERSION` is `2` (`common::PROTOCOL_VERSION`). `protocol`
  must equal `2` (else 400 + `ErrorCode::ProtocolVersion`) and
  `token` must validate (else 401), both checked *before* the
  upgrade so failures land in the REST error envelope. Since v2 the
  gateway carries `WsClientMsg` / `WsServerMsg` as **binary
  MessagePack frames**; the read side still accepts legacy JSON text
  frames. The REST session survives a socket disconnect; only the
  gateway goes away.
- **Registration is invite-gated**: every Registration Invite works
  exactly once. The first account to register against a fresh
  database becomes the Instance's single admin; the server prints a
  first-registration token to its logs on first boot. The admin mints
  further single-use Registration Invites via `POST /auth/invites`.
- **Guild Invites** are minted by the Guild Owner via
  `POST /guilds/{guild_id}/invites`; they are use-limited and may
  expire. Channel create/delete and guild-invite issuance are
  Owner-only.
- **Auth rate limit**: `POST /auth/register` and `POST /auth/login`
  are per-IP throttled at `AUTH_RATE_PER_MIN` hits/min/IP (default `5`,
  overridable via env). Exceeding the limit returns `429`
  (`ErrorCode::RateLimited`). The limiter reads the direct peer
  (`ConnectInfo`) in local dev and the first hop of `X-Forwarded-For`
  behind Caddy. All other routes (logout, `/auth/me`, the WS upgrade)
  are unthrottled.

## Error envelope

Every failing REST response is a JSON `ApiError` (`common/src/protocol.rs`):

```json
{ "code": "unauthorized", "message": "session token expired" }
```

`code` is an `ErrorCode` variant and fixes the HTTP status:

| `ErrorCode` | HTTP | Typical cause |
|---|---|---|
| `unauthorized` | 401 | missing/expired/invalid session token |
| `forbidden` | 403 | authenticated but not allowed (not a member, not the Owner) |
| `not_found` | 404 | no such id, or not visible to the caller |
| `username_taken` | 400 | registration with an existing username |
| `invalid_invite` | 400 | registration or guild-join code unknown/expired/exhausted |
| `rate_limited` | 429 | too many auth attempts from this IP |
| `voice_channel_full` | 409 | voice channel already at the 6-participant cap |
| `protocol_version` | 400 | `protocol` parameter is not `2` |
| `invalid_request` | 400 | malformed body, bad enum, `Dm` where only text/voice allowed |
| `internal` | 500 | unexpected server fault |

## Auth (`server/src/auth.rs`)

| Method & path | Body | Success | Notes |
|---|---|---|---|
| `POST /auth/register` | `RegisterRequest { username, password, invite_code, identity_key }` | `TokenResponse { token, account: AccountInfo }` | username must be 3-32 chars of `[a-z0-9_.]`; `UsernameTaken` / `InvalidInvite` on failure; first registrant becomes admin; password hashed with Argon2id off the async runtime |
| `POST /auth/login` | `LoginRequest { username, password }` | `TokenResponse` | unknown user and wrong password are indistinguishable on the wire (`Unauthorized`) |
| `POST /auth/logout` | none | `204` | deletes the REST session; the WS socket, if any, is unaffected |
| `GET /auth/me` | none | `AccountInfo` | `Unauthorized` if the account no longer exists |
| `POST /auth/invites` | none | `{ "code": "<invite>" }` | admin-only; non-admins get `Forbidden` |

## Friends (`server/src/friends.rs`)

| Method & path | Body | Success | Notes |
|---|---|---|---|
| `GET /friends` | none | `FriendList { friends, incoming, outgoing }` | each list entry is an `AccountBrief` of the *other* side; presence stamped from `EXISTS presence:{id}` |
| `POST /friends/requests` | `{ "account_id": <i64> }` | `FriendList` | auto-accepts a reverse request (both become friends, both pushed `FriendRequestAccepted`); idempotent on an already-outgoing request; `InvalidRequest` if self / already friends |
| `POST /friends/requests/{account_id}/accept` | none | `FriendList` | `{account_id}` is the *other* account; `InvalidRequest` if no pending request from them |
| `POST /friends/requests/{account_id}/decline` | none | `FriendList` | declines the incoming request *and* cancels the caller's outgoing request to that account |
| `DELETE /friends/{account_id}` | none | `204` | removes the friendship; both sides pushed `FriendRemoved`; `NotFound` if not friends |
| `GET /accounts/by-username/{username}` | none | `AccountBrief` | resolves "add by username" to an account id; unknown username yields `NotFound` |

## Keys (`server/src/keys.rs`)

Olm prekey bootstrap. No friendship requirement: Olm prekey exchange
may legitimately reach accounts that are not yet Friends.

| Method & path | Body | Success | Notes |
|---|---|---|---|
| `PUT /keys/identity` | `{ "identity_key": "<b64>" }` | `204` | stores the long-term identity key on the caller's account |
| `POST /keys/otk` | `UploadOtkRequest { one_time_keys: Vec<String> }` | `204` | each entry is `"key_id:b64pubkey"` (the id must not contain `:`); at most 50 per call; last key_id wins on duplicate |
| `GET /keys/{account_id}` | none | `ClaimedKeys { identity_key, one_time_key }` | atomically claims (deletes) one one-time key so it is handed out at most once; `NotFound` if no such account, `InvalidRequest` if it has no identity key; an empty OTK pool returns `one_time_key: null` (not an error) |

## Guilds, channels, DMs (`server/src/guilds.rs`)

| Method & path | Body | Success | Notes |
|---|---|---|---|
| `POST /guilds` | `CreateGuildRequest { name }` | `GuildInfo` | caller becomes Owner and is auto-inserted as a Member; two default channels created (text `general`, voice `general`) |
| `GET /guilds` | none | `Vec<GuildInfo>` | guilds the caller is a Member of, channels included |
| `POST /guilds/join` | `JoinGuildRequest { code }` | `GuildInfo` | consumes one use; `InvalidInvite` if unknown/expired/exhausted; idempotent re-join returns the guild without consuming a use; existing Members pushed `MemberJoined`, the joiner pushed `GuildJoined` |
| `POST /guilds/{guild_id}/channels` | `CreateChannelRequest { name, kind }` | `ChannelInfo` | Owner-only; `kind` must be `Text` or `Voice` (`Dm` is rejected with `InvalidRequest`); members pushed `ChannelCreated` |
| `POST /guilds/{guild_id}/invites` | `CreateGuildInviteRequest { max_uses: Option<i64>, ttl_secs: Option<i64> }` | `GuildInviteDto` | Owner-only; both limits optional (`None` = unconstrained); expiry computed DB-side from `now()` |
| `POST /guilds/{guild_id}/leave` | none | `204` | the Owner may leave; the Guild persists ownerless in v1 (no transfer/dissolution); `NotFound` if not a member; remaining members pushed `MemberLeft` |
| `DELETE /channels/{channel_id}` | none | `204` | Owner-only; deletes the channel (messages cascade via FK, attachments' message links become NULL); DM channels are not deletable here (`NotFound`); members pushed `ChannelDeleted` |
| `POST /dms` | `OpenDmRequest { account_id }` | `DmChannel` | requires an accepted friendship (else `Forbidden`); idempotent (returns the existing channel for the pair); the peer's username becomes the synthesized channel name |
| `GET /dms` | none | `Vec<DmChannel>` | the caller's open DM channels with the peer brief on each side |

## Messages (`server/src/messages.rs`)

`content` is base64 ciphertext, opaque to the server: only its encoded
shape and size are validated (ADR-0001). The Instance stores it
verbatim and fans it out.

| Method & path | Body | Success | Notes |
|---|---|---|---|
| `POST /channels/{id}/messages` | `SendMessageRequest { kind, content, reply_to, attachment_id }` | `MessageDto` | caller must be a channel member; `content` is base64 ciphertext, at most 64 KiB decoded; `reply_to` must reference a message in this channel; the *sender* gets the DTO as the HTTP response (it is NOT echoed over the gateway); other `chan:{id}` subscribers receive it via pub/sub |
| `GET /channels/{id}/messages` | query `before=<id>&limit=<1..100>` | `MessagePage { messages, has_more }` | one page of history, oldest-first; control messages included (clients filter); omit `before` for the newest page; `limit` defaults to 50 and clamps to 1..100; `has_more` signals an older page |
| `DELETE /channels/{id}/messages/{message_id}` | none | `204` | sender-only (anyone else's message yields `Forbidden`); drops the row plus any attachment row/object (object removal is best-effort); pushes `MessageDeleted` to all `chan:{id}` subscribers, the deleter included (the `204` carries no body) |

## Attachments (`server/src/attachments.rs`)

Two flows share the `attachments` table. The request body limit is
raised to `ATTACHMENT_MAX_MB` (default 50) on this router only; every
other endpoint keeps axum's 2 MB default.

| Method & path | Body | Success | Notes |
|---|---|---|---|
| `POST /attachments` | `CreateAttachmentRequest { name, size, nonce }` | `CreateAttachmentResponse { attachment: AttachmentMeta, upload_url }` | reserves a row and returns a 15-min presigned `PUT` URL; the client encrypts on-device and PUTs raw ciphertext to `upload_url` (no auth header; the SigV4 query signature is the authorization); `encrypted: true` |
| `POST /attachments/image` | raw WebP bytes | `ImageUploadResponse { attachment: AttachmentMeta }` | the deliberate ADR-0001 exception: the Instance receives the raw bytes, validates them as WebP (RIFF/WEBP magic, not Content-Type), and stores them itself under a server-assigned `img_...webp` name; `encrypted: false`, empty nonce; no `upload_url` (bytes are already in object storage) |
| `GET /attachments/{id}/download-url` | none | `DownloadUrlResponse { url, expires_at_ms }` | 10-min presigned `GET`; v1 membership model: any authed account can mint a URL for any attachment id (the s3 key is unguessable, the URL expires, and the bytes are ciphertext only peers can decrypt) |

To attach a file to a message, reserve it via `POST /attachments`,
upload the ciphertext, then pass the returned `attachment.id` as
`SendMessageRequest.attachment_id`; `messages.rs` claims the row on
send.

## Mailbox (`server/src/mailbox.rs`)

Directed 1:1 ciphertext control items, typically Olm messages
carrying Megolm session keys (ADR-0001's sender-key bootstrap). Queued
for an account that may be offline: delivered as `MailboxAppend` while
online and re-drained in the `Ready` snapshot on reconnect; deleted
only when the client acknowledges via `WsClientBody::AckMailbox`.

| Method & path | Body | Success | Notes |
|---|---|---|---|
| `POST /mailbox` | `{ "to": <i64>, "content": "<b64 ciphertext>" }` | `204` | no friendship requirement (Olm prekey exchange may reach non-friends); unknown recipient yields `NotFound` (the insert's FK violation is mapped to 404); `content` is the same base64 ciphertext shape as messages |

## Voice (`server/src/voice.rs`)

| Method & path | Body | Success | Notes |
|---|---|---|---|
| `GET /turn` | none | `TurnInfo { urls, username, credential }` | static long-term TURN credentials for the whole Instance in v1 (`turn:<TURN_ADDR>`); shared user `bysyc` / `TURN_PASSWORD` |

Voice join/leave and WebRTC signaling relay happen over the gateway
(see below), not REST.

## WebSocket gateway (`server/src/ws.rs`)

`GET /ws?token=<token>&protocol=2` upgrades to a bidirectional
connection. Pre-upgrade failures return the REST error envelope
above. Post-upgrade, every server frame is a binary MessagePack
`WsServerMsg`; the reader accepts both binary MessagePack
`WsClientMsg` frames and legacy JSON text frames.

The first frame is `WsServerBody::Ready` (the full snapshot: account,
friends, incoming/outgoing requests, guilds, DM channels, and
undelivered mailbox items), queued before any pub/sub event by the
single-writer task layout. Connection lifecycle: set presence, fan out
`Presence{online:true}` to friends and guild co-members, send `Ready`,
then run until socket close. On disconnect: clear the presence key,
leave any voice channel, fan out `Presence{online:false}`. The REST
session survives disconnect.

The client sends `WsClientMsg { id, body }` where `body` is a
`WsClientBody` variant (`common/src/protocol.rs`):

| `WsClientBody` | Server effect |
|---|---|
| `Heartbeat` | refresh presence TTL and re-sync the subscription set (the sync point after joining a guild or opening a DM) |
| `Typing { channel_id }` | fanned out to `chan:{channel_id}` as `WsServerBody::Typing`; `Forbidden` if not a channel member |
| `AckMailbox { ids }` | deletes the acknowledged mailbox rows (idempotent) |
| `VoiceJoin { channel_id }` | joins the call; 6-participant cap (`VoiceChannelFull`); replies with a direct `VoiceState` and publishes a fresh `VoiceState` to the channel |
| `VoiceLeave` | leaves the current call (the wire carries no channel id; the server looks it up); remaining participants get a fresh `VoiceState` |
| `CallSignal { call_id, to, kind }` | relays `CallSignalKind` (`Offer`/`Answer`/`Candidate`/`Hangup`) to `to`; `Forbidden` unless both peers are in the call (voice channel participants, or the DM pair for a Private Call) |

The server sends `WsServerMsg { id: Option<i64>, body }` where `body`
is a `WsServerBody` variant. Besides the direct replies above, the
server pushes: `Message`, `MessageDeleted`, `MailboxAppend`,
`Presence`, `Typing`, `FriendRequested`, `FriendRequestAccepted`,
`FriendRemoved`, `GuildJoined`, `ChannelCreated`, `ChannelDeleted`,
`MemberLeft`, `MemberJoined`, `VoiceState`, `CallSignal`, and `Error`
(`{ reply_to, code, message }`, attributing a failed client message
by echoing its `id`). The pub/sub topic families are `acct:{id}`
(directed) and `chan:{id}` (channel-scoped); a small pool of shared
subscriber workers owns every Redis subscription in the process (see
[architecture.md](architecture.md#pubsub-fan-out)).

## Health

| Method & path | Body | Success |
|---|---|---|
| `GET /healthz` | none | `200` `ok` (plain text, no auth) |

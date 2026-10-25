# Architecture (one host)

bysyc is single-tenant: one `docker compose` stack on one VPS serves
one Instance (see `CONTEXT.md` for the domain term). This page ties
together the [README "How it works"](../README.md#how-it-works)
section, the one-host topology and port table in
[deployment.md](deployment.md), and the ADRs. Refer to those for
detail; this page is the one-host data flow.

## Data flow

```
                         Internet
                            │
                            ▼
                 Caddy :443 (TLS, ACME :80)
                            │  reverse_proxy (HTTP + WS upgrade)
                            ▼
            bysyc-server :8080  (axum, plain HTTP, no TLS)
                 │         │         │
                 │         │         └─► SeaweedFS-S3 :8333  (loopback)
                 │         │               presigned PUT/GET for ciphertext blobs;
                 │         │               SigV4 auth via s3.json; server is sole S3 client
                 │         └─► Redis :16379  (loopback)
                 │               pub/sub fan-out: acct:{id}, chan:{id}
                 │               + session tokens (GETEX) + presence keys (SET EX 90s)
                 └─► Postgres :15432  (loopback)
                      accounts, friends, friend_requests, guilds, guild_members,
                      channels, dm_channels, messages, attachments,
                      one_time_keys, mailbox, voice_participants

   coturn :3478 tcp+udp  +  :49160-49200/udp   ◄── WebRTC peers (mesh voice)
                          DTLS-SRTP end-to-end; coturn relays packets without keys
```

Caddy terminates TLS and proxies both REST and the WebSocket upgrade
to `bysyc-server` on `127.0.0.1:8080`. The server has no built-in TLS
(see [deployment.md](deployment.md#architecture-one-host)); Caddy is
mandatory on a public VPS. Postgres, Redis, and SeaweedFS stay
loopback-bound, so only Caddy `:443`/`:80` and coturn
`:3478`/`:49160-49200` face the internet. The port table and `ufw`
rules live in [deployment.md](deployment.md#ports-to-open); this page
does not repeat them.

## Request paths

- **REST**: client -> Caddy -> `bysyc-server` (axum). Auth is a
  session token in `Authorization: Bearer <token>`; the full route
  surface is in [api.md](api.md). Bodies are JSON, built from the
  shared types in `common/src/protocol.rs` (the single contract
  between client and server).
- **Realtime**: client -> Caddy -> `GET /ws?token=<token>&protocol=2`
  -> axum WebSocket upgrade. Since protocol v2 the gateway carries
  binary MessagePack frames (`encode_ws_server_msg` /
  `decode_ws_client_msg` in `common/src/protocol.rs`); the read side
  still accepts legacy JSON text frames from older clients. The first
  frame on any connection is `Ready`, queued before any pub/sub event
  by the single-writer task layout.

## Pub/sub fan-out

State mutations publish to Redis; the gateway subscribes and
forwards. Two topic families:

- `acct:{id}` (directed events): presence, friend requests, mailbox
  append, relayed call signals.
- `chan:{id}` (channel events): messages, typing, voice state, for
  every channel the account can read.

A small pool of shared subscriber workers (`WS_EVENT_WORKERS`, default
4, spawned once in `main`) owns every Redis subscription in the
process. Each connection is homed round-robin to one worker, so it
observes all of its topics on one ordered stream (a Megolm session
share on `acct:{id}` arrives before the message it unlocks on
`chan:{id}`). The worker transcodes each JSON pub/sub payload to a
binary MessagePack frame once; every connection homed there reuses
the same frame bytes. A lagging connection drops events and backfills
via `GET /channels/{id}/messages`. Detail: `server/src/ws.rs`,
`server/src/events.rs`.

## Voice (mesh WebRTC + TURN)

A Call lives in a voice channel: presence in the channel is presence
in the Call (see `CONTEXT.md`). Clients exchange SDP/ICE directly
peer-to-peer (full-mesh, DTLS-SRTP), so no server component ever sees
media. coturn relays already-encrypted packets for peers behind hard
NATs without decryption. Capped at 6 participants and audio-only for
v1; the topology only breaks down with video. Signaling is relayed
through the gateway as `WsClientBody::CallSignal` /
`WsServerBody::CallSignal`. See
[ADR-0002](adr/0002-calls-mesh-webrtc-with-turn-relay.md).

## Crypto layering

Messages are ciphertext the Instance validates only for shape and
size; plaintext exists only on devices. DMs use Olm (vodozemac)
double-ratchet with prekey bootstrap through directed mailboxes, so a
DM can start while the peer is offline. Guild channels use
per-sender Megolm sessions with keys distributed pairwise over
Olm-encrypted control messages (the WhatsApp sender-key model). The
Instance never holds keys. Members joining a channel can only
decrypt from their join point onward. See
[ADR-0001](adr/0001-e2ee-vodozemac-olm-megolm.md); domain terms
(Instance, Account, Identity Key, Friend, Message, Guild, Channel,
DM, Call) in [CONTEXT.md](../CONTEXT.md).

## Client

The client is one pure-Rust egui/eframe desktop app: GPU-rendered,
immediate-mode, repaints only on interaction. Local state is SQLite
(rusqlite, bundled); the session token and pickle passphrase live in
a 0600 `secrets.json` in the data dir, not the OS keychain
([ADR-0003](adr/0003-pure-rust-egui-client.md),
[ADR-0006](adr/0006-session-secrets-in-0600-file.md)). Voice uses
str0m (sans-I/O WebRTC) over a tokio-owned UDP loop, with cpal for
capture and Opus for the codec. See `README.md` for v1 limits (one
device per account, audio-only calls, no read receipts).

## Cross-references

- [README.md](../README.md): quickstart, "How it works", v1 limits.
- [docs/deployment.md](deployment.md): VPS deploy, port table,
  hardening, Caddy and coturn config.
- [docs/api.md](api.md): REST and WS route surface.
- [docs/adr/](adr/): 0001 Olm/Megolm, 0002 mesh WebRTC + TURN,
  0003 pure-Rust egui client, 0005 client secrets in a 0600 file.

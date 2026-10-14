# bysyc

Self-hosted, end-to-end encrypted chat + calls for a small group of friends.
Pure Rust: egui client, axum server. See `CONTEXT.md` for the domain glossary
and `docs/adr/` for the load-bearing decisions.

## What's implemented (v1 complete)

- **Accounts + friends** — invite-gated registration, identity keys, friend
  requests with accept/decline, presence (online/offline) over the gateway.
- **E2EE text chat** — Olm (vodozemac) pairwise sessions carry Megolm session
  keys through a per-account mailbox; Megolm group sessions encrypt every
  channel (DMs and guild channels). Sessions rotate at 100 messages / 1 week;
  newcomers decrypt from their join point onward. The Instance stores and
  relays ciphertext only (ADR 0001).
- **Guilds** — create, invite by code, join; default text + voice channels.
- **Files & images** — client-side encrypted (key + nonce travel inside the
  Megolm envelope), stored in SeaweedFS via its S3 API.
- **Calls** — 1:1 private calls and guild voice channels: mesh WebRTC with a
  TURN relay (coturn), audio-only, capped at 6 speakers per channel.
- **Desktop client** — egui/eframe, one binary, one device per account (v1).

## Quickstart (full deployment via Docker)

Requires [mise](https://mise.jdx.io) (or Rust 1.99+) and Docker.

```
mise install                                # pinned Rust toolchain
cp .env.example .env                        # set POSTGRES_PASSWORD, TURN_PASSWORD,
                                            # S3 keys, ADMIN_PASSWORD, TURN_ADDR
# generate deploy/seaweedfs/s3.json from the S3_ACCESS_KEY/S3_SECRET_KEY
# in .env (the compose file mounts it into SeaweedFS; it enforces SigV4
# with exactly those credentials — see the comment in docker-compose.yml)
docker compose up -d --build                # postgres, redis, seaweedfs, coturn, bysyc-server
mise exec -- cargo run -q -p bysyc-server -- make-invite   # mint a registration invite
mise run dev-client                         # or: cargo run -p bysyc-client
```

Register with the invite, add each other as friends, and you're chatting
E2EE. `GET /healthz` on the server port answers `ok` when the Instance is up.

## Development workflow

```
mise run infra-up       # postgres, redis, seaweedfs, coturn via docker compose
mise run dev-server     # axum on :8080 (sources .env; /healthz)
mise run dev-client     # egui window
mise run test-e2e       # live two-account e2e against the dev server
mise run release        # cargo build --release --workspace (thin LTO)
mise run check          # cargo check --workspace
```

`test-e2e` sources `.env`, mints its own invites (or takes `INVITE_A` /
`INVITE_B`), creates two throwaway accounts with random suffixes, and drives
the real client stack — net, state, store, crypto, the actual composer send
path — over REST + WebSocket against the running dev server: friendship,
presence edges, DM E2EE in both directions, Megolm session reuse, and a guild
message shared to a newcomer. It is `#[ignore]`-gated and skipped unless
`BYSYC_E2E=1`, so plain `cargo test` stays hermetic.

## Architecture (one paragraph)

Three crates: `common` (wire protocol shared by both sides), `server` (the
"Instance": axum REST + one WebSocket gateway, Postgres for state, Redis
pub/sub for event fan-out, SeaweedFS-S3 for encrypted blobs), and `client`
(egui UI over the same net/state/store modules the e2e test drives). The
Instance is a delivery engine for ciphertext: clients establish Olm sessions
via one-time keys and use them solely to transport Megolm group-session keys
through directed mailboxes; channel messages are Megolm ciphertext the server
validates only for shape and size. Voice is mesh WebRTC with TURN fallback.
The load-bearing decisions — Olm/Megolm layering (0001), mesh WebRTC + TURN
(0002), pure-Rust egui client (0003) — are written up in `docs/adr/`.

## Known v1 limits

- One device per account: a second login supersedes the first; no multi-device
  key sync.
- If a guild's owner leaves, the guild continues without an owner (no transfer).
- `file_meta` (attachment names/sizes after decryption) is in-memory client
  state: it is not repopulated for old rows after a client restart.
- The chat `ScrollArea` assumes a uniform row height; very tall images render
  with imperfect scroll anchoring.
- No read receipts, message editing, or reactions.
- TURN uses static shared credentials (`TURN_ADDR` + `TURN_PASSWORD` for
  everyone); no per-session credential issuance.
- Video and SFU-based large calls are v2 territory; v1 calls are audio-only
  mesh (max 6).

## Layout

- `client/` — egui/eframe desktop app (Windows, macOS, Linux)
- `server/` — axum REST + WebSocket gateway (single binary; `make-invite` CLI)
- `common/` — wire types shared by client and server
- `deploy/seaweedfs/` — S3 credential config generated from `.env`
- `docs/adr/` — architecture decision records

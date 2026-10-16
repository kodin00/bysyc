# bysyc

Self-hosted, end-to-end encrypted chat + voice calls for a small group of
friends — a tiny private Discord. The server only stores and relays
ciphertext; keys never leave the clients. Pure Rust: egui desktop client,
axum server.

## Quickstart

Needs [mise](https://mise.jdx.io) and Docker.

Everything in Docker:

```
mise install
cp .env.example .env      # set POSTGRES_PASSWORD, TURN_PASSWORD, S3 keys,
                          # TURN_ADDR (and COTURN_EXTERNAL_IP on a VPS)
# put the same S3 keys into deploy/seaweedfs/s3.json (accessKey/secretKey)
docker compose up -d --build
curl localhost:8080/healthz   # → ok
mise run dev-client
```

Or dev on the host — backing services in Docker only (don't also
`docker compose up`: both claim port 8080):

```
mise run infra-up         # postgres, redis, seaweedfs, coturn
mise run dev-server
mise run dev-client       # another terminal
```

## Adding people

Registration is invite-gated; every code works exactly once. First boot
against a fresh database prints a first-registration token to the server
logs (`docker compose logs server`) — the first person to register with it
becomes the Instance admin. The admin mints further single-use invite codes
from the client's Settings → Invites panel; the operator can also mint one
from the host:

```
set -a; . ./.env; set +a; cargo run -q -p bysyc-server -- make-invite
```

Friends register from the client's login screen (Register tab, paste the
code). For friends on other machines: point the client at
`http://<your-ip>:8080` — in dev mode set `BIND_ADDR=0.0.0.0:8080`, and set
`TURN_ADDR` to your LAN address (e.g. `192.168.1.10:3478`) so calls work.

## Commands

```
mise run check          # cargo check --workspace
mise run dev-server     # server on the host (sources .env)
mise run dev-client     # desktop client
mise run infra-up       # start postgres/redis/seaweedfs/coturn
mise run infra-down     # stop them
mise run test-e2e       # live two-account e2e test (needs dev-server)
mise run release        # optimized workspace build
```

## How it works

Three crates: `common` (wire protocol), `server` (axum REST + one WebSocket
gateway; Postgres state, Redis pub/sub fan-out, SeaweedFS-S3 blobs), and
`client` (the egui app). Clients establish Olm (vodozemac) sessions to
transport Megolm group-session keys through directed mailboxes; channel
messages are Megolm ciphertext the server validates only for shape and size.
Voice is mesh WebRTC with a TURN relay for hard NATs.

Deeper reading: `CONTEXT.md` (domain glossary), `docs/adr/` (Olm/Megolm
layering, mesh WebRTC + TURN, pure-Rust egui client).

## v1 limits

- One device per account — a second login supersedes the first.
- Calls are audio-only, max 6 speakers per channel; video/SFU is v2.
- No read receipts, message editing, or reactions.
- TURN uses one static shared credential; attachment metadata isn't kept
  across client restarts.

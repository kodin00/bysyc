# bysyc

Self-hosted, end-to-end encrypted chat + voice calls for a small group of
friends — like a tiny private Discord. The server stores and relays ciphertext
only; the keys never leave your clients. Pure Rust: egui desktop client,
axum server.

## Quickstart

You need [mise](https://mise.jdx.io) and Docker.

### Option A — everything in Docker

```
mise install                          # pinned Rust toolchain
cp .env.example .env                  # then edit .env and set:
                                      #   POSTGRES_PASSWORD, TURN_PASSWORD,
                                      #   S3_ACCESS_KEY + S3_SECRET_KEY,
                                      #   ADMIN_USERNAME + ADMIN_PASSWORD, TURN_ADDR
```

Next, put the same S3 keys into `deploy/seaweedfs/s3.json` — edit the
`accessKey`/`secretKey` fields to match `.env` (compose mounts this file into
SeaweedFS; it's what enforces S3 auth):

```
docker compose up -d --build          # postgres, redis, seaweedfs, coturn, bysyc-server
curl localhost:8080/healthz           # → ok
mise run dev-client                   # build + run the desktop client
```

### Option B — dev on the host

Server and client run natively; only the backing services run in Docker:

```
mise run infra-up                     # postgres, redis, seaweedfs, coturn only
mise run dev-server                   # sources .env, binds 127.0.0.1:8080
mise run dev-client                   # in another terminal
```

> Don't combine `docker compose up -d` with `mise run dev-server`: the compose
> `server` service also claims port 8080 (on all interfaces) and the two will
> collide. `infra-up` is the right companion to `dev-server`.

## Adding people

Registration is invite-gated — every code works exactly once.

- On first boot against a fresh database, the server creates an **admin
  account** from `ADMIN_USERNAME`/`ADMIN_PASSWORD` (only when the accounts
  table is empty) and logs one invite code — check the server logs. This
  account exists just to get the Instance off the ground.
- For every additional person, mint a code from the repo root:

```
set -a; . ./.env; set +a; cargo run -q -p bysyc-server -- make-invite
```

  It prints a single-use code. The server binary does not read `.env` itself,
  so the `set -a` lines load it into the environment first. This works from
  the host in both modes — in full-Docker mode the database is published on
  `127.0.0.1:15432`.

- Friends register from the client's login screen: switch to **Register**,
  paste the invite code, done.

**Friends on other machines** need the server to be reachable:

- Full-Docker mode already listens on all interfaces (`0.0.0.0:8080`).
- Dev mode binds loopback by default — set `BIND_ADDR=0.0.0.0:8080` in `.env`
  before `mise run dev-server`.
- On the LAN, also set `TURN_ADDR` in `.env` to your machine's LAN address
  (e.g. `192.168.1.10:3478`) — the server hands it to clients for calls.
- Friends point the client at `http://<your-lan-ip>:8080`.
- One account per device: logging in a second time supersedes the first
  login (v1).

## Everyday commands

```
mise run check          # cargo check --workspace
mise run dev-server     # run the server on the host (sources .env)
mise run dev-client     # run the desktop client
mise run infra-up       # start postgres/redis/seaweedfs/coturn
mise run infra-down     # stop them
mise run test-e2e       # live two-account e2e test (needs dev-server running)
mise run release        # optimized workspace build
```

## How it works

Three crates: `common` (wire protocol), `server` (the "Instance": axum REST +
one WebSocket gateway, Postgres for state, Redis pub/sub for fan-out,
SeaweedFS-S3 for encrypted blobs), and `client` (the egui desktop app). The
Instance is a delivery engine for ciphertext: clients establish Olm
(vodozemac) sessions to transport Megolm group-session keys through directed
mailboxes; channel messages are Megolm ciphertext the server validates only
for shape and size. Voice is mesh WebRTC with a TURN relay for hard NATs.

Deeper reading: `CONTEXT.md` (domain glossary) and `docs/adr/` for the
load-bearing decisions — Olm/Megolm layering (0001), mesh WebRTC + TURN
(0002), pure-Rust egui client (0003).

## Known limits (v1)

- One device per account — a second login supersedes the first.
- A guild keeps running if its owner leaves; no ownership transfer.
- Decrypted attachment names/sizes aren't remembered across client restarts.
- Chat scroll anchoring is imperfect around very tall images.
- No read receipts, message editing, or reactions.
- TURN uses one static shared credential for everyone.
- Calls are audio-only, max 6 speakers per channel; video/SFU is v2.

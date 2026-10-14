# bysyc

Self-hosted, end-to-end encrypted chat + calls for a small group of friends.
Pure Rust: egui client, axum server. See `CONTEXT.md` for the domain glossary
and `docs/adr/` for the load-bearing decisions.

## Layout

- `client/` — egui/eframe desktop app (Windows, macOS, Linux)
- `server/` — axum REST + WebSocket gateway (single binary)
- `common/` — wire types shared by client and server

## Development

Requires [mise](https://mise.jdx.io) and Docker.

```
mise install            # rust toolchain (pinned in mise.toml)
cp .env.example .env    # set passwords
mise run infra-up       # postgres, redis, seaweedfs, coturn via docker compose
mise run dev-server     # axum on :8080 (healthz at /healthz)
mise run dev-client     # egui window
```

## Deploy

`docker compose up -d --build` runs the full Instance (postgres, redis,
seaweedfs, coturn, bysyc-server).

## Milestones

1. Auth + accounts + friends
2. Guilds/channels + E2EE text chat (vodozemac: Olm DMs, Megolm channels)
3. File/image upload (client-side encrypted, SeaweedFS via S3)
4. 1:1 private calls (mesh WebRTC)
5. Guild voice channels (mesh, cap 6, audio-only)

# Deploy notes

`docker-compose.yml` (at the repo root) is the single entry point for a
self-hosted bysyc instance. Copy `.env.example` to `.env` and fill in the
passwords before `docker compose up`; the compose file fails closed if any
required variable is unset.

## SeaweedFS S3 identity config

The `seaweedfs` service mounts `deploy/seaweedfs/s3.json` read-only at
`/etc/seaweedfs/s3.json` and starts the S3 gateway with
`-s3.config=/etc/seaweedfs/s3.json`, which enforces SigV4 auth on the
gateway. The real `s3.json` is **gitignored** (see `.gitignore`) so secrets
never land in the repo — only the template `s3.json.example` is committed.

A fresh checkout therefore has no `s3.json`, and `docker compose up` would
mount a broken/empty bind and the S3 gateway would fail to boot. Set it up
once before first start:

1. Copy the template into place:

   ```sh
   cp deploy/seaweedfs/s3.json.example deploy/seaweedfs/s3.json
   ```

2. Open `deploy/seaweedfs/s3.json` and set the `bysyc` identity's
   `accessKey` / `secretKey` to the **same values** you put in `.env` as
   `S3_ACCESS_KEY` / `S3_SECRET_KEY`. The bysyc server authenticates to the
   S3 gateway with the `.env` pair; SeaweedFS authorizes it via the
   `s3.json` pair, so they must match exactly (the gateway rejects SigV4
   requests whose signing key isn't in `s3.json`).

3. Regenerate / re-edit `s3.json` whenever you rotate `S3_*` keys in
   `.env`, then `docker compose restart seaweedfs server`.

Never commit `deploy/seaweedfs/s3.json`. The `anonymous` identity keeps
read-only access so unauthenticated `HEAD`/`GET` probes resolve; the bysyc
identity holds the full action set the server needs.

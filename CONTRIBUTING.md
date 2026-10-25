# Contributing to bysyc

bysyc is a small, single-tenant self-hosted project. These notes cover
the local workflow; see `README.md` for the quickstart, `CONTEXT.md`
for the domain glossary, and `docs/` for architecture and deployment.

## Toolchain

`mise.toml` pins `rust = "1.99.0"` (edition 2024, declared in
`Cargo.toml`). Use [mise](https://mise.jdx.io):

```
mise install
```

or match that toolchain by hand. A mismatched compiler will trip
`cargo check` on edition-2024 syntax.

## mise tasks

Every routine entry point is a mise task (definitions in `mise.toml`):

| Task | Does |
|------|------|
| `mise run check` | `cargo check --workspace` |
| `mise run dev-server` | run `bysyc-server` on the host (sources `.env`) |
| `mise run dev-client` | run the desktop client |
| `mise run infra-up` | start the postgres/redis/seaweedfs/coturn containers |
| `mise run infra-down` | stop them |
| `mise run test-e2e` | live two-account e2e test (needs `dev-server`) |
| `mise run release` | optimized workspace build |

`cargo build` / `cargo test` from the workspace root also work
directly. The compose infra (`infra-up`) is only needed for the dev
server and the e2e test.

## Tests and the `BYSYC_E2E` gate

Normal `cargo test` is hermetic: it never touches the network, the
compose infra, or a live database. The one exception is the live
two-account end-to-end test (`client/tests/e2e.rs`), which exercises
the real client stack (REST, the WS gateway loop, the SQLite store,
and the Olm/Megolm crypto engine) against a running Instance. It is
gated twice:

- `#[ignore]` keeps plain `cargo test` (and a bare `cargo test
  --ignored`) from running it; and
- the test body no-ops unless `BYSYC_E2E=1`, so a stray `--ignored`
  invocation is a silent no-op rather than a misleading failure.

Run it via mise, which sources `.env` (so the `make-invite` helper can
reach the DB) and sets the gate for you:

```
mise run dev-server        # terminal 1 (needs mise run infra-up)
mise run test-e2e          # terminal 2
```

Or directly:

```
BYSYC_E2E=1 cargo test -p bysyc-client --test e2e -- --ignored --nocapture
```

## Commits

Match the existing history: one short lowercase subject with a scope
prefix, `server:` / `client:` / `common:` / `docs:`. Browse the real
history with `git log --oneline -10`; representative subjects:

```
server: attachments (presigned S3), voice channels, TURN
client: hover actions overlay (no height shift, bare icons), zero vertical padding composer
common: msgpack ws wire codec (protocol v2), binary gateway frames, none-omission
docs: api surface, architecture diagram, contributing notes
```

No attribution trailers of any kind: no `Co-Authored-By:`, no
"Generated with/by <tool>" / no AI-tool footers anywhere, not in
commits, PRs, or code comments. See `AGENTS.md`. Commits and PRs read
as if written by a human.

## Secrets

Never commit secrets (`.env`, invite codes, keys). The server reads
its secrets from `.env` (copy `.env.example`); the client keeps its
session token and pickle passphrase in a local 0600 file, never the OS
keychain (ADR-0005). Server-side, `chmod 600 .env` and back it up
somewhere safe; losing `POSTGRES_PASSWORD` locks you out of your own
DB.

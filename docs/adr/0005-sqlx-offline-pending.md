# sqlx compile-time checking: offline mode pending a CI step

Status: pending (offline query data not yet checked in).

## Context

`server/Cargo.toml` enables sqlx's `macros` feature so the crate can adopt
`query!` / `query_as!` / `query_scalar!` for compile-time SQL validation. The
compile-time macros check every query's SQL text and bind types against the
live database schema at build time. In a CI / contributor workflow that runs
without a live Postgres, sqlx supports an **offline mode**: a prior
`cargo sqlx prepare --workspace` run emits `.sqlx/query-*.json` files checked
into the repo, and subsequent builds read those instead of a database.

## Decision (this commit)

The `macros` feature is **enabled**, but **every query in the server crate is
still a runtime `sqlx::query(...)` / `query_as(...)` / `query_scalar(...)` call**.
No `query!` / `query_as!` / `query_scalar!` macro is in use yet, and the
`.sqlx/` directory of offline query data has **not** been generated.

Rationale: this commit was prepared without `cargo`, `docker`, `mise`, or
`psql` available in the working environment, so `cargo sqlx prepare` could not
be run. Leaving the macros in place without offline data would break the
build (a macro expansion with no database and no `.sqlx/` data fails to
compile). The safe state is: feature on, queries runtime, no macros invoked.

## Why this is the safe intermediate

- With the `macros` feature on but no macros invoked, `cargo check` / `cargo
  build` succeed exactly as before — the feature only gates the macro
  definitions; they must be *called* to require database access.
- Every existing runtime query keeps working unchanged.
- The MEMBER_OF-interpolated dynamic query in `messages.rs` (the
  `AssertSqlSafe(format!(...))` shapes) **cannot** become a `query!` macro at
  all: the macros cannot interpolate an identifier into the SQL text, so that
  query stays runtime permanently regardless of this ADR's resolution.

## The pending step (to close this ADR)

An operator or CI job with `docker` and `cargo` available runs, in order:

```sh
# 1. Bring up Postgres (and Redis/SeaweedFS/coturn if the broader suite runs).
mise run infra-up          # or: docker compose up -d postgres

# 2. Apply the schema. The migrations live inline in server/src/db.rs as the
#    MIGRATION_1..MIGRATION_4 constants; the server's db::migrate applies them
#    guarded by schema_migrations. Easiest: run the server once against the
#    empty database so migrate() runs on boot, e.g.:
DATABASE_URL=postgres://bysyc:bysyc@localhost:5432/bysyc cargo run -p bysyc-server
#    (Ctrl-C once it logs "applied database migration" / "first-registration
#     token"). Or extract the CREATE statements to a temp .sql and psql them.

# 3. Generate the offline query data.
DATABASE_URL=postgres://bysyc:bysyc@localhost:5432/bysyc cargo sqlx prepare -p bysyc-server

# 4. Commit the generated .sqlx/ tree (it is referenced by sqlx at build time
#    when DATABASE_URL is unset).
```

Once `cargo sqlx prepare` succeeds and emits `.sqlx/query-*.json`, the **static**
queries in `keys.rs`, `ws.rs`, `mailbox.rs`, `guilds.rs`, `messages.rs`, and
`auth.rs` can be migrated one by one from `sqlx::query(...)` to `query!` /
`query_as!` / `query_scalar!` — **only** when the matching `.sqlx/query-*.json`
is present (the CRITICAL SAFETY rule: never leave a macro in place without its
offline data, or the build breaks for anyone without a database).

## Why not just keep runtime queries forever

Runtime queries defer SQL mistakes to production: a typo in a column name, a
bind-type mismatch, or a schema drift surfaces as a 500 at the call site, not
as a compile error. Compile-time checking moves those to `cargo build`, which
is the point of paying the sqlx macro complexity. The offline data is what
makes that affordable for contributors without a local Postgres.

## The one query that stays runtime permanently

`messages.rs`'s `MEMBER_OF` is a compile-time `const &str` interpolated into
several queries via `AssertSqlSafe(format!(...))`:

- `can_read`'s `SELECT {MEMBER_OF}` predicate,
- `send_message`'s `SELECT {MEMBER_OF} AS member, ...` precondition, and
- `send_message`'s `INSERT ... SELECT ... WHERE {MEMBER_OF} ... RETURNING`.

`cargo sqlx prepare` cannot capture a query whose text is built at runtime by
`format!` (the macros interpolate only values via `$1` bind parameters, never
arbitrary SQL identifiers), so these three stay as runtime
`sqlx::query(...)` calls. `AssertSqlSafe` documents that the interpolation is
this compile-time constant only — nothing user-controlled reaches the SQL text.

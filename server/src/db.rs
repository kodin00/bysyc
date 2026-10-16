//! AppState + boot glue (pool construction, migrations, admin bootstrap).
//! Pool/struct owned by the orchestrator; migrate/bootstrap/make_invite
//! bodies are owned by S1 and replace the no-op stubs below.

use crate::config::Config;
use rand::distr::{Alphanumeric, SampleString};

#[derive(Clone)]
pub struct AppState {
    pub pg: sqlx::PgPool,
    pub redis: redis::aio::ConnectionManager,
    /// Second manager on its own connection, dedicated to event publishes —
    /// a clone of [`Self::redis`] would share one pipe, so publishes could
    /// queue behind session/presence traffic. Publish call sites migrate to
    /// this field incrementally.
    pub redis_events: redis::aio::ConnectionManager,
    /// S3 client built once at boot. `aws_sdk_s3::Client` wraps its
    /// connection pool in Arcs, so the clone in `AppState` reuses the same
    /// TCP pool instead of dialing per request.
    pub s3: aws_sdk_s3::Client,
    pub config: Config,
}

pub async fn connect_pool(
    database_url: &str,
    max_connections: u32,
) -> Result<sqlx::PgPool, sqlx::Error> {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(max_connections)
        // A couple of warm connections so a quiet period doesn't force a
        // fresh dial+auth on the next burst.
        .min_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .max_lifetime(std::time::Duration::from_secs(30 * 60))
        .connect(database_url)
        .await
}

/// Initial schema. Names and types are the cross-agent contract — apply
/// verbatim; after it ships, changes come only as new appended migrations.
const MIGRATION_1: &str = r#"
CREATE TABLE accounts(id BIGSERIAL PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, identity_key TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE registration_invites(code TEXT PRIMARY KEY, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), used_by BIGINT REFERENCES accounts(id), used_at TIMESTAMPTZ);
CREATE TABLE one_time_keys(account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, key_id TEXT NOT NULL, pubkey TEXT NOT NULL, PRIMARY KEY(account_id, key_id));
CREATE TABLE friends(a BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, b BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, since TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY(a,b), CHECK(a<b));
CREATE TABLE friend_requests(from_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, to_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY(from_id,to_id));
CREATE TABLE guilds(id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, owner_id BIGINT NOT NULL REFERENCES accounts(id), created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE guild_members(guild_id BIGINT NOT NULL REFERENCES guilds(id) ON DELETE CASCADE, account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, joined_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY(guild_id, account_id));
CREATE TABLE guild_invites(code TEXT PRIMARY KEY, guild_id BIGINT NOT NULL REFERENCES guilds(id) ON DELETE CASCADE, created_by BIGINT NOT NULL REFERENCES accounts(id), max_uses INT, uses INT NOT NULL DEFAULT 0, expires_at TIMESTAMPTZ);
CREATE TABLE channels(id BIGSERIAL PRIMARY KEY, guild_id BIGINT REFERENCES guilds(id) ON DELETE CASCADE, kind TEXT NOT NULL CHECK(kind IN ('text','voice')), name TEXT NOT NULL);
CREATE TABLE dm_channels(channel_id BIGINT PRIMARY KEY REFERENCES channels(id) ON DELETE CASCADE, a BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, b BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, UNIQUE(a,b), CHECK(a<b));
CREATE TABLE messages(id BIGSERIAL PRIMARY KEY, channel_id BIGINT NOT NULL REFERENCES channels(id) ON DELETE CASCADE, sender_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, kind TEXT NOT NULL CHECK(kind IN ('chat','control')), content TEXT NOT NULL, reply_to BIGINT REFERENCES messages(id) ON DELETE SET NULL, attachment_id BIGINT, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE INDEX idx_messages_channel ON messages(channel_id, id DESC);
CREATE TABLE attachments(id BIGSERIAL PRIMARY KEY, uploader_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, name TEXT NOT NULL, size BIGINT NOT NULL, nonce TEXT NOT NULL, s3_key TEXT NOT NULL UNIQUE, message_id BIGINT REFERENCES messages(id) ON DELETE SET NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE mailbox(id BIGSERIAL PRIMARY KEY, recipient_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, sender_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, content TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE INDEX idx_mailbox_recipient ON mailbox(recipient_id);
CREATE TABLE voice_participants(channel_id BIGINT NOT NULL REFERENCES channels(id) ON DELETE CASCADE, account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, joined_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY(channel_id, account_id));
"#;

/// Migration 2: image attachments (`POST /attachments/image`). Those bytes
/// are stored unencrypted — the Instance itself PUT them after validating
/// the WebP magic — so `encrypted` distinguishes them from the ciphertext
/// every earlier row holds. `DEFAULT TRUE` backfills existing rows for
/// free; no data rewrite needed.
const MIGRATION_2: &str = r#"
ALTER TABLE attachments ADD COLUMN encrypted BOOLEAN NOT NULL DEFAULT TRUE;
"#;

/// Migration 3: secondary indexes for the hot lookups the existing keys
/// don't cover. Each column below is the non-leading column of its table's
/// (composite) primary/unique key, so queries filtering on it alone —
/// "which guilds is this account in", "list channel X's attachments'
/// messages", "show my pending friend requests", "which voice rooms am I
/// in", "find the attachments a deleted message claimed" — planned a full
/// scan. `IF NOT EXISTS` keeps each statement safe to re-run outside the
/// schema_migrations guard.
const MIGRATION_3: &str = r#"
CREATE INDEX IF NOT EXISTS idx_guild_members_account ON guild_members(account_id);
CREATE INDEX IF NOT EXISTS idx_channels_guild ON channels(guild_id);
CREATE INDEX IF NOT EXISTS idx_friends_b ON friends(b);
CREATE INDEX IF NOT EXISTS idx_dm_channels_b ON dm_channels(b);
CREATE INDEX IF NOT EXISTS idx_friend_requests_to ON friend_requests(to_id);
CREATE INDEX IF NOT EXISTS idx_attachments_message ON attachments(message_id);
CREATE INDEX IF NOT EXISTS idx_voice_participants_account ON voice_participants(account_id);
"#;

/// Migration 4: `is_admin` flag on accounts. The first account to register
/// (against the boot-minted first-registration token) is the Instance's
/// single admin; `DEFAULT FALSE` backfills every existing row as a normal
/// account, so upgrading an already-populated instance changes nothing.
const MIGRATION_4: &str = r#"
ALTER TABLE accounts ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT FALSE;
"#;

/// Every migration in application order: `(version, sql)`. Append-only —
/// never edit or reorder a shipped entry.
const MIGRATIONS: &[(i64, &str)] = &[
    (1, MIGRATION_1),
    (2, MIGRATION_2),
    (3, MIGRATION_3),
    (4, MIGRATION_4),
];

/// S1: apply all embedded migrations in order, guarded by schema_migrations.
///
/// Idempotent and safe on an empty database: the guard table is created with
/// `IF NOT EXISTS`, and each migration runs at most once, each inside its
/// own transaction together with its version bookkeeping row.
pub async fn migrate(pool: &sqlx::PgPool) -> anyhow::Result<()> {
    // Existence check instead of `CREATE TABLE IF NOT EXISTS` so repeat
    // boots don't log Postgres' "already exists, skipping" NOTICE.
    let guarded: bool = sqlx::query_scalar("SELECT to_regclass('schema_migrations') IS NOT NULL")
        .fetch_one(pool)
        .await?;
    if !guarded {
        sqlx::raw_sql(
            "CREATE TABLE schema_migrations(
                 version INT PRIMARY KEY,
                 applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
             )",
        )
        .execute(pool)
        .await?;
    }

    for &(version, sql) in MIGRATIONS {
        let already_applied: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)")
                .bind(version)
                .fetch_one(pool)
                .await?;
        if already_applied {
            continue;
        }
        let mut tx = pool.begin().await?;
        // raw_sql: the DDL is a multi-statement batch, which prepared
        // statements refuse — this uses the simple protocol instead.
        sqlx::raw_sql(sql).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO schema_migrations(version) VALUES ($1)")
            .bind(version)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        tracing::info!(version, "applied database migration");
    }
    Ok(())
}

/// On a fresh database (no accounts yet), mint the single first-registration
/// token and print it. The operator hands it to whoever should become the
/// admin; redeeming it via `POST /auth/register` makes that account the admin
/// (first registrant wins, see `auth::register`). Never reprints once any
/// account exists — an already-bootstrapped instance is left alone.
pub async fn bootstrap(state: &AppState) -> anyhow::Result<()> {
    let accounts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accounts")
        .fetch_one(&state.pg)
        .await?;
    if accounts > 0 {
        return Ok(());
    }

    let code = new_invite_code();
    let mut tx = state.pg.begin().await?;
    sqlx::query("INSERT INTO registration_invites(code) VALUES ($1)")
        .bind(&code)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    // Bare line on stdout so the operator can copy it straight out of
    // `docker compose logs` without scrubbing prose; the tracing line is
    // for structured logs / log shippers.
    println!("first-registration token (sign up with it to become the admin): {code}");
    tracing::info!("first-registration token: {code}");
    Ok(())
}

/// S1: `bysyc-server make-invite` — mint + print one registration invite code.
pub async fn make_invite(state: &AppState) -> anyhow::Result<()> {
    let code = new_invite_code();
    sqlx::query("INSERT INTO registration_invites(code) VALUES ($1)")
        .bind(&code)
        .execute(&state.pg)
        .await?;
    // Bare code on stdout so the operator can copy it without editing
    // logging prose out of the clipboard.
    println!("{code}");
    Ok(())
}

/// Fresh invite code: 22 chars from `[a-zA-Z0-9]` via the OS CSPRNG
/// (62^22 ≈ 2^131 — collision with an existing code is not a practical
/// concern).
pub(crate) fn new_invite_code() -> String {
    Alphanumeric.sample_string(&mut rand::rng(), 22)
}

#[cfg(test)]
mod tests {
    use super::new_invite_code;

    #[test]
    fn invite_codes_are_22_alphanumerics() {
        let code = new_invite_code();
        assert_eq!(code.len(), 22);
        assert!(code.chars().all(|c| c.is_ascii_alphanumeric()));
        assert_ne!(code, new_invite_code());
    }
}

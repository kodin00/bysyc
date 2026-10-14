//! AppState + boot glue (pool construction, migrations, admin bootstrap).
//! Pool/struct owned by the orchestrator; migrate/bootstrap/make_invite
//! bodies are owned by S1 and replace the no-op stubs below.

use crate::config::Config;
use crate::passwd;
use rand::distr::{Alphanumeric, SampleString};

#[derive(Clone)]
pub struct AppState {
    pub pg: sqlx::PgPool,
    pub redis: redis::aio::ConnectionManager,
    pub config: Config,
}

pub async fn connect_pool(database_url: &str) -> Result<sqlx::PgPool, sqlx::Error> {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(16)
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

/// Every migration in application order: `(version, sql)`. Append-only —
/// never edit or reorder a shipped entry.
const MIGRATIONS: &[(i64, &str)] = &[(1, MIGRATION_1)];

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

/// S1: when accounts is empty and ADMIN_USERNAME/ADMIN_PASSWORD are set,
/// create the admin account plus a registration invite printed to stdout.
///
/// No-op once any account exists; warns (and does nothing) when the table is
/// empty but the credentials are only partially configured.
pub async fn bootstrap_admin(state: &AppState) -> anyhow::Result<()> {
    let accounts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accounts")
        .fetch_one(&state.pg)
        .await?;
    if accounts > 0 {
        return Ok(());
    }

    let (username, password) = match (&state.config.admin_username, &state.config.admin_password) {
        (Some(u), Some(p)) => (u.as_str(), p.as_str()),
        _ => {
            tracing::warn!(
                "accounts table is empty but ADMIN_USERNAME/ADMIN_PASSWORD are not both set; \
                 no admin account was created"
            );
            return Ok(());
        }
    };

    let mut tx = state.pg.begin().await?;
    sqlx::query("INSERT INTO accounts(username, password_hash) VALUES ($1, $2)")
        .bind(username)
        .bind(passwd::hash_password(password))
        .execute(&mut *tx)
        .await?;
    let code = new_invite_code();
    sqlx::query("INSERT INTO registration_invites(code) VALUES ($1)")
        .bind(&code)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    tracing::info!("admin \"{username}\" created; registration invite code: {code}");
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
fn new_invite_code() -> String {
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

//! AppState + boot glue (pool construction, migrations, admin bootstrap).
//! Pool/struct owned by the orchestrator; migrate/bootstrap/make_invite
//! bodies are owned by S1 and replace the no-op stubs below.

use crate::config::Config;

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

/// S1: apply all embedded migrations in order, guarded by schema_migrations.
pub async fn migrate(_pool: &sqlx::PgPool) -> anyhow::Result<()> {
    Ok(())
}

/// S1: when accounts is empty and ADMIN_USERNAME/ADMIN_PASSWORD are set,
/// create the admin account plus a registration invite printed to stdout.
pub async fn bootstrap_admin(_state: &AppState) -> anyhow::Result<()> {
    Ok(())
}

/// S1: `bysyc-server make-invite` — mint + print one registration invite code.
pub async fn make_invite(_state: &AppState) -> anyhow::Result<()> {
    Ok(())
}

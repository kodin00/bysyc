//! Environment-driven configuration. Owned by the orchestrator.

#[derive(Clone, Debug)]
pub struct Config {
    pub database_url: String,
    pub redis_url: String,
    pub s3_endpoint: String,
    pub s3_access_key: String,
    pub s3_secret_key: String,
    pub s3_bucket: String,
    /// Public TURN address clients dial, e.g. "turn.example.com:3478".
    pub turn_addr: String,
    pub turn_user: String,
    pub turn_password: String,
    /// Ciphertext-size cap per attachment, from `ATTACHMENT_MAX_MB` (default 50).
    pub attachment_max_bytes: u64,
    /// Postgres pool ceiling, from `DB_MAX_CONNECTIONS` (default 16).
    pub db_max_connections: u32,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            // Production-critical: a missing/empty value means a broken
            // deployment, so crash at boot with a pointer to .env.example
            // rather than failing on first request with a cryptic error.
            database_url: require_env("DATABASE_URL"),
            redis_url: require_env("REDIS_URL"),
            s3_secret_key: require_env("S3_SECRET_KEY"),
            turn_password: require_env("TURN_PASSWORD"),
            // Tunables: safe local defaults, overridden in production .env.
            s3_endpoint: env("S3_ENDPOINT", "http://localhost:8333"),
            s3_access_key: env("S3_ACCESS_KEY", "bysyc"),
            s3_bucket: env("S3_BUCKET", "bysyc"),
            turn_addr: env("TURN_ADDR", "localhost:3478"),
            turn_user: env("TURN_USER", "bysyc"),
            attachment_max_bytes: env("ATTACHMENT_MAX_MB", "50").parse::<u64>().unwrap_or(50)
                * 1024
                * 1024,
            db_max_connections: env("DB_MAX_CONNECTIONS", "16").parse::<u32>().unwrap_or(16),
        }
    }
}

fn env(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Read a required env var, panicking at boot (not first use) when it is
/// unset or empty. The message points operators at `.env.example` so a
/// misconfigured instance fails loudly and obviously.
fn require_env(key: &str) -> String {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => v,
        _ => panic!("{key} must be set (see .env.example)"),
    }
}

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
    /// First-boot admin account (created only when the accounts table is empty).
    pub admin_username: Option<String>,
    pub admin_password: Option<String>,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            database_url: env("DATABASE_URL", "postgres://bysyc:bysyc@localhost/bysyc"),
            redis_url: env("REDIS_URL", "redis://localhost/1"),
            s3_endpoint: env("S3_ENDPOINT", "http://localhost:8333"),
            s3_access_key: env("S3_ACCESS_KEY", "bysyc"),
            s3_secret_key: env("S3_SECRET_KEY", "bysyc"),
            s3_bucket: env("S3_BUCKET", "bysyc"),
            turn_addr: env("TURN_ADDR", "localhost:3478"),
            turn_user: env("TURN_USER", "bysyc"),
            turn_password: env("TURN_PASSWORD", "bysyc"),
            admin_username: std::env::var("ADMIN_USERNAME")
                .ok()
                .filter(|s| !s.is_empty()),
            admin_password: std::env::var("ADMIN_PASSWORD")
                .ok()
                .filter(|s| !s.is_empty()),
        }
    }
}

fn env(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

pub mod attachments;
pub mod auth;
pub mod config;
pub mod db;
pub mod error;
pub mod events;
pub mod friends;
pub mod guilds;
pub mod keys;
pub mod mailbox;
pub mod messages;
pub mod passwd;
pub mod rate_limit;
pub mod routes;
pub mod s3;
pub mod session;
pub mod voice;
pub mod ws;

pub use config::Config;
pub use db::{AppState, connect_pool, migrate, bootstrap, make_invite};
pub use routes::router;

pub async fn boot(config: &Config) -> anyhow::Result<db::AppState> {
    let pg = db::connect_pool(&config.database_url, config.db_max_connections).await?;
    db::migrate(&pg).await?;
    let redis_client = redis::Client::open(config.redis_url.as_str())?;
    let redis = redis::aio::ConnectionManager::new(redis_client.clone()).await?;
    // Not a clone of `redis` (a manager clone shares one connection): a
    // second manager so event publishes get their own pipe.
    let redis_events = redis::aio::ConnectionManager::new(redis_client).await?;
    let s3 = s3::client(config);
    Ok(AppState {
        pg,
        redis,
        redis_events,
        s3,
        config: config.clone(),
    })
}

mod attachments;
mod auth;
mod config;
mod db;
mod error;
mod friends;
mod guilds;
mod keys;
mod mailbox;
mod messages;
mod routes;
mod s3;
mod session;
mod voice;
mod ws;

use db::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let config = config::Config::from_env();

    // CLI: `bysyc-server make-invite` mints a registration invite and exits.
    if std::env::args().nth(1).as_deref() == Some("make-invite") {
        let state = boot(&config).await?;
        db::make_invite(&state).await?;
        return Ok(());
    }

    let state = boot(&config).await?;
    db::bootstrap_admin(&state).await?;
    let app = routes::router(state);

    let addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("bysyc-server listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn boot(config: &config::Config) -> anyhow::Result<AppState> {
    let pg = db::connect_pool(&config.database_url).await?;
    db::migrate(&pg).await?;
    let redis_client = redis::Client::open(config.redis_url.as_str())?;
    let redis = redis::aio::ConnectionManager::new(redis_client).await?;
    Ok(AppState { pg, redis, config: config.clone() })
}

mod attachments;
mod auth;
mod config;
mod db;
mod error;
mod events;
mod friends;
mod guilds;
mod keys;
mod mailbox;
mod messages;
mod passwd;
mod rate_limit;
mod routes;
mod s3;
mod session;
mod voice;
mod ws;

use db::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive("info".parse()?),
        )
        .init();

    let config = config::Config::from_env();

    // CLI: `bysyc-server make-invite` mints a registration invite and exits.
    if std::env::args().nth(1).as_deref() == Some("make-invite") {
        let state = boot(&config).await?;
        db::make_invite(&state).await?;
        return Ok(());
    }

    let state = boot(&config).await?;
    db::bootstrap(&state).await?;
    // Shared gateway subscribers: a fixed pool of Redis pub/sub connections
    // total, no matter how many WebSocket connections are live.
    let workers = ws_event_workers();
    ws::start_event_bus(&config.redis_url, workers);
    tracing::info!("gateway event bus online ({workers} shared redis subscribers)");
    let app = routes::router(state);

    let addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let listener = tokio::net::TcpListener::bind(&addr).await.map_err(|e| {
        anyhow::anyhow!(
            "{e} — binding {addr}: another server or docker container holds the port \
             (check `docker ps`); change BIND_ADDR in .env to pick another one"
        )
    })?;
    tracing::info!("bysyc-server listening on {addr}");
    // into_make_service_with_connect_info injects the peer's SocketAddr into
    // request extensions, so the auth rate-limiter (rate_limit.rs) can key on
    // the real client IP even without a reverse proxy setting X-Forwarded-For.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}

/// Gateway shared-subscriber worker count, from `WS_EVENT_WORKERS`
/// (default 4, clamped 1..=8). Connections are homed round-robin to a
/// worker; each worker holds exactly one Redis pub/sub connection carrying
/// the union of its homed connections' event topics.
fn ws_event_workers() -> usize {
    std::env::var("WS_EVENT_WORKERS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(4)
        .clamp(1, 8)
}

async fn boot(config: &config::Config) -> anyhow::Result<AppState> {
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

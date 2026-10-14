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
mod voice;
mod ws;

#[tokio::main]
async fn main() {
    let app = routes::router();

    let addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("cannot bind {addr}: {e}"));

    println!("bysyc-server listening on {addr}");
    axum::serve(listener, app).await.unwrap();
}

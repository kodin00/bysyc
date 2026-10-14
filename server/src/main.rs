use axum::{routing::get, Router};

#[tokio::main]
async fn main() {
    let app = Router::new().route("/healthz", get(|| async { "ok" }));

    let addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("cannot bind {addr}: {e}"));

    println!("bysyc-server listening on {addr}");
    axum::serve(listener, app).await.unwrap();
}

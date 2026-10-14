//! WebSocket gateway (auth, Redis fan-out, presence) — owned by S4

pub fn router() -> axum::Router {
    axum::Router::new()
}

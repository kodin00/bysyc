//! Directed encrypted control-message delivery — owned by S4.

pub fn router() -> axum::Router<crate::db::AppState> {
    axum::Router::new()
}

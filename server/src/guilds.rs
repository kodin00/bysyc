//! Module router. Owner agent fills this file.

pub fn router() -> axum::Router<crate::db::AppState> {
    axum::Router::new()
}

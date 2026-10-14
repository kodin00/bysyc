//! Composition root: merges every module's router. Owned by S1 (foundation);
//! new endpoints are registered inside their own module files, not here.

pub fn router() -> axum::Router {
    axum::Router::new()
        .merge(crate::auth::router())
        .merge(crate::friends::router())
        .merge(crate::keys::router())
        .merge(crate::guilds::router())
        .merge(crate::attachments::router())
        .route("/healthz", axum::routing::get(|| async { "ok" }))
}

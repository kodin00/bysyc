//! Composition root: merges every module's router into one stateful router.
//! Owned by the orchestrator; new endpoints are registered inside their own
//! module files, not here.

use crate::db::AppState;

pub fn router(state: AppState) -> axum::Router {
    axum::Router::new()
        .merge(crate::auth::router())
        .merge(crate::friends::router())
        .merge(crate::keys::router())
        .merge(crate::guilds::router())
        .merge(crate::attachments::router())
        .merge(crate::voice::router())
        .merge(crate::ws::router())
        .route("/healthz", axum::routing::get(|| async { "ok" }))
        .with_state(state)
}

//! Composition root: merges every module's router into one stateful router.
//! Owned by the orchestrator; new endpoints are registered inside their own
//! module files, not here.

use crate::db::AppState;

pub fn router(state: AppState) -> axum::Router {
    // axum caps request bodies at 2 MB by default, which silently rejects
    // the configured attachment ceiling (ATTACHMENT_MAX_MB) before the
    // handler runs. Raise the cap only on the attachments router — every
    // other endpoint keeps the small default.
    let attachment_body_limit =
        axum::extract::DefaultBodyLimit::max(state.config.attachment_max_bytes as usize);
    axum::Router::new()
        .merge(crate::auth::router())
        .merge(crate::friends::router())
        .merge(crate::keys::router())
        .merge(crate::guilds::router())
        .merge(crate::attachments::router().layer(attachment_body_limit))
        .merge(crate::messages::router())
        .merge(crate::mailbox::router())
        .merge(crate::voice::router())
        .merge(crate::ws::router())
        .route("/healthz", axum::routing::get(|| async { "ok" }))
        .with_state(state)
}

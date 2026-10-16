//! Composition root: merges every module's router into one stateful router.
//! Owned by the orchestrator; new endpoints are registered inside their own
//! module files, not here.

use std::sync::Arc;

use crate::db::AppState;
use crate::rate_limit::RateLimiter;

pub fn router(state: AppState) -> axum::Router {
    // axum caps request bodies at 2 MB by default, which silently rejects
    // the configured attachment ceiling (ATTACHMENT_MAX_MB) before the
    // handler runs. Raise the cap only on the attachments router — every
    // other endpoint keeps the small default.
    let attachment_body_limit =
        axum::extract::DefaultBodyLimit::max(state.config.attachment_max_bytes as usize);
    // Per-IP auth rate limit: AUTH_RATE_PER_MIN (default 5) hits/min/IP.
    let rate_per_min = std::env::var("AUTH_RATE_PER_MIN")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(5);
    let rate_limiter = Arc::new(RateLimiter::new(rate_per_min));
    axum::Router::new()
        .merge(crate::auth::router(rate_limiter))
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

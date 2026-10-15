//! Directed encrypted control-message delivery — owned by S4.
//!
//! The mailbox queues 1:1 ciphertext control items (typically Olm messages
//! carrying Megolm session keys — ADR 0001's sender-key bootstrap) for an
//! account that may be offline. Items are delivered as
//! [`WsServerBody::MailboxAppend`] pushes while the recipient is connected
//! and re-drained in the [`WsServerBody::Ready`] snapshot on reconnect;
//! they are deleted only when the client acknowledges them
//! (`WsClientBody::AckMailbox`, handled by the gateway).
//!
//! Delivery deliberately has NO friendship requirement: it targets any
//! existing account. DMs are friends-only, but Olm prekey bootstrap may
//! legitimately reach accounts that are not (yet) Friends.
//!
//! # Schema assumptions (S1 owns migrations)
//!
//! - `accounts(id, ...)`
//! - `mailbox(id, recipient_id, sender_id, content, created_at BIGINT
//!   epoch-ms)`

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use sqlx::Row;

use bysyc_common::protocol::{MailboxItem, WsServerBody};

use crate::db::AppState;
use crate::error::{ApiError, ApiResult};
use crate::messages::check_ciphertext;
use crate::session::Authed;

pub fn router() -> axum::Router<AppState> {
    axum::Router::new().route("/mailbox", post(post_mailbox))
}

#[derive(serde::Deserialize)]
struct MailboxSendRequest {
    to: i64,
    content: String,
}

/// Queue one directed ciphertext item for `recipient_id` and push it to
/// their live connections. Used by the REST route below and available to
/// sibling modules (e.g. key management) that need directed delivery.
///
/// `content` is taken by value so one buffer serves both the row (written
/// under a borrow) and the pushed [`MailboxItem`] (moved in) — no copy in
/// between. A recipient that does not reference an existing account
/// surfaces as the insert's foreign-key violation (23503), mapped here to
/// the same 404 the old existence probe produced; the sender FK cannot
/// fire, since `sender_id` is the authenticated caller.
///
/// The row is committed before the push: if Redis fan-out fails the item
/// still arrives in the recipient's next `Ready` drain, so a publish error
/// is logged, not propagated.
pub async fn deliver(
    state: &AppState,
    recipient_id: i64,
    sender_id: i64,
    content: String,
) -> ApiResult<()> {
    let row = match sqlx::query(
        "INSERT INTO mailbox (recipient_id, sender_id, content) \
         VALUES ($1, $2, $3) \
         RETURNING id, (EXTRACT(EPOCH FROM created_at) * 1000)::bigint AS created_at_ms",
    )
    .bind(recipient_id)
    .bind(sender_id)
    .bind(content.as_str())
    .fetch_one(&state.pg)
    .await
    {
        Ok(row) => row,
        Err(sqlx::Error::Database(db)) if db.code().as_deref() == Some("23503") => {
            return Err(ApiError::not_found("recipient not found"));
        }
        Err(e) => return Err(e.into()),
    };

    let item = MailboxItem {
        id: row.try_get("id")?,
        sender_id,
        content,
        created_at_ms: row.try_get("created_at_ms")?,
    };

    if let Err(e) = crate::events::publish_to_account(
        &state.redis_events,
        recipient_id,
        WsServerBody::MailboxAppend(item),
    )
    .await
    {
        tracing::warn!(recipient_id, "mailbox item stored but push failed: {e}");
    }
    Ok(())
}

/// POST /mailbox — send one directed ciphertext control item. `204` on
/// acceptance. `to` must reference an existing account (the insert's
/// foreign-key check answers 404); no friendship requirement, see the
/// module docs.
async fn post_mailbox(
    State(state): State<AppState>,
    auth: Authed,
    body: Bytes,
) -> ApiResult<StatusCode> {
    let me = auth.0;
    let req: MailboxSendRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::invalid(format!("malformed request body: {e}")))?;
    check_ciphertext(&req.content)?;

    deliver(&state, req.to, me, req.content).await?;
    Ok(StatusCode::NO_CONTENT)
}

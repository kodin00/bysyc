//! Channel message send/fetch/delete — owned by S4.
//!
//! Message `content` is base64 ciphertext and opaque to the Instance
//! (ADR 0001): we validate only its encoded shape and size, store it
//! verbatim, and fan it out. The sender receives the created
//! [`MessageDto`] as the HTTP response; it is deliberately NOT echoed
//! back over the gateway — only other subscribers of `chan:{id}` receive
//! the published copy. Deletion (`DELETE /channels/{id}/messages/{mid}`,
//! senders may remove only their own) drops the row plus any attachment
//! row/object owned by it, then fans a [`WsServerBody::MessageDeleted`]
//! out to the same `chan:{id}` subscribers — the deleter included, since
//! the `204` response carries no body.
//!
//! # Schema (S1's migration, landed; attachments.encrypted via migration 2)
//!
//! - `channels(id, guild_id NULL, kind 'text'|'voice', name)` — DM
//!   channels are rows with `guild_id IS NULL` paired in `dm_channels`;
//!   the wire always reports them as [`ChannelKind::Dm`]
//! - `dm_channels(channel_id, a, b)`, `guild_members(guild_id, account_id)`
//! - `messages(id, channel_id, sender_id, kind 'chat'|'control', content,
//!   reply_to NULL, attachment_id NULL, created_at TIMESTAMPTZ)` — this
//!   sqlx build has no chrono feature, so timestamps are read through
//!   `EXTRACT(EPOCH ...)::bigint` conversions and written only by the
//!   column's `now()` default
//! - `attachments(id, uploader_id, name, size, nonce, s3_key,
//!   message_id NULL, encrypted)` — `encrypted` is FALSE only for
//!   server-stored WebP images (see `attachments.rs`); every row that
//!   predates the column reads as TRUE via its default

use std::collections::HashMap;

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{delete, get};
use base64::Engine as _;
use bysyc_common::protocol::{
    AttachmentMeta, ChannelKind, MessageDto, MessageKind, MessagePage, SendMessageRequest,
    WsServerBody,
};
use sqlx::{PgPool, Row};

use crate::db::AppState;
use crate::error::{ApiError, ApiResult};
use crate::s3;
use crate::session::Authed;

/// Maximum plaintext-ciphertext the Instance will carry: 64 KiB decoded
/// (a 64 KiB base64 string is at most ~87k chars, so the raw-length guard
/// below is the looser pre-filter).
const MAX_CIPHERTEXT_BYTES: usize = 64 * 1024;
/// Raw string-length ceiling that comfortably admits any 64 KiB base64
/// payload while keeping pathological inputs out before decoding.
const MAX_CIPHERTEXT_CHARS: usize = 90_000;

pub fn router() -> axum::Router<AppState> {
    axum::Router::new()
        .route(
            "/channels/{id}/messages",
            get(page_messages).post(send_message),
        )
        .route(
            "/channels/{id}/messages/{message_id}",
            delete(delete_message),
        )
}

/// Validate that `content` is base64 ciphertext of at most 64 KiB decoded
/// (ADR 0001: content is opaque — shape and size are all the Instance
/// checks). Accepts standard (padded or unpadded — vodozemac's Megolm
/// `to_base64` emits unpadded standard) and URL-safe/no-pad encodings;
/// anything else is rejected as [`ErrorCode::InvalidRequest`].
pub(crate) fn check_ciphertext(content: &str) -> Result<(), ApiError> {
    if content.len() > MAX_CIPHERTEXT_CHARS {
        return Err(ApiError::invalid("content exceeds 64 KiB of ciphertext"));
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(content.as_bytes())
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(content.as_bytes()))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(content.as_bytes()))
        .map_err(|_| ApiError::invalid("content must be base64 ciphertext"))?;
    if decoded.len() > MAX_CIPHERTEXT_BYTES {
        return Err(ApiError::invalid("content exceeds 64 KiB of ciphertext"));
    }
    Ok(())
}

/// Whether `me` can read `channel_id`: member of the owning guild, or a
/// participant in the DM. Nonexistent channels read as false.
pub(crate) async fn can_read(pg: &PgPool, me: i64, channel_id: i64) -> sqlx::Result<bool> {
    let ok = sqlx::query_scalar::<_, i64>(
        "SELECT 1::bigint \
         FROM channels c \
         LEFT JOIN dm_channels dc ON dc.channel_id = c.id \
         WHERE c.id = $1 \
           AND (EXISTS (SELECT 1 FROM guild_members gm \
                        WHERE gm.guild_id = c.guild_id AND gm.account_id = $2) \
                OR dc.a = $2 OR dc.b = $2)",
    )
    .bind(channel_id)
    .bind(me)
    .fetch_optional(pg)
    .await?;
    Ok(ok.is_some())
}

/// `MessageKind` <-> its `messages.kind` column spelling.
pub(crate) fn message_kind_str(kind: MessageKind) -> &'static str {
    match kind {
        MessageKind::Chat => "chat",
        MessageKind::Control => "control",
    }
}

pub(crate) fn parse_message_kind(s: &str) -> Option<MessageKind> {
    match s {
        "chat" => Some(MessageKind::Chat),
        "control" => Some(MessageKind::Control),
        _ => None,
    }
}

pub(crate) fn parse_channel_kind(s: &str) -> Option<ChannelKind> {
    match s {
        "text" => Some(ChannelKind::Text),
        "voice" => Some(ChannelKind::Voice),
        "dm" => Some(ChannelKind::Dm),
        _ => None,
    }
}

/// POST /channels/{id}/messages — store one ciphertext envelope and fan it
/// out to the channel. The response body is the created [`MessageDto`] and
/// the sender does NOT additionally receive it over the gateway.
async fn send_message(
    State(state): State<AppState>,
    auth: Authed,
    Path(channel_id): Path<i64>,
    body: Bytes,
) -> ApiResult<Json<MessageDto>> {
    let me = auth.0;
    let req: SendMessageRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::invalid(format!("malformed request body: {e}")))?;
    check_ciphertext(&req.content)?;

    if !can_read(&state.pg, me, channel_id).await? {
        return Err(ApiError::forbidden("not a member of this channel"));
    }

    if let Some(reply_to) = req.reply_to {
        let target = sqlx::query_scalar::<_, i64>(
            "SELECT 1::bigint FROM messages WHERE id = $1 AND channel_id = $2",
        )
        .bind(reply_to)
        .bind(channel_id)
        .fetch_optional(&state.pg)
        .await?;
        if target.is_none() {
            return Err(ApiError::invalid(
                "reply_to does not reference a message in this channel",
            ));
        }
    }

    // Attachment claim + insert run in one transaction: the UPDATE's
    // `message_id IS NULL` guard makes the claim atomic even without the
    // pre-SELECT (two concurrent sends cannot both win).
    let mut tx = state.pg.begin().await?;

    let attachment_meta = match req.attachment_id {
        Some(att_id) => {
            let row = sqlx::query(
                "SELECT id, name, size, nonce, encrypted FROM attachments \
                 WHERE id = $1 AND uploader_id = $2 AND message_id IS NULL",
            )
            .bind(att_id)
            .bind(me)
            .fetch_optional(&mut *tx)
            .await?;
            match row {
                Some(r) => Some(AttachmentMeta {
                    id: r.try_get("id")?,
                    name: r.try_get("name")?,
                    size: r.try_get("size")?,
                    nonce: r.try_get("nonce")?,
                    encrypted: r.try_get("encrypted")?,
                }),
                None => {
                    return Err(ApiError::invalid(
                        "attachment not found, not uploaded by you, or already attached",
                    ));
                }
            }
        }
        None => None,
    };

    let row = sqlx::query(
        "INSERT INTO messages \
             (channel_id, sender_id, kind, content, reply_to, attachment_id) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         RETURNING id, (EXTRACT(EPOCH FROM created_at) * 1000)::bigint AS created_at_ms",
    )
    .bind(channel_id)
    .bind(me)
    .bind(message_kind_str(req.kind.clone()))
    .bind(&req.content)
    .bind(req.reply_to)
    .bind(req.attachment_id)
    .fetch_one(&mut *tx)
    .await?;
    let message_id: i64 = row.try_get("id")?;
    let created_at_ms: i64 = row.try_get("created_at_ms")?;

    if let (Some(att_id), Some(_)) = (req.attachment_id, attachment_meta.as_ref()) {
        let claimed = sqlx::query(
            "UPDATE attachments SET message_id = $1 \
             WHERE id = $2 AND uploader_id = $3 AND message_id IS NULL",
        )
        .bind(message_id)
        .bind(att_id)
        .bind(me)
        .execute(&mut *tx)
        .await?;
        if claimed.rows_affected() == 0 {
            // Concurrently claimed by another message; roll back our insert.
            return Err(ApiError::invalid("attachment was already attached"));
        }
    }

    tx.commit().await?;

    let dto = MessageDto {
        id: message_id,
        channel_id,
        sender_id: me,
        kind: req.kind,
        content: req.content,
        reply_to: req.reply_to,
        attachment: attachment_meta,
        created_at_ms,
    };

    // The message is durably stored; fan-out is best-effort. Clients
    // backfill gaps through the history endpoint.
    if let Err(e) = crate::events::publish_to_channel(
        &state.redis,
        channel_id,
        &WsServerBody::Message(dto.clone()),
    )
    .await
    {
        tracing::warn!(
            channel_id,
            message_id,
            "message stored but fan-out failed: {e}"
        );
    }

    Ok(Json(dto))
}

/// GET /channels/{id}/messages?before=<id>&limit=<1..100> — one page of
/// channel history, oldest-first. Control messages are included; clients
/// filter them.
async fn page_messages(
    State(state): State<AppState>,
    auth: Authed,
    Path(channel_id): Path<i64>,
    Query(params): Query<HashMap<String, String>>,
) -> ApiResult<Json<MessagePage>> {
    let me = auth.0;

    let before: Option<i64> = match params.get("before") {
        None => None,
        Some(raw) => Some(
            raw.parse()
                .map_err(|_| ApiError::invalid("before must be a message id"))?,
        ),
    };
    let limit: i64 = match params.get("limit") {
        None => 50,
        Some(raw) => raw
            .parse::<i64>()
            .map_err(|_| ApiError::invalid("limit must be an integer"))?
            .clamp(1, 100),
    };

    if !can_read(&state.pg, me, channel_id).await? {
        return Err(ApiError::forbidden("not a member of this channel"));
    }

    let rows = sqlx::query(
        "SELECT m.id, m.sender_id, m.kind, m.content, m.reply_to, \
                (EXTRACT(EPOCH FROM m.created_at) * 1000)::bigint AS created_at_ms, \
                a.id AS att_id, a.name AS att_name, a.size AS att_size, \
                a.nonce AS att_nonce, a.encrypted AS att_encrypted \
         FROM messages m \
         LEFT JOIN attachments a ON a.id = m.attachment_id \
         WHERE m.channel_id = $1 AND ($2::bigint IS NULL OR m.id < $2) \
         ORDER BY m.id DESC \
         LIMIT $3",
    )
    .bind(channel_id)
    .bind(before)
    .bind(limit + 1) // fetch one extra row to detect the older page
    .fetch_all(&state.pg)
    .await?;

    let has_more = rows.len() as i64 > limit;
    let mut messages = Vec::with_capacity(rows.len().min(limit as usize));
    for row in rows.iter().take(limit as usize) {
        let kind = parse_message_kind(&row.try_get::<String, _>("kind")?)
            .ok_or_else(|| ApiError::internal("corrupt message kind in database"))?;
        let attachment = match row.try_get::<Option<i64>, _>("att_id")? {
            Some(_) => Some(AttachmentMeta {
                id: row.try_get("att_id")?,
                name: row.try_get("att_name")?,
                size: row.try_get("att_size")?,
                nonce: row.try_get("att_nonce")?,
                encrypted: row.try_get("att_encrypted")?,
            }),
            None => None,
        };
        messages.push(MessageDto {
            id: row.try_get("id")?,
            channel_id,
            sender_id: row.try_get("sender_id")?,
            kind,
            content: row.try_get("content")?,
            reply_to: row.try_get("reply_to")?,
            attachment,
            created_at_ms: row.try_get("created_at_ms")?,
        });
    }
    // Fetched newest-first for the LIMIT cut; the contract is oldest-first.
    messages.reverse();

    Ok(Json(MessagePage { messages, has_more }))
}

/// DELETE /channels/{id}/messages/{message_id} — remove one of the
/// caller's own messages (chat or control alike; anyone else's yields
/// [`ErrorCode::Forbidden`]). A message with an attached file takes its
/// attachments row and — best-effort — the stored object with it. Every
/// subscriber of the channel, the deleter included, is pushed
/// [`WsServerBody::MessageDeleted`]; history paging stops returning the
/// message immediately.
async fn delete_message(
    State(state): State<AppState>,
    auth: Authed,
    Path((channel_id, message_id)): Path<(i64, i64)>,
) -> ApiResult<StatusCode> {
    let me = auth.0;

    let row = sqlx::query("SELECT sender_id FROM messages WHERE id = $1 AND channel_id = $2")
        .bind(message_id)
        .bind(channel_id)
        .fetch_optional(&state.pg)
        .await?;
    match row {
        Some(r) if r.try_get::<i64, _>("sender_id")? == me => {}
        Some(_) => return Err(ApiError::forbidden("only the sender can delete a message")),
        None => return Err(ApiError::not_found("no such message")),
    }

    // Grab the object key before deleting: `attachments.message_id` is
    // ON DELETE SET NULL, so after the message row is gone the row can no
    // longer be found by message_id.
    let s3_key: Option<String> =
        sqlx::query_scalar("SELECT s3_key FROM attachments WHERE message_id = $1")
            .bind(message_id)
            .fetch_optional(&state.pg)
            .await?;

    // Attachment row first, then the message: deleting the message first
    // would null out `attachments.message_id` before the row is matched.
    let mut tx = state.pg.begin().await?;
    sqlx::query("DELETE FROM attachments WHERE message_id = $1")
        .bind(message_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM messages WHERE id = $1")
        .bind(message_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    // The row is gone from the source of truth; object removal is
    // best-effort (an orphaned object sits behind an unguessable key) and
    // must not fail the already-committed delete.
    if let Some(key) = s3_key.as_deref() {
        if let Err(e) = s3::delete_object(&state, key).await {
            tracing::warn!(
                message_id,
                key,
                "message deleted but object removal failed: {}",
                e.message
            );
        }
    }

    // Same best-effort fan-out contract as send; a client that misses the
    // push reconciles on its next history page.
    if let Err(e) = crate::events::publish_to_channel(
        &state.redis,
        channel_id,
        &WsServerBody::MessageDeleted {
            channel_id,
            message_id,
        },
    )
    .await
    {
        tracing::warn!(
            channel_id,
            message_id,
            "message deleted but fan-out failed: {e}"
        );
    }

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ciphertext_size_limits() {
        assert!(check_ciphertext("").is_ok());
        assert!(check_ciphertext("aGVsbG8=").is_ok());
        assert!(check_ciphertext("aGVsbG8").is_ok()); // url-safe no-pad fallback
        // Unpadded standard alphabet (contains + and /): what vodozemac's
        // MegolmMessage::to_base64 emits. Rejected by padded-STANDARD and
        // URL_SAFE alike.
        assert!(check_ciphertext("+/+/AA").is_ok());
        // 90_001 chars of valid base64 -> rejected on raw length.
        let too_long = "A".repeat(90_001);
        assert!(check_ciphertext(&too_long).is_err());
        // Not base64 at all.
        assert!(check_ciphertext("not base64!!").is_err());
        // Valid base64 decoding to > 64 KiB.
        let big = base64::engine::general_purpose::STANDARD.encode(vec![0u8; 64 * 1024 + 1]);
        assert!(
            big.len() < 90_000,
            "fixture should pass the raw-length guard"
        );
        assert!(check_ciphertext(&big).is_err());
        let ok_big = base64::engine::general_purpose::STANDARD.encode(vec![0u8; 64 * 1024]);
        assert!(check_ciphertext(&ok_big).is_ok());
    }

    #[test]
    fn kind_strings_round_trip() {
        for k in [MessageKind::Chat, MessageKind::Control] {
            let s = message_kind_str(k.clone());
            assert_eq!(parse_message_kind(s), Some(k));
        }
        assert_eq!(parse_message_kind("bogus"), None);
        for k in [ChannelKind::Text, ChannelKind::Voice, ChannelKind::Dm] {
            let s = match k {
                ChannelKind::Text => "text",
                ChannelKind::Voice => "voice",
                ChannelKind::Dm => "dm",
            };
            assert_eq!(parse_channel_kind(s), Some(k));
        }
        assert_eq!(parse_channel_kind("bogus"), None);
    }
}

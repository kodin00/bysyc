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
use sqlx::{AssertSqlSafe, PgPool, Row};

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

/// Channel-membership predicate shared by [`can_read`] and the send path's
/// check and write queries: account `$2` may act on channel `$1` when it is
/// a member of the owning guild or a participant in the DM. Nonexistent
/// channels read false. Queries embedding it are wrapped in
/// [`AssertSqlSafe`]: the interpolation is this compile-time constant, so
/// nothing user-controlled ever reaches the SQL text.
const MEMBER_OF: &str = "EXISTS (SELECT 1 FROM channels c \
     LEFT JOIN dm_channels dc ON dc.channel_id = c.id \
     WHERE c.id = $1 \
       AND (EXISTS (SELECT 1 FROM guild_members gm \
                    WHERE gm.guild_id = c.guild_id AND gm.account_id = $2) \
            OR dc.a = $2 OR dc.b = $2))";

/// Whether `me` can read `channel_id`: member of the owning guild, or a
/// participant in the DM. Nonexistent channels read as false.
pub(crate) async fn can_read(pg: &PgPool, me: i64, channel_id: i64) -> sqlx::Result<bool> {
    sqlx::query_scalar::<_, bool>(AssertSqlSafe(format!("SELECT {MEMBER_OF}")))
        .bind(channel_id)
        .bind(me)
        .fetch_one(pg)
        .await
}

/// `MessageKind` <-> its `messages.kind` column spelling.
pub(crate) fn message_kind_str(kind: MessageKind) -> &'static str {
    match kind {
        MessageKind::Chat => "chat",
        MessageKind::Control => "control",
        // `MessageKind` is `#[non_exhaustive]`; Unknown (a `#[serde(other)]`
        // fallback from a newer peer) or any future variant never reaches here
        // — `send_message` rejects non-Chat/Control before calling this.
        _ => "chat",
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
    // `MessageKind` is `#[non_exhaustive]` with a `#[serde(other)]` Unknown
    // fallback; the DB's `messages.kind` CHECK only allows 'chat'|'control',
    // so anything else is rejected up front rather than turned into a
    // CHECK-violation 500.
    if !matches!(req.kind, MessageKind::Chat | MessageKind::Control) {
        return Err(ApiError::invalid("unknown message kind"));
    }

    // Both preconditions in one round trip: channel membership, and — only
    // when the request is a reply — that the target lives in this channel.
    let checks = sqlx::query(AssertSqlSafe(format!(
        "SELECT {MEMBER_OF} AS member, \
         ($3::bigint IS NULL \
          OR EXISTS (SELECT 1 FROM messages WHERE id = $3 AND channel_id = $1)) AS reply_ok"
    )))
    .bind(channel_id)
    .bind(me)
    .bind(req.reply_to)
    .fetch_one(&state.pg)
    .await?;
    if !checks.try_get::<bool, _>("member")? {
        return Err(ApiError::forbidden("not a member of this channel"));
    }
    if !checks.try_get::<bool, _>("reply_ok")? {
        return Err(ApiError::invalid(
            "reply_to does not reference a message in this channel",
        ));
    }

    // One write round trip on either path; no explicit transaction, since
    // every precondition the old BEGIN..COMMIT guarded now rides inside
    // the statement itself.
    let (message_id, created_at_ms, attachment_meta) = match req.attachment_id {
        None => {
            // Membership is re-asserted in the WHERE, so a revocation
            // racing the check above cannot slip a row in: zero returned
            // rows means exactly that.
            let row = sqlx::query(AssertSqlSafe(format!(
                "INSERT INTO messages \
                     (channel_id, sender_id, kind, content, reply_to, attachment_id) \
                 SELECT $1, $2, $3, $4, $5, NULL \
                 WHERE {MEMBER_OF} \
                 RETURNING id, (EXTRACT(EPOCH FROM created_at) * 1000)::bigint AS created_at_ms"
            )))
            .bind(channel_id)
            .bind(me)
            .bind(message_kind_str(req.kind.clone()))
            .bind(&req.content)
            .bind(req.reply_to)
            .fetch_optional(&state.pg)
            .await?;
            match row {
                Some(r) => (r.try_get("id")?, r.try_get("created_at_ms")?, None),
                None => {
                    return Err(ApiError::forbidden("not a member of this channel"));
                }
            }
        }
        Some(att_id) => {
            // Claim + insert as one statement: `locked` takes the
            // attachment row lock under the uploader/unclaimed guard, so a
            // concurrent send loses the lock race, locks nothing, inserts
            // nothing — the atomicity the old explicit transaction bought,
            // with none of its round trips. `ins` runs before `claim`
            // because the latter reads the former's RETURNING output, which
            // also satisfies the attachments.message_id foreign key.
            let row = sqlx::query(
                "WITH locked AS ( \
                     SELECT id FROM attachments \
                     WHERE id = $6 AND uploader_id = $2 AND message_id IS NULL \
                     FOR UPDATE \
                 ), ins AS ( \
                     INSERT INTO messages \
                         (channel_id, sender_id, kind, content, reply_to, attachment_id) \
                     SELECT $1, $2, $3, $4, $5, l.id FROM locked l \
                     RETURNING id, attachment_id, \
                             (EXTRACT(EPOCH FROM created_at) * 1000)::bigint AS created_at_ms \
                 ), claim AS ( \
                     UPDATE attachments a SET message_id = i.id \
                     FROM ins i \
                     WHERE a.id = i.attachment_id \
                     RETURNING a.id, a.name, a.size, a.nonce, a.encrypted \
                 ) \
                 SELECT i.id, i.created_at_ms, \
                        c.id AS att_id, c.name AS att_name, c.size AS att_size, \
                        c.nonce AS att_nonce, c.encrypted AS att_encrypted \
                 FROM ins i CROSS JOIN claim c",
            )
            .bind(channel_id)
            .bind(me)
            .bind(message_kind_str(req.kind.clone()))
            .bind(&req.content)
            .bind(req.reply_to)
            .bind(att_id)
            .fetch_optional(&state.pg)
            .await?;
            match row {
                Some(r) => (
                    r.try_get("id")?,
                    r.try_get("created_at_ms")?,
                    Some(AttachmentMeta {
                        id: r.try_get("att_id")?,
                        name: r.try_get("att_name")?,
                        size: r.try_get("att_size")?,
                        nonce: r.try_get("att_nonce")?,
                        encrypted: r.try_get("att_encrypted")?,
                    }),
                ),
                None => {
                    return Err(ApiError::invalid(
                        "attachment not found, not uploaded by you, or already attached",
                    ));
                }
            }
        }
    };

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
        &state.redis_events,
        channel_id,
        WsServerBody::Message(dto.clone()),
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
///
/// One round trip: authorization rides inside the DELETE predicate itself
/// (no check-then-delete window), and the attachment row leaves in the
/// same implicit transaction before the message's ON DELETE SET NULL can
/// sever the link.
async fn delete_message(
    State(state): State<AppState>,
    auth: Authed,
    Path((channel_id, message_id)): Path<(i64, i64)>,
) -> ApiResult<StatusCode> {
    let me = auth.0;

    // `del` deletes only the caller's own message in this channel; `att`
    // drops the attachment row(s) it owned and returns the object key(s).
    // The main query reads the pre-statement snapshot, so `existed` still
    // sees a row `del` declined to delete — that splits a zero-row delete
    // into forbidden (someone else's) vs. not-found, exactly the split the
    // old pre-SELECT made.
    let row = sqlx::query(
        "WITH del AS ( \
             DELETE FROM messages \
             WHERE id = $1 AND channel_id = $2 AND sender_id = $3 \
             RETURNING id \
         ), att AS ( \
             DELETE FROM attachments WHERE message_id IN (SELECT id FROM del) \
             RETURNING s3_key \
         ) \
         SELECT (SELECT s3_key FROM att LIMIT 1) AS s3_key, \
                EXISTS (SELECT 1 FROM del) AS deleted, \
                EXISTS (SELECT 1 FROM messages WHERE id = $1 AND channel_id = $2) AS existed",
    )
    .bind(message_id)
    .bind(channel_id)
    .bind(me)
    .fetch_one(&state.pg)
    .await?;

    if !row.try_get::<bool, _>("deleted")? {
        return Err(if row.try_get::<bool, _>("existed")? {
            ApiError::forbidden("only the sender can delete a message")
        } else {
            ApiError::not_found("no such message")
        });
    }
    let s3_key: Option<String> = row.try_get("s3_key")?;

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
        &state.redis_events,
        channel_id,
        WsServerBody::MessageDeleted {
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
                // `ChannelKind` is non_exhaustive; the loop above lists every
                // variant this version knows, so this is unreachable.
                _ => continue,
            };
            assert_eq!(parse_channel_kind(s), Some(k));
        }
        assert_eq!(parse_channel_kind("bogus"), None);
    }
}

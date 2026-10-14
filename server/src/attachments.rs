//! Attachment reservation + presigned upload/download URLs — owned by S5.
//!
//! Flow (ADR 0001: the Instance never sees plaintext or keys):
//! 1. `POST /attachments` reserves a row and hands back a presigned `PUT`
//!    URL (15 min). The client encrypts on-device and PUTs raw ciphertext
//!    bytes to that URL — no auth header, no required Content-Type; the
//!    SigV4 query signature *is* the authorization.
//! 2. The sender references `attachment.id` from `SendMessageRequest`;
//!    messages.rs (S4) claims the row (`attachments.message_id`) on send.
//! 3. Recipients fetch bytes via `GET /attachments/{id}/download-url`
//!    (10 min presigned `GET`) and decrypt with the nonce carried in the
//!    message's [`AttachmentMeta`].

use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use bysyc_common::protocol::{
    AttachmentMeta, CreateAttachmentRequest, CreateAttachmentResponse, DownloadUrlResponse,
};
use rand::distr::{Alphanumeric, SampleString};

use crate::db::AppState;
use crate::error::{ApiError, ApiResult};
use crate::s3;
use crate::session::Authed;

/// Lifetime of a presigned upload URL.
const UPLOAD_URL_TTL: Duration = Duration::from_secs(15 * 60);
/// Lifetime of a presigned download URL.
const DOWNLOAD_URL_TTL: Duration = Duration::from_secs(10 * 60);

/// `attachments.name` column cap.
const MAX_NAME_CHARS: usize = 255;
/// `attachments.nonce` column cap.
const MAX_NONCE_CHARS: usize = 128;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/attachments", post(create_attachment))
        .route("/attachments/{id}/download-url", get(download_url))
}

/// POST /attachments — reserve storage for one encrypted file.
async fn create_attachment(
    State(state): State<AppState>,
    Authed(me): Authed,
    body: Bytes,
) -> ApiResult<Json<CreateAttachmentResponse>> {
    let req: CreateAttachmentRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::invalid(format!("malformed request body: {e}")))?;

    if req.name.is_empty() || req.name.chars().count() > MAX_NAME_CHARS {
        return Err(ApiError::invalid(format!(
            "name must be 1..={MAX_NAME_CHARS} characters"
        )));
    }
    if req.size < 1 || req.size as u64 > state.config.attachment_max_bytes {
        return Err(ApiError::invalid(format!(
            "size must be 1..={} bytes",
            state.config.attachment_max_bytes
        )));
    }
    if req.nonce.is_empty() || req.nonce.chars().count() > MAX_NONCE_CHARS {
        return Err(ApiError::invalid(format!(
            "nonce must be 1..={MAX_NONCE_CHARS} characters"
        )));
    }

    // Object key is unguessable (128 bits); only this server can mint
    // signed URLs for it. "Bucket already exists" counts as success.
    s3::ensure_bucket(&state).await?;
    let s3_key = format!("att/{}", Alphanumeric.sample_string(&mut rand::rng(), 32));

    let row = sqlx::query(
        "INSERT INTO attachments(name, size, nonce, s3_key, uploader_id) \
                           VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(&req.name)
    .bind(req.size)
    .bind(&req.nonce)
    .bind(&s3_key)
    .bind(me)
    .fetch_one(&state.pg)
    .await?;
    let id: i64 = sqlx::Row::try_get(&row, "id")
        .map_err(|e| ApiError::internal(format!("reading attachment id: {e}")))?;

    let upload_url = s3::presign_put(&state, &s3_key, UPLOAD_URL_TTL).await?;

    Ok(Json(CreateAttachmentResponse {
        attachment: AttachmentMeta {
            id,
            name: req.name,
            size: req.size,
            nonce: req.nonce,
        },
        upload_url,
    }))
}

/// GET /attachments/{id}/download-url — short-lived presigned GET.
///
/// v1 membership model: any authenticated Account can mint a download URL
/// for any attachment id. This is deliberate — the s3 key is unguessable
/// (128 random hex chars), the URL expires in 10 minutes, and the bytes it
/// serves are ciphertext only this account's peers can decrypt anyway.
/// Message visibility (who learns an attachment id at all) is already
/// gated by channel membership in messages/guild endpoints.
async fn download_url(
    State(state): State<AppState>,
    Authed(_me): Authed,
    Path(id): Path<i64>,
) -> ApiResult<Json<DownloadUrlResponse>> {
    let s3_key: Option<String> = sqlx::query_scalar("SELECT s3_key FROM attachments WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.pg)
        .await?;
    let s3_key = s3_key.ok_or_else(|| ApiError::not_found("no such attachment"))?;

    let url = s3::presign_get(&state, &s3_key, DOWNLOAD_URL_TTL).await?;
    let expires_at_ms = now_ms() + DOWNLOAD_URL_TTL.as_millis() as i64;

    Ok(Json(DownloadUrlResponse { url, expires_at_ms }))
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after 1970")
        .as_millis() as i64
}

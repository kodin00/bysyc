//! Attachment storage — owned by S5.
//!
//! Two paths share the `attachments` table:
//!
//! 1. Ciphertext flow (ADR 0001: the Instance never sees plaintext or keys):
//!    1. `POST /attachments` reserves a row and hands back a presigned `PUT`
//!       URL (15 min). The client encrypts on-device and PUTs raw ciphertext
//!       bytes to that URL — no auth header, no required Content-Type; the
//!       SigV4 query signature *is* the authorization.
//!    2. The sender references `attachment.id` from `SendMessageRequest`;
//!       messages.rs (S4) claims the row (`attachments.message_id`) on send.
//!    3. Recipients fetch bytes via `GET /attachments/{id}/download-url`
//!       (10 min presigned `GET`) and decrypt with the nonce carried in the
//!       message's [`AttachmentMeta`].
//!
//! 2. Image flow (`POST /attachments/image`) — the deliberate exception:
//!    the Instance receives the raw bytes, confirms they really are WebP
//!    (magic-byte check below — a mislabeled PNG is rejected with a 400,
//!    not stored), and PUTs them itself. These bytes are plaintext the
//!    server has seen: ADR 0001's "never sees plaintext" is intentionally
//!    waived for images only, in exchange for the server being able to
//!    guarantee the stored format. The stored name is server-assigned
//!    (`img_` + 12 random chars + `.webp`) so an uploader's original file
//!    name never reaches storage, the database, or other members. Rows are
//!    written with `encrypted = false` and an empty nonce (nothing to
//!    derive a content key from); messages claim them exactly like
//!    ciphertext attachments.

use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use bysyc_common::protocol::{
    AttachmentMeta, CreateAttachmentRequest, CreateAttachmentResponse, DownloadUrlResponse,
    ImageUploadResponse,
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
/// Random chars in a server-assigned image name (`img_` prefix and `.webp`
/// suffix excluded). 62^12 ≈ 2^71 — plenty for "not the original name".
const IMAGE_NAME_RAND_CHARS: usize = 12;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/attachments", post(create_attachment))
        .route("/attachments/image", post(upload_image))
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
            encrypted: true,
        },
        upload_url,
    }))
}

/// WebP container check: `RIFF` magic at bytes 0..4 and the `WEBP` FourCC
/// at 8..12 (bytes 4..8 are the RIFF chunk size, ignored). This is the
/// whole point of the image path — the Instance must confirm uploaded
/// bytes really are WebP rather than trust a Content-Type or extension.
pub(crate) fn is_webp(bytes: &[u8]) -> bool {
    bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP"
}

/// POST /attachments/image — store one server-validated WebP image.
///
/// The Instance sees (and itself stores) these bytes, unlike the presigned
/// ciphertext flow; see the module docs for why that exception is
/// deliberate. The response carries the reserved row; there is no upload
/// URL because the bytes are already in object storage.
async fn upload_image(
    State(state): State<AppState>,
    Authed(me): Authed,
    body: Bytes,
) -> ApiResult<Json<ImageUploadResponse>> {
    if body.is_empty() || body.len() as u64 > state.config.attachment_max_bytes {
        return Err(ApiError::invalid(format!(
            "image must be 1..={} bytes",
            state.config.attachment_max_bytes
        )));
    }
    if !is_webp(&body) {
        return Err(ApiError::invalid(
            "image must be a WebP file (RIFF/WEBP container)",
        ));
    }

    // Server-assigned name only: the uploader's original file name must
    // not leak into storage, the database, or other members' clients.
    let name = format!(
        "img_{}.webp",
        Alphanumeric.sample_string(&mut rand::rng(), IMAGE_NAME_RAND_CHARS)
    );
    // No client-side key derivation for plaintext bytes; the column is
    // plain TEXT NOT NULL, and '' satisfies it (the 1..128-char check
    // above applies to the ciphertext flow's request body only).
    let nonce = String::new();
    let size = body.len() as i64;

    // Same key shape as the ciphertext path: unguessable, and only this
    // server can mint URLs for it.
    let s3_key = format!("att/{}", Alphanumeric.sample_string(&mut rand::rng(), 32));
    s3::put_object(&state, &s3_key, body).await?;

    let row = sqlx::query(
        "INSERT INTO attachments(name, size, nonce, s3_key, uploader_id, encrypted) \
           VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(&name)
    .bind(size)
    .bind(&nonce)
    .bind(&s3_key)
    .bind(me)
    .bind(false)
    .fetch_one(&state.pg)
    .await?;
    let id: i64 = sqlx::Row::try_get(&row, "id")
        .map_err(|e| ApiError::internal(format!("reading attachment id: {e}")))?;

    Ok(Json(ImageUploadResponse {
        attachment: AttachmentMeta {
            id,
            name,
            size,
            nonce,
            encrypted: false,
        },
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

#[cfg(test)]
mod tests {
    use super::*;

    /// "RIFF" + u32-le size + the given FourCC at bytes 8..12: a generic
    /// RIFF container (AVI, WAVE, ...).
    fn riff(fourcc: &[u8]) -> Vec<u8> {
        let mut out = b"RIFF".to_vec();
        out.extend_from_slice(&36u32.to_le_bytes());
        out.extend_from_slice(fourcc);
        out
    }

    /// `riff` with the WebP FourCC plus one chunk: the smallest header the
    /// magic check accepts. The size field is not validated.
    fn webp_header(chunk: &[u8]) -> Vec<u8> {
        let mut out = riff(b"WEBP");
        out.extend_from_slice(chunk);
        out
    }

    #[test]
    fn webp_magic_accepts_every_chunk_variant() {
        // VP8 (lossy), VP8L (lossless), and VP8X (extended) share the
        // RIFF/WEBP container.
        for chunk in [&b"VP8 "[..], b"VP8L", b"VP8X"] {
            assert!(is_webp(&webp_header(chunk)), "{chunk:?} should pass");
        }
        // Only the head is checked; a real payload behind it still passes.
        let mut full = webp_header(b"VP8 ");
        full.extend_from_slice(&[0u8; 64]);
        assert!(is_webp(&full));
    }

    #[test]
    fn webp_magic_rejects_other_image_formats() {
        // The formats a client is most likely to send by mistake.
        assert!(!is_webp(b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR"), "PNG");
        assert!(!is_webp(b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01"), "JPEG");
        assert!(!is_webp(b"GIF89a\x0a\x00\x0a\x00\x91\x00\x00"), "GIF");
    }

    #[test]
    fn webp_magic_rejects_truncated_garbage_and_non_webp_riff() {
        assert!(!is_webp(b""), "empty");
        assert!(!is_webp(b"RIFF\x24\x00\x00\x00WEB"), "cut before the FourCC");
        assert!(!is_webp(b"RIFF\x24\x00\x00\x00"), "RIFF alone");
        // Other RIFF containers look similar but are not WebP.
        assert!(!is_webp(&riff(b"AVI ")), "RIFF/AVI");
        assert!(!is_webp(&riff(b"WAVE")), "RIFF/WAVE");
        assert!(!is_webp(b"definitely not an image at all"), "garbage");
    }
}

//! Key material endpoints: identity-key upload, one-time-key pooling, and
//! single-claim key fetch for Olm session bootstrap.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use bysyc_common::protocol::{ClaimedKeys, UploadOtkRequest};
use serde::Deserialize;

use crate::db::AppState;
use crate::error::{ApiError, ApiResult};
use crate::session::Authed;

/// Max one-time keys accepted per upload call.
const MAX_OTKS_PER_UPLOAD: usize = 50;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/keys/identity", put(put_identity))
        .route("/keys/otk", post(upload_otk))
        .route("/keys/{account_id}", get(claim_keys))
}

#[derive(Deserialize)]
struct PutIdentityRequest {
    identity_key: String,
}

async fn put_identity(
    State(state): State<AppState>,
    Authed(me): Authed,
    Json(req): Json<PutIdentityRequest>,
) -> ApiResult<StatusCode> {
    sqlx::query("UPDATE accounts SET identity_key = $1 WHERE id = $2")
        .bind(&req.identity_key)
        .bind(me)
        .execute(&state.pg)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn upload_otk(
    State(state): State<AppState>,
    Authed(me): Authed,
    Json(req): Json<UploadOtkRequest>,
) -> ApiResult<StatusCode> {
    if req.one_time_keys.len() > MAX_OTKS_PER_UPLOAD {
        return Err(ApiError::invalid("at most 50 one-time keys per upload"));
    }
    let mut tx = state.pg.begin().await?;
    for entry in &req.one_time_keys {
        // Client-side format: a single opaque "key_id:b64pubkey" string.
        let Some((key_id, pubkey)) = entry.split_once(':') else {
            return Err(ApiError::invalid(
                "one-time key entries must be formatted 'key_id:b64pubkey'",
            ));
        };
        sqlx::query(
            "INSERT INTO one_time_keys (account_id, key_id, pubkey) VALUES ($1, $2, $3) \
             ON CONFLICT (account_id, key_id) DO UPDATE SET pubkey = EXCLUDED.pubkey",
        )
        .bind(me)
        .bind(key_id)
        .bind(pubkey)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Identity key plus one atomically-claimed OTK (deleted as it is returned, so
/// each key is handed out at most once). An empty peer OTK pool is not an
/// error: `one_time_key` comes back `None` and the client proceeds without a
/// one-time key.
async fn claim_keys(
    State(state): State<AppState>,
    Authed(_me): Authed,
    Path(account_id): Path<i64>,
) -> ApiResult<Json<ClaimedKeys>> {
    let identity_key: Option<Option<String>> =
        sqlx::query_scalar("SELECT identity_key FROM accounts WHERE id = $1")
            .bind(account_id)
            .fetch_optional(&state.pg)
            .await?;
    let identity_key = identity_key
        .ok_or_else(|| ApiError::not_found("no such account"))?
        .ok_or_else(|| ApiError::invalid("peer has no identity key"))?;

    let claimed: Option<(String, String)> = sqlx::query_as(
        "DELETE FROM one_time_keys \
         WHERE ctid IN (SELECT ctid FROM one_time_keys WHERE account_id = $1 LIMIT 1) \
         RETURNING key_id, pubkey",
    )
    .bind(account_id)
    .fetch_optional(&state.pg)
    .await?;
    let one_time_key = claimed.map(|(key_id, pubkey)| format!("{key_id}:{pubkey}"));

    Ok(Json(ClaimedKeys {
        identity_key,
        one_time_key,
    }))
}

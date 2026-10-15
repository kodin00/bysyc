//! Auth endpoints: invite-gated registration, login, logout, and "me".
//!
//! Sessions and the [`Authed`] extractor live in [`crate::session`].

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use bysyc_common::protocol::{
    AccountInfo, ErrorCode, LoginRequest, RegisterRequest, TokenResponse,
};

use crate::db::AppState;
use crate::error::{ApiError, ApiResult};
use crate::passwd;
use crate::session::{self, Authed};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
        .route("/auth/me", get(me))
}

/// (id, username, identity_key, created_at_ms)
type AccountRow = (i64, String, Option<String>, i64);

fn account_info((id, username, identity_key, created_at_ms): AccountRow) -> AccountInfo {
    AccountInfo {
        id,
        username,
        identity_key: identity_key.unwrap_or_default(),
        created_at_ms,
    }
}

/// 3–32 chars of `[a-z0-9_.]`.
fn valid_username(username: &str) -> bool {
    (3..=32).contains(&username.len())
        && username
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.')
}

async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> ApiResult<Json<TokenResponse>> {
    if !valid_username(&req.username) {
        return Err(ApiError::invalid(
            "username must be 3-32 characters of a-z, 0-9, '_' or '.'",
        ));
    }

    // Hash before opening the transaction: argon2 is slow and must not hold
    // the invite/username locks below. It's also CPU-bound (~19 MiB, tens of
    // ms), so it runs on the blocking pool instead of an async worker.
    let password_hash = tokio::task::spawn_blocking(move || passwd::hash_password(&req.password))
        .await
        .map_err(|_| ApiError::internal("password hash worker panicked"))?;

    let mut tx = state.pg.begin().await?;

    // Lock the invite row so concurrent redemptions of the same code
    // serialize, and validate it exists and is unused.
    let invite: Option<(Option<i64>,)> =
        sqlx::query_as("SELECT used_by FROM registration_invites WHERE code = $1 FOR UPDATE")
            .bind(&req.invite_code)
            .fetch_optional(&mut *tx)
            .await?;
    match invite {
        None => {
            return Err(ApiError::bad(
                ErrorCode::InvalidInvite,
                "unknown registration invite code",
            ));
        }
        Some((Some(_),)) => {
            return Err(ApiError::bad(
                ErrorCode::InvalidInvite,
                "registration invite already used",
            ));
        }
        Some((None,)) => {}
    }

    // Serialize same-username registrations so the existence check below is
    // authoritative; released automatically at commit/rollback.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(&req.username)
        .execute(&mut *tx)
        .await?;

    let taken: Option<i64> = sqlx::query_scalar("SELECT id FROM accounts WHERE username = $1")
        .bind(&req.username)
        .fetch_optional(&mut *tx)
        .await?;
    if taken.is_some() {
        return Err(ApiError::bad(
            ErrorCode::UsernameTaken,
            "username is already taken",
        ));
    }

    let row: AccountRow = sqlx::query_as(
        "INSERT INTO accounts (username, password_hash, identity_key) \
         VALUES ($1, $2, $3) \
         RETURNING id, username, identity_key, (EXTRACT(EPOCH FROM created_at) * 1000)::bigint",
    )
    .bind(&req.username)
    .bind(&password_hash)
    .bind(&req.identity_key)
    .fetch_one(&mut *tx)
    .await?;

    sqlx::query("UPDATE registration_invites SET used_by = $1, used_at = now() WHERE code = $2")
        .bind(row.0)
        .bind(&req.invite_code)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    tracing::info!(account_id = row.0, username = %req.username, "account registered");

    let token = session::create(&state.redis, row.0).await?;
    Ok(Json(TokenResponse {
        token,
        account: account_info(row),
    }))
}

async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> ApiResult<Json<TokenResponse>> {
    // Unknown user and wrong password are indistinguishable on the wire.
    let row: Option<(i64, String, String, Option<String>, i64)> = sqlx::query_as(
        "SELECT id, username, password_hash, identity_key, \
                (EXTRACT(EPOCH FROM created_at) * 1000)::bigint \
         FROM accounts WHERE username = $1",
    )
    .bind(&req.username)
    .fetch_optional(&state.pg)
    .await?;
    let Some((id, username, password_hash, identity_key, created_at_ms)) = row else {
        tracing::info!(username = %req.username, "login failed: unknown account");
        return Err(ApiError::unauthorized("invalid credentials"));
    };
    // Same blocking-pool treatment as register: argon2 is CPU-bound.
    let verified =
        tokio::task::spawn_blocking(move || passwd::verify_password(&req.password, &password_hash))
            .await
            .map_err(|_| ApiError::internal("password verify worker panicked"))?;
    if !verified {
        tracing::info!(account_id = id, "login failed: wrong password");
        return Err(ApiError::unauthorized("invalid credentials"));
    }

    tracing::info!(account_id = id, "login ok");
    let token = session::create(&state.redis, id).await?;
    Ok(Json(TokenResponse {
        token,
        account: AccountInfo {
            id,
            username,
            identity_key: identity_key.unwrap_or_default(),
            created_at_ms,
        },
    }))
}

async fn logout(
    State(state): State<AppState>,
    Authed(me): Authed,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    // Authed already validated the token; re-read it to delete the session.
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::unauthorized("expected 'Authorization: Bearer <token>'"))?;
    session::delete(&state.redis, raw).await?;
    tracing::info!(account_id = me, "logout");
    Ok(StatusCode::NO_CONTENT)
}

async fn me(State(state): State<AppState>, Authed(me): Authed) -> ApiResult<Json<AccountInfo>> {
    let row: Option<AccountRow> = sqlx::query_as(
        "SELECT id, username, identity_key, (EXTRACT(EPOCH FROM created_at) * 1000)::bigint \
         FROM accounts WHERE id = $1",
    )
    .bind(me)
    .fetch_optional(&state.pg)
    .await?;
    let row = row.ok_or_else(|| ApiError::unauthorized("account no longer exists"))?;
    Ok(Json(account_info(row)))
}

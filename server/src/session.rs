//! Bearer-token sessions in Redis, plus the [`Authed`] request extractor.
//!
//! The extractor lives here (rather than in `auth.rs`) because it *is*
//! session validation: parse `Authorization: Bearer <token>` and resolve it
//! through the session store below. Every authenticated handler in the crate
//! takes `Authed` as an extractor argument.
//!
//! Session format: token = 32 random bytes, hex-encoded (64 chars); Redis key
//! `sess:{token}` holds the account_id, TTL 30 days, sliding — every
//! successful [`validate`] refreshes the TTL back to 30 days.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::db::AppState;
use crate::error::ApiError;

/// Session lifetime: 30 days, in seconds.
const SESSION_TTL_SECS: u64 = 30 * 24 * 60 * 60;

/// The authenticated caller: `Authed(me)` yields the account id.
pub struct Authed(pub i64);

impl FromRequestParts<AppState> for Authed {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer_token(parts.headers.get(axum::http::header::AUTHORIZATION))?;
        let account_id = validate(&state.redis, &token).await?;
        Ok(Authed(account_id))
    }
}

/// Pull the raw token out of an `Authorization` header value.
fn bearer_token(value: Option<&axum::http::HeaderValue>) -> Result<String, ApiError> {
    let raw = value
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::unauthorized("missing Authorization header"))?;
    let token = raw
        .strip_prefix("Bearer ")
        .ok_or_else(|| ApiError::unauthorized("expected 'Authorization: Bearer <token>'"))?;
    if token.is_empty() {
        return Err(ApiError::unauthorized("empty bearer token"));
    }
    Ok(token.to_owned())
}

/// Mint a session token for `account_id` and store it with a 30-day TTL.
pub async fn create(
    redis: &redis::aio::ConnectionManager,
    account_id: i64,
) -> Result<String, ApiError> {
    let bytes: [u8; 32] = rand::random();
    let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let mut conn = redis.clone();
    redis::Pipeline::new()
        .cmd("SET")
        .arg(format!("sess:{token}"))
        .arg(account_id.to_string())
        .arg("EX")
        .arg(SESSION_TTL_SECS)
        .query_async::<()>(&mut conn)
        .await?;
    Ok(token)
}

/// Resolve a token to its account id, refreshing the sliding TTL.
///
/// Returns `unauthorized` when the token is unknown or expired.
pub async fn validate(redis: &redis::aio::ConnectionManager, token: &str) -> Result<i64, ApiError> {
    let key = format!("sess:{token}");
    let mut conn = redis.clone();
    let account_id: Option<String> = redis::cmd("GET").arg(&key).query_async(&mut conn).await?;
    let Some(account_id) = account_id else {
        return Err(ApiError::unauthorized("invalid or expired session token"));
    };
    let account_id: i64 = account_id
        .parse()
        .map_err(|_| ApiError::internal("corrupt session record"))?;
    redis::cmd("EXPIRE")
        .arg(&key)
        .arg(SESSION_TTL_SECS)
        .query_async::<()>(&mut conn)
        .await?;
    Ok(account_id)
}

/// Delete a session (logout). Idempotent: deleting an unknown token is fine.
pub async fn delete(redis: &redis::aio::ConnectionManager, token: &str) -> Result<(), ApiError> {
    let mut conn = redis.clone();
    redis::cmd("DEL")
        .arg(format!("sess:{token}"))
        .query_async::<()>(&mut conn)
        .await?;
    Ok(())
}

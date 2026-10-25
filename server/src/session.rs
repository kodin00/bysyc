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

use bysyc_common::protocol::AccountInfo;

use crate::db::AppState;
use crate::error::ApiError;

/// Session lifetime: 30 days, in seconds.
const SESSION_TTL_SECS: u64 = 30 * 24 * 60 * 60;
/// TTL for the short-lived `AccountInfo` cache under `sessinfo:{id}` that
/// `/auth/me` reads to skip the Postgres hit on the hot path. Short so an
/// identity-key upload (which refreshes it) and any future account mutation
/// propagate within minutes even if the refresh is missed.
const ACCOUNT_INFO_TTL_SECS: u64 = 5 * 60;

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
///
/// Also caches `account_info` (as JSON) under `sessinfo:{account_id}` with a
/// short TTL so [`account_info`] (and thus `/auth/me`) can serve the hot path
/// from Redis without a Postgres hit. The cache is refreshed on identity-key
/// upload (see `crate::keys::put_identity`); the short TTL bounds staleness if
/// a refresh is missed.
pub async fn create(
    redis: &redis::aio::ConnectionManager,
    account_id: i64,
    account_info: &AccountInfo,
) -> Result<String, ApiError> {
    // 32 random bytes hex-encoded (64 chars). `hex::encode` preallocates the
    // 64-byte String in one shot; the old `format!("{b:02x}")` allocated a
    // String per byte before collecting.
    let token = hex::encode(rand::random::<[u8; 32]>());
    let info_json = serde_json::to_string(account_info)
        .map_err(|e| ApiError::internal(format!("account info serialize failed: {e}")))?;
    let mut conn = redis.clone();
    redis::Pipeline::new()
        .cmd("SET")
        .arg(format!("sess:{token}"))
        .arg(account_id.to_string())
        .arg("EX")
        .arg(SESSION_TTL_SECS)
        .cmd("SET")
        .arg(format!("sessinfo:{account_id}"))
        .arg(info_json)
        .arg("EX")
        .arg(ACCOUNT_INFO_TTL_SECS)
        .query_async::<()>(&mut conn)
        .await?;
    Ok(token)
}

/// Read the cached `AccountInfo` for `account_id`, if present. `/auth/me`
/// uses this to skip the Postgres hit on the hot path; a miss (cache empty,
/// expired, or corrupt) falls through to a Postgres fetch that re-caches
/// via [`cache_account_info`]. Returns `Ok(None)` for a corrupt record so
/// the caller degrades to the Postgres fallback rather than erroring the
/// request.
pub async fn account_info(
    redis: &redis::aio::ConnectionManager,
    account_id: i64,
) -> Result<Option<AccountInfo>, ApiError> {
    let mut conn = redis.clone();
    let json: Option<String> = redis::cmd("GET")
        .arg(format!("sessinfo:{account_id}"))
        .query_async(&mut conn)
        .await?;
    match json {
        Some(s) => match serde_json::from_str::<AccountInfo>(&s) {
            Ok(info) => Ok(Some(info)),
            Err(e) => {
                tracing::warn!(account_id, "corrupt sessinfo cache, ignoring: {e}");
                Ok(None)
            }
        },
        None => Ok(None),
    }
}

/// Write (or refresh) the cached `AccountInfo` for `account_id`. Called by
/// [`create`] on session creation, by `/auth/me` on a cache miss (read-
/// through), and by `keys::put_identity` after the identity key changes.
pub async fn cache_account_info(
    redis: &redis::aio::ConnectionManager,
    account_id: i64,
    info: &AccountInfo,
) -> Result<(), ApiError> {
    let info_json = serde_json::to_string(info)
        .map_err(|e| ApiError::internal(format!("account info serialize failed: {e}")))?;
    let mut conn = redis.clone();
    redis::cmd("SET")
        .arg(format!("sessinfo:{account_id}"))
        .arg(info_json)
        .arg("EX")
        .arg(ACCOUNT_INFO_TTL_SECS)
        .query_async::<()>(&mut conn)
        .await?;
    Ok(())
}

/// Resolve a token to its account id, refreshing the sliding TTL.
///
/// Returns `unauthorized` when the token is unknown or expired.
pub async fn validate(redis: &redis::aio::ConnectionManager, token: &str) -> Result<i64, ApiError> {
    let key = format!("sess:{token}");
    let mut conn = redis.clone();
    // GETEX fetches and slides the TTL in one round trip; a missing key
    // yields None without creating anything.
    let account_id: Option<String> = redis::cmd("GETEX")
        .arg(&key)
        .arg("EX")
        .arg(SESSION_TTL_SECS)
        .query_async(&mut conn)
        .await?;
    let Some(account_id) = account_id else {
        return Err(ApiError::unauthorized("invalid or expired session token"));
    };
    let account_id: i64 = account_id
        .parse()
        .map_err(|_| ApiError::internal("corrupt session record"))?;
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

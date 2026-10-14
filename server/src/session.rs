//! Bearer-token session validation against Redis. Owned by S2 — this stub
//! fixes the signature other agents code against.
//!
//! Session format: 32 random bytes, hex-encoded. Redis key `sess:{token}`
//! holds the account_id, TTL 30 days, refreshed on each successful validate.

pub async fn validate(
    redis: &redis::aio::ConnectionManager,
    token: &str,
) -> Result<i64, crate::error::ApiError> {
    let _ = (redis, token);
    Err(crate::error::ApiError::internal("sessions not implemented yet"))
}

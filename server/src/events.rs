//! Redis-backed event fan-out. Owned by the orchestrator.
//!
//! Every gateway connection subscribes to `acct:{id}` (directed events) and
//! `chan:{id}` for each channel its account can read. REST handlers publish
//! here; the owning WS connection forwards to the client.

use bysyc_common::protocol::WsServerBody;

/// Serialize and publish a directed event to every live connection of `account_id`.
pub async fn publish_to_account(
    redis: &redis::aio::ConnectionManager,
    account_id: i64,
    body: &WsServerBody,
) -> Result<(), redis::RedisError> {
    let json = serde_json::to_string(&wrap(body)).expect("WsServerBody serializes");
    let mut conn = redis.clone();
    redis::Pipeline::new()
        .publish(format!("acct:{account_id}"), json)
        .query_async(&mut conn)
        .await
}

/// Serialize and publish a channel-scoped event (messages, typing, voice) to
/// every live connection subscribed to `channel_id`.
pub async fn publish_to_channel(
    redis: &redis::aio::ConnectionManager,
    channel_id: i64,
    body: &WsServerBody,
) -> Result<(), redis::RedisError> {
    let json = serde_json::to_string(&wrap(body)).expect("WsServerBody serializes");
    let mut conn = redis.clone();
    redis::Pipeline::new()
        .publish(format!("chan:{channel_id}"), json)
        .query_async(&mut conn)
        .await
}

fn wrap(body: &WsServerBody) -> bysyc_common::protocol::WsServerMsg {
    bysyc_common::protocol::WsServerMsg { id: None, body: body.clone() }
}

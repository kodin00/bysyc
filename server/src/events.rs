//! Redis-backed event fan-out. Owned by the orchestrator.
//!
//! Every gateway connection subscribes to `acct:{id}` (directed events) and
//! `chan:{id}` for each channel its account can read. REST handlers publish
//! here; the owning WS connection forwards to the client.
//!
//! Bodies are taken by value and serialized exactly once per broadcast; the
//! payload bytes are then reused for every PUBLISH, so an N-account fan-out
//! costs one pipelined Redis round trip, not N awaited publishes. Publishes
//! ride the caller's dedicated event connection (`AppState::redis_events`)
//! so they never queue behind session/presence traffic.

use bysyc_common::protocol::{WsServerBody, WsServerMsg};

/// The exact envelope every publish here puts on the wire: a `WsServerMsg`
/// (body only — the envelope carries no server-side sequence number since
/// protocol v2 dropped `WsServerMsg.id`) serialized to JSON. One call per
/// broadcast — callers never re-serialize per recipient.
fn event_json(body: WsServerBody) -> String {
    serde_json::to_string(&WsServerMsg { body }).expect("WsServerBody serializes")
}

/// Serialize and publish a directed event to every live connection of `account_id`.
pub async fn publish_to_account(
    redis: &redis::aio::ConnectionManager,
    account_id: i64,
    body: WsServerBody,
) -> Result<(), redis::RedisError> {
    FanOut::new().account(account_id, body).flush(redis).await
}

/// Serialize and publish a directed event to many accounts in a single
/// Redis round trip: the body is serialized once and every PUBLISH in the
/// pipeline reuses the same payload bytes.
pub async fn publish_to_accounts(
    redis: &redis::aio::ConnectionManager,
    accounts: &[i64],
    body: WsServerBody,
) -> Result<(), redis::RedisError> {
    FanOut::new().accounts(accounts, body).flush(redis).await
}

/// Serialize and publish a channel-scoped event (messages, typing, voice) to
/// every live connection subscribed to `channel_id`.
pub async fn publish_to_channel(
    redis: &redis::aio::ConnectionManager,
    channel_id: i64,
    body: WsServerBody,
) -> Result<(), redis::RedisError> {
    let json = event_json(body);
    let mut conn = redis.clone();
    redis::pipe()
        .publish(format!("chan:{channel_id}"), json)
        .query_async(&mut conn)
        .await
}

/// A batch of directed publishes flushed as ONE pipelined Redis round trip.
/// For when one mutation produces several distinct events (or one event for
/// many accounts) and they should share the round trip:
///
/// ```ignore
/// events::FanOut::new()
///     .accounts(&existing_members, WsServerBody::MemberJoined { .. })
///     .account(me, WsServerBody::GuildJoined { .. })
///     .flush(&state.redis_events)
///     .await?;
/// ```
pub struct FanOut {
    pipe: redis::Pipeline,
}

impl FanOut {
    pub fn new() -> Self {
        Self {
            pipe: redis::pipe(),
        }
    }

    /// Queue one directed event for `account_id`.
    pub fn account(mut self, account_id: i64, body: WsServerBody) -> Self {
        self.pipe
            .publish(format!("acct:{account_id}"), event_json(body));
        self
    }

    /// Queue the same directed event for every account in `accounts`: the
    /// body is serialized once and the payload reused per PUBLISH. An empty
    /// slice queues nothing.
    pub fn accounts(mut self, accounts: &[i64], body: WsServerBody) -> Self {
        if !accounts.is_empty() {
            let json = event_json(body);
            for id in accounts {
                self.pipe.publish(format!("acct:{id}"), json.as_str());
            }
        }
        self
    }

    /// Send every queued publish in one Redis round trip. A batch that
    /// queued nothing is a no-op.
    pub async fn flush(
        self,
        redis: &redis::aio::ConnectionManager,
    ) -> Result<(), redis::RedisError> {
        if self.pipe.is_empty() {
            return Ok(());
        }
        let mut conn = redis.clone();
        self.pipe.query_async::<()>(&mut conn).await
    }
}

impl Default for FanOut {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The envelope is a wire contract clients depend on; pin the exact
    /// bytes for one representative body.
    #[test]
    fn envelope_bytes_are_pinned() {
        let json = event_json(WsServerBody::Presence {
            account_id: 2,
            online: true,
        });
        assert_eq!(
            json,
            r#"{"body":{"presence":{"account_id":2,"online":true}}}"#
        );
    }
}

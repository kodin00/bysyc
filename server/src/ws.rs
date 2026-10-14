//! The WebSocket gateway (`GET /ws`) — owned by S4.
//!
//! # Connection lifecycle
//!
//! 1. **Pre-upgrade checks** (failures stay inside the REST error envelope):
//!    `protocol` must equal [`PROTOCOL_VERSION`] (else HTTP 400 +
//!    `ErrorCode::ProtocolVersion`) and `token` must validate to an account
//!    (else 401).
//! 2. **Post-upgrade**: mark Redis presence (`presence:{id}` = "1", EX 90s),
//!    fan out `Presence{online:true}` to friends + guild co-members, then
//!    send `Ready` as the very first frame.
//! 3. **Task layout** (one task per connection, single writer):
//!
//!    ```text
//!    [subscription task] --raw JSON--> [out mpsc] --> [writer task] --> socket
//!    [connection loop] ---direct replies-^
//!    ```
//!
//!    Every frame to the client is written by the writer task alone, in
//!    order, so `Ready` precedes any pub/sub event.
//! 4. **Subscription lifecycle**: the subscription task owns a dedicated
//!    Redis pub/sub connection subscribed to `acct:{me}` plus `chan:{c}`
//!    for every channel `me` can read. The set is synchronized (a) once at
//!    connect, (b) on every client `Heartbeat` — the cheap, well-defined
//!    sync point — and (c) after a successful `VoiceJoin` (so a Private
//!    Call in a freshly opened DM works without waiting for a heartbeat).
//!    A client that just joined a Guild or opened a DM should therefore
//!    send a `Heartbeat` to start receiving the new channel's events;
//!    events missed before that are backfilled via
//!    `GET /channels/{id}/messages`. The task reconnects with backoff and
//!    re-establishes the full subscription set if the Redis connection
//!    drops.
//! 5. **Server-side heartbeat interval** (30s): refreshes the presence TTL
//!    as a safety net independent of client heartbeats. Connectivity is
//!    detected from socket close, not from TTL expiry.
//! 6. **Disconnect** (every exit path): delete the presence key, leave any
//!    voice channel via [`crate::voice::leave`] (which publishes the new
//!    `VoiceState`), fan out `Presence{online:false}` to the same
//!    friends+co-members audience. The REST session survives disconnect.
//!
//! # v1 limitations (documented contract)
//!
//! - One live connection per account: a second concurrent connection gets
//!   its own socket but shares the single presence key, so the first
//!   disconnect marks the account offline while the second socket lives.
//! - `Typing` membership is checked against the database on every message
//!   (no cache).
//!
//! # Schema (S1's migration, landed)
//!
//! - `accounts(id, username, password_hash, identity_key NULLABLE,
//!   created_at TIMESTAMPTZ)` — timestamps are read via
//!   `EXTRACT(EPOCH ...)::bigint` because this sqlx build has no chrono
//!   feature; a NULL identity_key is reported as an empty string
//! - `friends(a, b)`, `friend_requests(from_id, to_id)`
//! - `guilds(id, name, owner_id)`, `guild_members(guild_id, account_id)`
//! - `channels(id, guild_id NULL, kind 'text'|'voice', name)` — DM
//!   channels are `guild_id IS NULL` rows paired in
//!   `dm_channels(channel_id, a, b)` and reported as `ChannelKind::Dm`
//!   on the wire
//! - `mailbox(id, recipient_id, sender_id, content, created_at)`
//! - `voice_participants(channel_id, account_id)`

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use axum::extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::response::Response;
use axum::routing::get;
use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use redis::aio::ConnectionManager;
use sqlx::{PgPool, Row};
use tokio::sync::mpsc;

use bysyc_common::PROTOCOL_VERSION;
use bysyc_common::protocol::{
    AccountBrief, AccountInfo, ChannelInfo, ChannelKind, DmChannel, ErrorCode, GuildInfo,
    MailboxItem, WsClientBody, WsClientMsg, WsServerBody, WsServerMsg,
};

use crate::db::AppState;
use crate::error::ApiError;

/// Presence key TTL in seconds; refreshed by client heartbeats and by the
/// server-side tick below.
const PRESENCE_TTL_SECS: u64 = 90;
/// Safety-net presence refresh cadence while the socket is open.
const TICK_INTERVAL: Duration = Duration::from_secs(30);
/// Outgoing frame queue depth per connection before backpressure kicks in.
const OUT_QUEUE_DEPTH: usize = 256;

pub fn router() -> axum::Router<AppState> {
    axum::Router::new().route("/ws", get(ws_upgrade))
}

/// GET /ws?token=<session>&protocol=<version> — validate before upgrading
/// so failures land in the documented REST error envelope, then hand the
/// socket to the connection task.
async fn ws_upgrade(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
    ws: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    let offered = params
        .get("protocol")
        .ok_or_else(|| ApiError::bad(ErrorCode::ProtocolVersion, "missing protocol version"))?;
    let offered: u32 = offered.parse().map_err(|_| {
        ApiError::bad(
            ErrorCode::ProtocolVersion,
            format!("protocol must be {PROTOCOL_VERSION}"),
        )
    })?;
    if offered != PROTOCOL_VERSION {
        return Err(ApiError::bad(
            ErrorCode::ProtocolVersion,
            format!("server speaks protocol {PROTOCOL_VERSION}, client offered {offered}"),
        ));
    }

    let token = params
        .get("token")
        .ok_or_else(|| ApiError::unauthorized("missing session token"))?;
    let account_id = crate::session::validate(&state.redis, token).await?;

    Ok(ws
        .on_failed_upgrade(move |e| {
            tracing::warn!(account_id, "websocket upgrade failed: {e}");
        })
        .on_upgrade(move |socket| async move {
            if let Err(e) = run_connected(&state, socket, account_id).await {
                tracing::warn!(account_id, "gateway error: {}", e.message);
            }
            // Every exit path — normal close, error, panic-free failure —
            // unwinds presence, voice participation, and offline fan-out.
            disconnect_cleanup(&state, account_id).await;
        }))
}

// ---------------------------------------------------------------------------
// Connection body
// ---------------------------------------------------------------------------

async fn run_connected(state: &AppState, socket: WebSocket, me: i64) -> Result<(), ApiError> {
    // 1. Presence on + fan-out (best effort: a Redis hiccup must not kill
    //    an otherwise healthy connection).
    if let Err(e) = set_presence(&state.redis, me).await {
        tracing::warn!(me, "presence set failed: {e}");
    }
    fan_out_presence(state, me, true).await?;

    // 2. Snapshot (drains the mailbox; rows are only deleted on ack).
    let ready = ready_snapshot(state, me).await?;

    // 3. Plumbing. `Ready` is queued before anything else can push, and a
    //    single writer drains the mpsc, so it is always the first frame.
    let (out_tx, out_rx) = mpsc::channel::<WsMessage>(OUT_QUEUE_DEPTH);
    out_tx
        .send(text_msg(WsServerMsg {
            id: None,
            body: WsServerBody::Ready {
                account: ready.account,
                friends: ready.friends,
                incoming_requests: ready.incoming_requests,
                outgoing_requests: ready.outgoing_requests,
                guilds: ready.guilds,
                dm_channels: ready.dm_channels,
                mailbox: ready.mailbox,
            },
        }))
        .await
        .expect("writer not yet spawned; queue cannot be closed");

    let (sub_tx, sub_rx) = mpsc::channel::<HashSet<String>>(4);
    let subscriber = tokio::spawn(run_subscriber(
        state.config.redis_url.clone(),
        sub_rx,
        out_tx.clone(),
    ));
    if let Err(e) = sync_subscriptions(state, me, &sub_tx).await {
        tracing::warn!(me, "initial subscription sync failed: {e}");
    }

    let (sink, mut stream) = socket.split();
    let writer = tokio::spawn(write_loop(sink, out_rx));

    // 4. Main loop: socket reader + presence safety tick.
    let mut ticker = tokio::time::interval(TICK_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let out = out_tx.clone();
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if let Err(e) = set_presence(&state.redis, me).await {
                    tracing::warn!(me, "presence refresh failed: {e}");
                }
            }
            frame = stream.next() => match frame {
                None => break, // client went away
                Some(Ok(WsMessage::Text(txt))) => {
                    handle_client_msg(state, &sub_tx, &out, me, txt.as_str()).await;
                }
                Some(Ok(WsMessage::Close(_))) => break,
                Some(Err(e)) => {
                    tracing::debug!(me, "socket read error: {e}");
                    break;
                }
                // Pings are answered by axum itself; binary frames are not
                // part of the protocol and are ignored.
                Some(Ok(_)) => {}
            },
        }
    }

    // 5. Teardown: stop producers, let the writer drain and close.
    subscriber.abort();
    drop(sub_tx);
    drop(out);
    drop(out_tx);
    let _ = writer.await;
    Ok(())
}

/// Undo everything the connection set up: presence key, voice
/// participation, offline fan-out. The REST session intentionally
/// survives — only the gateway goes away.
async fn disconnect_cleanup(state: &AppState, me: i64) {
    let mut conn = state.redis.clone();
    if let Err(e) = redis::cmd("DEL")
        .arg(format!("presence:{me}"))
        .query_async::<()>(&mut conn)
        .await
    {
        tracing::warn!(me, "presence delete failed: {e}");
    }

    // Leave any Call. voice::leave publishes the fresh VoiceState to the
    // channel (and clears the participant row).
    match sqlx::query_scalar::<_, i64>(
        "SELECT channel_id FROM voice_participants WHERE account_id = $1",
    )
    .bind(me)
    .fetch_all(&state.pg)
    .await
    {
        Ok(channels) => {
            for channel_id in channels {
                if let Err(e) = crate::voice::leave(state, channel_id, me).await {
                    tracing::warn!(
                        me,
                        channel_id,
                        "voice leave on disconnect failed: {}",
                        e.message
                    );
                }
            }
        }
        Err(e) => tracing::error!(me, "voice cleanup query failed: {e:#}"),
    }

    if let Err(e) = fan_out_presence(state, me, false).await {
        tracing::warn!(me, "offline fan-out failed: {}", e.message);
    }
}

// ---------------------------------------------------------------------------
// Client message handling
// ---------------------------------------------------------------------------

async fn handle_client_msg(
    state: &AppState,
    sub_tx: &mpsc::Sender<HashSet<String>>,
    out: &mpsc::Sender<WsMessage>,
    me: i64,
    text: &str,
) {
    let msg: WsClientMsg = match serde_json::from_str(text) {
        Ok(m) => m,
        Err(e) => {
            send_error(
                out,
                None,
                ErrorCode::InvalidRequest,
                format!("malformed message: {e}"),
            );
            return;
        }
    };

    match msg.body {
        WsClientBody::Heartbeat => {
            // Refresh liveness and re-sync the subscription set: this is
            // the documented sync point after joining a guild / opening a
            // DM (see module docs).
            if let Err(e) = set_presence(&state.redis, me).await {
                tracing::warn!(me, "presence refresh failed: {e}");
            }
            if let Err(e) = sync_subscriptions(state, me, sub_tx).await {
                tracing::warn!(me, "subscription resync failed: {e}");
            }
        }
        WsClientBody::Typing { channel_id } => {
            match crate::messages::can_read(&state.pg, me, channel_id).await {
                Ok(true) => {
                    if let Err(e) = crate::events::publish_to_channel(
                        &state.redis,
                        channel_id,
                        &WsServerBody::Typing {
                            channel_id,
                            account_id: me,
                        },
                    )
                    .await
                    {
                        tracing::warn!(me, channel_id, "typing fan-out failed: {e}");
                    }
                }
                Ok(false) => send_error(
                    out,
                    Some(msg.id),
                    ErrorCode::Forbidden,
                    "not a member of this channel",
                ),
                Err(e) => {
                    tracing::error!(me, "typing membership check failed: {e:#}");
                    send_error(out, Some(msg.id), ErrorCode::Internal, "database error");
                }
            }
        }
        WsClientBody::AckMailbox { ids } => {
            if ids.is_empty() {
                return;
            }
            if let Err(e) =
                sqlx::query("DELETE FROM mailbox WHERE recipient_id = $1 AND id = ANY($2)")
                    .bind(me)
                    .bind(&ids)
                    .execute(&state.pg)
                    .await
            {
                tracing::error!(me, "mailbox ack failed: {e:#}");
                send_error(out, Some(msg.id), ErrorCode::Internal, "database error");
            }
        }
        WsClientBody::VoiceJoin { channel_id } => {
            match crate::voice::join(state, channel_id, me).await {
                Ok(participants) => {
                    // Direct reply so the joiner learns the participants
                    // immediately, before (and independent of) the pub/sub
                    // VoiceState that voice::join publishes to the channel.
                    let _ = out
                        .send(text_msg(WsServerMsg {
                            id: None,
                            body: WsServerBody::VoiceState {
                                channel_id,
                                participants,
                            },
                        }))
                        .await;
                    // Pick up subscriptions in case the call sits in a
                    // freshly opened DM the heartbeat has not synced yet.
                    if let Err(e) = sync_subscriptions(state, me, sub_tx).await {
                        tracing::warn!(me, "post-join subscription resync failed: {e}");
                    }
                }
                Err(e) => send_error(out, Some(msg.id), e.code, e.message),
            }
        }
        WsClientBody::VoiceLeave => {
            // The wire message carries no channel id; look up where we are.
            let current = sqlx::query_scalar::<_, i64>(
                "SELECT channel_id FROM voice_participants WHERE account_id = $1 LIMIT 1",
            )
            .bind(me)
            .fetch_optional(&state.pg)
            .await
            .ok()
            .flatten();
            match current {
                Some(channel_id) => {
                    if let Err(e) = crate::voice::leave(state, channel_id, me).await {
                        send_error(out, Some(msg.id), e.code, e.message);
                    }
                    // The updated VoiceState reaches the leaver through
                    // their still-active chan:{id} subscription.
                }
                None => {} // not in a Call: nothing to do, no error
            }
        }
        WsClientBody::CallSignal { call_id, to, kind } => {
            if let Err(e) = crate::voice::relay_signal(state, call_id, me, to, kind).await {
                send_error(out, Some(msg.id), e.code, e.message);
            }
        }
    }
}

fn send_error(
    out: &mpsc::Sender<WsMessage>,
    reply_to: Option<u64>,
    code: ErrorCode,
    message: impl Into<String>,
) {
    let msg = WsServerMsg {
        id: None,
        body: WsServerBody::Error {
            reply_to,
            code,
            message: message.into(),
        },
    };
    // try_send: never block the reader on a stalled client; if the queue
    // is full the socket is wedged anyway.
    let _ = out.try_send(text_msg(msg));
}

// ---------------------------------------------------------------------------
// Subscription plumbing
// ---------------------------------------------------------------------------

/// Every channel id `me` can currently read: all channels of their guilds
/// (text AND voice — VoiceState/Typing ride the same `chan:{id}` topics)
/// plus their DM channels.
async fn my_channels(pg: &PgPool, me: i64) -> sqlx::Result<Vec<i64>> {
    Ok(sqlx::query_scalar(
        "SELECT c.id FROM channels c \
         JOIN guild_members gm ON gm.guild_id = c.guild_id \
         WHERE gm.account_id = $1 \
         UNION \
         SELECT dc.channel_id FROM dm_channels dc WHERE dc.a = $1 OR dc.b = $1",
    )
    .bind(me)
    .fetch_all(pg)
    .await?)
}

/// The full pub/sub topic set for an account: the directed topic plus one
/// topic per readable channel.
fn subscription_names(me: i64, channels: &[i64]) -> HashSet<String> {
    let mut set = HashSet::with_capacity(channels.len() + 1);
    set.insert(format!("acct:{me}"));
    for c in channels {
        set.insert(format!("chan:{c}"));
    }
    set
}

/// Recompute the desired topic set and hand it to the subscription task.
async fn sync_subscriptions(
    state: &AppState,
    me: i64,
    sub_tx: &mpsc::Sender<HashSet<String>>,
) -> sqlx::Result<()> {
    let desired = subscription_names(me, &my_channels(&state.pg, me).await?);
    // A send error means the subscriber is gone, i.e. the connection is
    // already tearing down.
    let _ = sub_tx.send(desired).await;
    Ok(())
}

/// Owns the per-connection Redis pub/sub connection. Receives full desired
/// topic sets, diffs them against the current one, and forwards every
/// published payload (already-serialized `WsServerMsg` JSON, see
/// [`crate::events`]) verbatim to the writer. Reconnects with backoff and
/// re-establishes the full topic set if the connection drops.
async fn run_subscriber(
    redis_url: String,
    mut cmd_rx: mpsc::Receiver<HashSet<String>>,
    out_tx: mpsc::Sender<WsMessage>,
) {
    let client = match redis::Client::open(redis_url.as_str()) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("invalid redis url for pub/sub: {e}");
            return;
        }
    };

    let mut desired: HashSet<String> = HashSet::new();
    let mut backoff = Duration::from_secs(1);
    loop {
        let mut pubsub = match client.get_async_pubsub().await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("pub/sub connect failed, retrying in {backoff:?}: {e}");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(30));
                continue;
            }
        };
        backoff = Duration::from_secs(1);

        // (Re)establish the entire desired set after a (re)connect.
        if !desired.is_empty() {
            let all: Vec<&str> = desired.iter().map(String::as_str).collect();
            if let Err(e) = pubsub.subscribe(all).await {
                tracing::warn!("pub/sub resubscribe failed: {e}");
                continue;
            }
        }

        loop {
            // The message stream mutably borrows `pubsub` (and is not
            // Unpin — hence the pin). Binding it per iteration and
            // dropping it before the handlers run lets
            // `apply_subscriptions` retake the connection between
            // iterations.
            let mut messages = Box::pin(pubsub.on_message());
            let step = tokio::select! {
                cmd = cmd_rx.recv() => Step::Cmd(cmd),
                msg = messages.next() => Step::Msg(msg),
            };
            drop(messages);
            match step {
                Step::Cmd(Some(next)) => {
                    if let Err(e) = apply_subscriptions(&mut pubsub, &desired, &next).await {
                        tracing::warn!("pub/sub sync failed, reconnecting: {e}");
                        desired = next; // keep the intended set for the reconnect
                        break;
                    }
                    desired = next;
                }
                Step::Cmd(None) => return, // gateway connection is gone
                Step::Msg(Some(m)) => {
                    if let Ok(payload) = m.get_payload::<String>() {
                        if out_tx.send(WsMessage::Text(payload.into())).await.is_err() {
                            return; // writer gone -> connection over
                        }
                    }
                }
                Step::Msg(None) => {
                    tracing::warn!("pub/sub stream ended, reconnecting");
                    break;
                }
            }
        }
    }
}

/// One resolved event of the subscriber loop (avoids borrowing `pubsub`
/// inside the select handlers).
enum Step {
    Cmd(Option<HashSet<String>>),
    Msg(Option<redis::Msg>),
}

async fn apply_subscriptions(
    pubsub: &mut redis::aio::PubSub,
    current: &HashSet<String>,
    desired: &HashSet<String>,
) -> Result<(), redis::RedisError> {
    let add: Vec<&str> = desired.difference(current).map(String::as_str).collect();
    if !add.is_empty() {
        pubsub.subscribe(add).await?;
    }
    let drop: Vec<&str> = current.difference(desired).map(String::as_str).collect();
    if !drop.is_empty() {
        pubsub.unsubscribe(drop).await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Presence
// ---------------------------------------------------------------------------

async fn set_presence(redis: &ConnectionManager, me: i64) -> Result<(), redis::RedisError> {
    let mut conn = redis.clone();
    redis::cmd("SET")
        .arg(format!("presence:{me}"))
        .arg("1")
        .arg("EX")
        .arg(PRESENCE_TTL_SECS)
        .query_async::<()>(&mut conn)
        .await
}

/// Accounts that should hear about `me`'s connectivity: friends plus every
/// co-member of `me`'s guilds.
async fn presence_audience(pg: &PgPool, me: i64) -> sqlx::Result<Vec<i64>> {
    Ok(sqlx::query_scalar(
        "SELECT CASE WHEN f.a = $1 THEN f.b ELSE f.a END AS other \
         FROM friends f WHERE f.a = $1 OR f.b = $1 \
         UNION \
         SELECT gm2.account_id \
         FROM guild_members gm1 \
         JOIN guild_members gm2 ON gm1.guild_id = gm2.guild_id \
         WHERE gm1.account_id = $1 AND gm2.account_id <> $1",
    )
    .bind(me)
    .fetch_all(pg)
    .await?)
}

async fn fan_out_presence(state: &AppState, me: i64, online: bool) -> Result<(), ApiError> {
    for id in presence_audience(&state.pg, me).await? {
        if let Err(e) = crate::events::publish_to_account(
            &state.redis,
            id,
            &WsServerBody::Presence {
                account_id: me,
                online,
            },
        )
        .await
        {
            // One unreachable peer must not abort the fan-out.
            tracing::warn!(me, "presence fan-out to {id} failed: {e}");
        }
    }
    Ok(())
}

/// Batch `EXISTS presence:{id}` for the given accounts. Failures degrade
/// to "all offline": the protocol allows stale presence in snapshots.
async fn presence_map(
    redis: &ConnectionManager,
    ids: &[i64],
) -> Result<HashMap<i64, bool>, redis::RedisError> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let mut pipe = redis::Pipeline::new();
    for id in ids {
        pipe.exists(format!("presence:{id}"));
    }
    let mut conn = redis.clone();
    let results: Vec<i64> = pipe.query_async(&mut conn).await?;
    Ok(ids
        .iter()
        .zip(results)
        .map(|(id, n)| (*id, n != 0))
        .collect())
}

// ---------------------------------------------------------------------------
// Ready snapshot
// ---------------------------------------------------------------------------

struct Ready {
    account: AccountInfo,
    friends: Vec<AccountBrief>,
    incoming_requests: Vec<AccountBrief>,
    outgoing_requests: Vec<AccountBrief>,
    guilds: Vec<GuildInfo>,
    dm_channels: Vec<DmChannel>,
    mailbox: Vec<MailboxItem>,
}

async fn ready_snapshot(state: &AppState, me: i64) -> Result<Ready, ApiError> {
    let pg = &state.pg;

    let row = sqlx::query(
        "SELECT id, username, identity_key, \
                (EXTRACT(EPOCH FROM created_at) * 1000)::bigint AS created_at_ms \
         FROM accounts WHERE id = $1",
    )
    .bind(me)
    .fetch_one(pg)
    .await?;
    let account = AccountInfo {
        id: row.try_get("id")?,
        username: row.try_get("username")?,
        identity_key: row
            .try_get::<Option<String>, _>("identity_key")?
            .unwrap_or_default(),
        created_at_ms: row.try_get("created_at_ms")?,
    };

    let mut friends = briefs(
        pg,
        "SELECT a.id, a.username, a.identity_key \
         FROM friends f \
         JOIN accounts a ON a.id = CASE WHEN f.a = $1 THEN f.b ELSE f.a END \
         WHERE f.a = $1 OR f.b = $1",
        me,
    )
    .await?;
    let mut incoming_requests = briefs(
        pg,
        "SELECT a.id, a.username, a.identity_key \
         FROM friend_requests fr \
         JOIN accounts a ON a.id = fr.from_id \
         WHERE fr.to_id = $1",
        me,
    )
    .await?;
    let mut outgoing_requests = briefs(
        pg,
        "SELECT a.id, a.username, a.identity_key \
         FROM friend_requests fr \
         JOIN accounts a ON a.id = fr.to_id \
         WHERE fr.from_id = $1",
        me,
    )
    .await?;

    let guild_rows = sqlx::query(
        "SELECT g.id, g.name, g.owner_id \
         FROM guilds g \
         JOIN guild_members gm ON gm.guild_id = g.id \
         WHERE gm.account_id = $1",
    )
    .bind(me)
    .fetch_all(pg)
    .await?;
    let mut guilds: Vec<GuildInfo> = guild_rows
        .iter()
        .map(|r| -> Result<GuildInfo, sqlx::Error> {
            Ok(GuildInfo {
                id: r.try_get("id")?,
                name: r.try_get("name")?,
                owner_id: r.try_get("owner_id")?,
                channels: Vec::new(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if !guilds.is_empty() {
        let guild_ids: Vec<i64> = guilds.iter().map(|g| g.id).collect();
        let chan_rows =
            sqlx::query("SELECT id, guild_id, kind, name FROM channels WHERE guild_id = ANY($1)")
                .bind(&guild_ids)
                .fetch_all(pg)
                .await?;
        for cr in chan_rows {
            let guild_id: i64 = cr.try_get("guild_id")?;
            let Some(guild) = guilds.iter_mut().find(|g| g.id == guild_id) else {
                continue;
            };
            guild.channels.push(ChannelInfo {
                id: cr.try_get("id")?,
                guild_id: Some(guild_id),
                kind: crate::messages::parse_channel_kind(&cr.try_get::<String, _>("kind")?)
                    .ok_or_else(|| ApiError::internal("corrupt channel kind in database"))?,
                name: cr.try_get("name")?,
            });
        }
    }

    let dm_rows = sqlx::query(
        "SELECT dc.channel_id, \
                a.id AS peer_id, a.username AS peer_username, a.identity_key AS peer_key \
         FROM dm_channels dc \
         JOIN accounts a ON a.id = CASE WHEN dc.a = $1 THEN dc.b ELSE dc.a END \
         WHERE dc.a = $1 OR dc.b = $1",
    )
    .bind(me)
    .fetch_all(pg)
    .await?;
    let mut dm_channels = Vec::with_capacity(dm_rows.len());
    for r in dm_rows {
        let peer = AccountBrief {
            id: r.try_get("peer_id")?,
            username: r.try_get("peer_username")?,
            identity_key: r
                .try_get::<Option<String>, _>("peer_key")?
                .unwrap_or_default(),
            online: false,
        };
        // DM channel name is synthesized as the peer's username; clients
        // usually render the peer directly.
        let name = peer.username.clone();
        dm_channels.push(DmChannel {
            channel: ChannelInfo {
                id: r.try_get("channel_id")?,
                guild_id: None,
                kind: ChannelKind::Dm,
                name,
            },
            peer,
        });
    }

    let mail_rows = sqlx::query(
        "SELECT id, sender_id, content, \
                (EXTRACT(EPOCH FROM created_at) * 1000)::bigint AS created_at_ms \
         FROM mailbox WHERE recipient_id = $1 ORDER BY id",
    )
    .bind(me)
    .fetch_all(pg)
    .await?;
    let mut mailbox = Vec::with_capacity(mail_rows.len());
    for r in mail_rows {
        mailbox.push(MailboxItem {
            id: r.try_get("id")?,
            sender_id: r.try_get("sender_id")?,
            content: r.try_get("content")?,
            created_at_ms: r.try_get("created_at_ms")?,
        });
    }

    // Stamp presence flags across every brief in the snapshot. Best
    // effort: on Redis failure everyone reads as offline (the protocol
    // explicitly allows stale snapshot presence; live pushes follow).
    let mut brief_ids: Vec<i64> = Vec::new();
    for b in friends
        .iter()
        .chain(incoming_requests.iter())
        .chain(outgoing_requests.iter())
    {
        brief_ids.push(b.id);
    }
    brief_ids.extend(dm_channels.iter().map(|d| d.peer.id));
    let online = match presence_map(&state.redis, &brief_ids).await {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(
                me,
                "presence lookup failed, snapshot shows everyone offline: {e}"
            );
            HashMap::new()
        }
    };
    let stamp = |b: &mut AccountBrief| b.online = online.get(&b.id).copied().unwrap_or(false);
    friends.iter_mut().for_each(stamp);
    incoming_requests.iter_mut().for_each(stamp);
    outgoing_requests.iter_mut().for_each(stamp);
    dm_channels.iter_mut().for_each(|d| stamp(&mut d.peer));

    Ok(Ready {
        account,
        friends,
        incoming_requests,
        outgoing_requests,
        guilds,
        dm_channels,
        mailbox,
    })
}

async fn briefs(pg: &PgPool, sql: &'static str, me: i64) -> sqlx::Result<Vec<AccountBrief>> {
    let rows = sqlx::query(sql).bind(me).fetch_all(pg).await?;
    rows.iter()
        .map(|r| {
            Ok(AccountBrief {
                id: r.try_get("id")?,
                username: r.try_get("username")?,
                identity_key: r
                    .try_get::<Option<String>, _>("identity_key")?
                    .unwrap_or_default(),
                online: false,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

async fn write_loop(mut sink: SplitSink<WebSocket, WsMessage>, mut rx: mpsc::Receiver<WsMessage>) {
    while let Some(msg) = rx.recv().await {
        if sink.send(msg).await.is_err() {
            break; // socket is gone; remaining frames are dropped
        }
    }
    let _ = sink.send(WsMessage::Close(None)).await;
}

fn text_msg(msg: WsServerMsg) -> WsMessage {
    WsMessage::Text(
        serde_json::to_string(&msg)
            .expect("WsServerMsg always serializes")
            .into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscription_names_cover_direct_and_channel_topics() {
        let set = subscription_names(7, &[10, 11, 10]);
        assert_eq!(set.len(), 3, "duplicates collapse");
        assert!(set.contains("acct:7"));
        assert!(set.contains("chan:10"));
        assert!(set.contains("chan:11"));
    }

    #[test]
    fn text_msg_serializes_envelope() {
        let frame = text_msg(WsServerMsg {
            id: None,
            body: WsServerBody::Presence {
                account_id: 2,
                online: true,
            },
        });
        match frame {
            WsMessage::Text(txt) => {
                let parsed: WsServerMsg = serde_json::from_str(txt.as_str()).expect("valid json");
                assert_eq!(
                    parsed.body,
                    WsServerBody::Presence {
                        account_id: 2,
                        online: true
                    }
                );
                assert_eq!(parsed.id, None);
            }
            other => panic!("expected text frame, got {other:?}"),
        }
    }
}

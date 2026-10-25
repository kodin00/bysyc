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
//!    [bus forwarder task] --msgpack frames--> [out mpsc] --> [writer task] --> socket
//!    [connection loop] ----direct replies------^
//!    ```
//!
//!    Every frame to the client is written by the writer task alone, in
//!    order, so `Ready` precedes any pub/sub event.
//! 4. **Event delivery — shared subscriber workers.** Instead of one Redis
//!    pub/sub connection per WebSocket connection, a small pool of workers
//!    (`WS_EVENT_WORKERS`, default 4; spawned once in `main`) owns every
//!    Redis subscription in the process. Connections are homed
//!    round-robin to one worker; that worker's single Redis connection
//!    holds the union of its homed connections' topics, so a connection
//!    sees its every topic (`acct:{me}` plus `chan:{c}` for each channel
//!    `me` can read — recomputed at connect, on every client `Heartbeat`,
//!    and after a successful `VoiceJoin`) arrive on one ordered stream,
//!    preserving cross-topic publish order exactly like the old
//!    per-connection subscriber did. Topic sets are refcounted per worker
//!    in the [`EventBus`]; a worker's first holder of a topic subscribes
//!    it, its last holder out unsubscribes. Workers forward
//!    `(topic, payload)` pairs into per-worker `tokio::sync::broadcast`
//!    rings (transcoding each JSON payload to a binary MessagePack frame
//!    once, so every connection homed on the worker reuses the same frame
//!    bytes); each connection's forwarder task filters its home ring by its
//!    own topics and forwards the frame verbatim. A connection that lags the
//!    ring simply misses events — backfill is `GET /channels/{id}/messages`.
//!    A client that just joined a Guild or opened a DM should send a
//!    `Heartbeat` to start receiving the new channel's events (the beat
//!    resyncs subscriptions immediately — pub/sub delivery starts only once
//!    the topic is subscribed, so a deferred sync would drop events).
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
//! - `Typing` readability is answered from the connection's cached channel
//!   set (refreshed on every resync) with a DB fallback for channels not
//!   yet in the cache; membership revoked between resyncs can therefore
//!   still emit `Typing` until the next heartbeat.
//! - A topic with readers on several workers is subscribed once per such
//!   worker (at most `WS_EVENT_WORKERS` Redis-side copies, constant — not
//!   one per connection); per-connection event ordering is unaffected
//!   (every topic a connection reads rides that connection's home
//!   worker's single Redis stream).
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
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::response::Response;
use axum::routing::get;
use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use redis::aio::ConnectionManager;
use sqlx::{PgPool, Row};
use tokio::sync::{Mutex, broadcast, mpsc};

use bysyc_common::PROTOCOL_VERSION;
use bysyc_common::protocol::{
    AccountBrief, AccountInfo, ChannelInfo, ChannelKind, DmChannel, ErrorCode, GuildInfo,
    MailboxItem, WsClientBody, WsClientMsg, WsServerBody, WsServerMsg, decode_ws_client_msg,
    encode_ws_server_msg,
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
/// Broadcast ring size for the shared event bus; also the per-connection
/// lag allowance before events start being skipped.
const EVENT_BUS_CAPACITY: usize = 1024;
/// Worker command queue depth per subscriber worker. Workers drain commands
/// even while reconnecting, so a deep queue only matters for Redis outages.
const WORKER_CMD_QUEUE: usize = 256;
/// How long teardown waits for the forwarder to release its bus topics
/// before aborting it (a wedged writer could otherwise stall it mid-send).
const FORWARDER_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

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
// Shared event bus (replaces one Redis pub/sub connection per connection)
// ---------------------------------------------------------------------------

/// One gateway event as the workers forward it: the Redis topic it was
/// published to plus the already-encoded binary `WsMessage` frame. The
/// payload arrives from [`crate::events`] as a JSON `WsServerMsg`; the
/// worker transcodes it once (see [`event_frame`]) so every connection homed
/// there shares the same frame bytes — the forwarder never re-encodes.
/// `Arc` on the topic and on the event itself keeps broadcast fan-out to
/// refcount bumps (the frame clones as a `Bytes` refcount bump).
struct BusEvent {
    topic: Arc<str>,
    frame: WsMessage,
}

/// Transcode one Redis pub/sub payload — the JSON `WsServerMsg` published by
/// [`crate::events`] — into the gateway's binary MessagePack frame.
/// Returns `None` (and logs) for a payload that does not parse: only this
/// process's publishers write these topics, so that is a bug, not a client
/// error.
fn event_frame(payload: &str) -> Option<WsMessage> {
    match serde_json::from_str::<WsServerMsg>(payload) {
        Ok(msg) => Some(WsMessage::Binary(encode_ws_server_msg(&msg).into())),
        Err(e) => {
            tracing::warn!("ignoring undecodable pub/sub payload: {e}");
            None
        }
    }
}

/// Topic-management command from the registry to one subscriber worker.
#[derive(Debug)]
enum WorkerCmd {
    /// The topic gained its first interested connection on this worker.
    Add(Arc<str>),
    /// The topic lost its last interested connection on this worker.
    Remove(Arc<str>),
}

/// The process-wide fan-out point between Redis pub/sub and every live
/// gateway connection. Connections are sharded round-robin over a small
/// pool of subscriber workers; each worker owns ONE Redis pub/sub
/// connection holding the union of its homed connections' topics and feeds
/// its own broadcast ring. Because every topic a connection cares about
/// rides that single Redis connection, the connection observes events in
/// Redis publish order — the per-connection ordering the old
/// one-subscriber-per-connection design gave, which clients rely on (e.g. a
/// Megolm session share published to `acct:{id}` must arrive before the
/// message it unlocks on `chan:{id}`).
struct EventBus {
    /// Per worker: command channel + that worker's broadcast ring.
    workers: Vec<WorkerHandle>,
    /// Per worker: live topic -> holder count (connections homed there).
    /// Guarded by the bus's tokio Mutex; every operation is a HashMap
    /// touch plus (rarely) queueing a worker command.
    registry: Mutex<Vec<HashMap<Arc<str>, usize>>>,
    next_worker: std::sync::atomic::AtomicUsize,
}

struct WorkerHandle {
    cmd_tx: mpsc::Sender<WorkerCmd>,
    events: broadcast::Sender<Arc<BusEvent>>,
}

/// AppState/router state are owned by other files, so the bus rides in a
/// module static installed by [`start_event_bus`] from `main` before the
/// listener binds.
static EVENT_BUS: OnceLock<EventBus> = OnceLock::new();

/// Start `workers` shared subscriber workers and install the process-wide
/// bus. No-op if called twice.
pub(crate) fn start_event_bus(redis_url: &str, workers: usize) {
    if EVENT_BUS.get().is_some() {
        return;
    }
    let (bus, worker_rxs) = EventBus::with_workers(workers);
    for (id, cmd_rx) in worker_rxs.into_iter().enumerate() {
        let ring = bus.workers[id].events.clone();
        tokio::spawn(run_event_worker(redis_url.to_owned(), id, cmd_rx, ring));
    }
    let _ = EVENT_BUS.set(bus);
}

fn event_bus() -> Option<&'static EventBus> {
    EVENT_BUS.get()
}

impl EventBus {
    fn with_workers(workers: usize) -> (Self, Vec<mpsc::Receiver<WorkerCmd>>) {
        let mut handles = Vec::with_capacity(workers);
        let mut worker_rxs = Vec::with_capacity(workers);
        let mut registry = Vec::with_capacity(workers);
        for _ in 0..workers.max(1) {
            let (cmd_tx, cmd_rx) = mpsc::channel(WORKER_CMD_QUEUE);
            let (events, _) = broadcast::channel(EVENT_BUS_CAPACITY);
            handles.push(WorkerHandle { cmd_tx, events });
            worker_rxs.push(cmd_rx);
            registry.push(HashMap::new());
        }
        (
            Self {
                workers: handles,
                registry: Mutex::new(registry),
                next_worker: std::sync::atomic::AtomicUsize::new(0),
            },
            worker_rxs,
        )
    }

    /// Home worker for a new connection (round-robin).
    fn assign(&self) -> usize {
        let n = self.workers.len();
        self.next_worker
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % n
    }

    /// This connection's view of its home worker's stream; filtering by
    /// topic is the forwarder's job (it owns the topic set).
    fn events(&self, worker: usize) -> broadcast::Receiver<Arc<BusEvent>> {
        self.workers[worker].events.subscribe()
    }

    /// Move one connection homed at `worker` from `current` topics to
    /// `desired`: the worker's first holder of a topic subscribes it on its
    /// Redis connection, its last holder out unsubscribes. An unchanged set
    /// is a no-op (digest short-circuit). `current` is updated to
    /// `desired` on completion.
    async fn set_topics(
        &self,
        worker: usize,
        current: &mut HashSet<Arc<str>>,
        desired: HashSet<Arc<str>>,
    ) {
        if *current == desired {
            return;
        }
        let mut cmds: Vec<WorkerCmd> = Vec::new();
        {
            let mut registry = self.registry.lock().await;
            let topics = &mut registry[worker];
            for topic in desired.difference(&*current) {
                let holders = topics.entry(Arc::clone(topic)).or_insert(0);
                *holders += 1;
                if *holders == 1 {
                    cmds.push(WorkerCmd::Add(Arc::clone(topic)));
                }
            }
            for topic in current.difference(&desired) {
                if let Some(holders) = topics.get_mut(topic) {
                    *holders -= 1;
                    if *holders == 0 {
                        topics.remove(topic);
                        cmds.push(WorkerCmd::Remove(Arc::clone(topic)));
                    }
                }
            }
        }
        let cmd_tx = self.workers[worker].cmd_tx.clone();
        for cmd in cmds {
            // Only fails if the worker task is gone; workers never exit on
            // their own (they outlive every connection by design).
            if let Err(e) = cmd_tx.send(cmd).await {
                tracing::error!("event worker command dropped: {e}");
            }
        }
        *current = desired;
    }
}

/// One shared Redis pub/sub connection holding the union of the topics its
/// homed connections care about. Mirrors the old per-connection
/// subscriber's resilience: reconnects with backoff and re-establishes its
/// whole held set, keeps accepting topic commands while disconnected (they
/// apply on reconnect), and forwards every received payload into its
/// broadcast ring verbatim.
async fn run_event_worker(
    redis_url: String,
    id: usize,
    mut cmd_rx: mpsc::Receiver<WorkerCmd>,
    bus_tx: broadcast::Sender<Arc<BusEvent>>,
) {
    let client = match redis::Client::open(redis_url.as_str()) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("invalid redis url for pub/sub: {e}");
            return;
        }
    };

    let mut held: HashSet<Arc<str>> = HashSet::new();
    let mut backoff = Duration::from_secs(1);
    loop {
        let mut pubsub = match client.get_async_pubsub().await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(id, "pub/sub connect failed, retrying in {backoff:?}: {e}");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(30));
                continue;
            }
        };
        backoff = Duration::from_secs(1);

        // (Re)establish this worker's entire held set after a (re)connect.
        if !held.is_empty() {
            let all: Vec<&str> = held.iter().map(|t| t.as_ref()).collect();
            if let Err(e) = pubsub.subscribe(all).await {
                tracing::warn!(id, "pub/sub resubscribe failed: {e}");
                continue;
            }
        }

        loop {
            // The message stream mutably borrows `pubsub` (and is not
            // Unpin — hence the pin). Binding it per iteration and dropping
            // it before the handlers run lets the command handlers retake
            // the connection between iterations.
            let mut messages = Box::pin(pubsub.on_message());
            let step = tokio::select! {
                cmd = cmd_rx.recv() => Step::Cmd(cmd),
                msg = messages.next() => Step::Msg(msg),
            };
            drop(messages);
            match step {
                Step::Cmd(Some(WorkerCmd::Add(topic))) => {
                    // Record intent first so a failed subscribe is healed
                    // by the reconnect's full resubscribe.
                    held.insert(Arc::clone(&topic));
                    if let Err(e) = pubsub.subscribe(topic.as_ref()).await {
                        tracing::warn!(id, "pub/sub subscribe failed, reconnecting: {e}");
                        break;
                    }
                }
                Step::Cmd(Some(WorkerCmd::Remove(topic))) => {
                    held.remove(&topic);
                    if let Err(e) = pubsub.unsubscribe(topic.as_ref()).await {
                        tracing::warn!(id, "pub/sub unsubscribe failed, reconnecting: {e}");
                        break;
                    }
                }
                Step::Cmd(None) => return, // bus is gone: process shutdown
                Step::Msg(Some(m)) => {
                    let topic = Arc::from(m.get_channel_name());
                    if let Ok(payload) = m.get_payload::<String>()
                        && let Some(frame) = event_frame(&payload)
                    {
                        // A send error just means no live receivers right
                        // now — the publish already happened, move on.
                        let _ = bus_tx.send(Arc::new(BusEvent { topic, frame }));
                    }
                }
                Step::Msg(None) => {
                    tracing::warn!(id, "pub/sub stream ended, reconnecting");
                    break;
                }
            }
        }
    }
}

/// One resolved event of the worker loop (avoids borrowing `pubsub` inside
/// the select handlers).
enum Step {
    Cmd(Option<WorkerCmd>),
    Msg(Option<redis::Msg>),
}

/// Per-connection pump between its home worker's broadcast ring and the
/// writer task: owns this connection's refcounted share of the worker's
/// topics, filters the ring down to them, and forwards payloads verbatim.
/// Exits — releasing every held topic — when the connection loop drops
/// `sub_tx` or the writer goes away.
async fn run_bus_forwarder(
    bus: &'static EventBus,
    home: usize,
    mut sub_rx: mpsc::Receiver<HashSet<Arc<str>>>,
    out_tx: mpsc::Sender<WsMessage>,
) {
    let mut events = bus.events(home);
    let mut held: HashSet<Arc<str>> = HashSet::new();
    loop {
        tokio::select! {
            desired = sub_rx.recv() => match desired {
                Some(desired) => bus.set_topics(home, &mut held, desired).await,
                None => {
                    bus.set_topics(home, &mut held, HashSet::new()).await;
                    return;
                }
            },
            event = events.recv() => match event {
                Ok(event) => {
                    if held.contains(event.topic.as_ref())
                        && out_tx.send(event.frame.clone()).await.is_err()
                    {
                        bus.set_topics(home, &mut held, HashSet::new()).await;
                        return; // writer gone -> connection over
                    }
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    // Drop-if-lagging is the bus policy: a connection this
                    // far behind catches up via `GET /channels/{id}/messages`.
                    tracing::debug!("gateway event bus lagged, skipped {skipped} events");
                }
                Err(broadcast::error::RecvError::Closed) => return,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Connection body
// ---------------------------------------------------------------------------

/// Per-connection gateway state: the channel set behind both the
/// subscription topics and the `Typing` fast path. Everything here is
/// derived; the DB stays the source of truth at every resync.
struct ConnState {
    me: i64,
    /// Channels `me` could read as of the last successful resync (`None`
    /// until then — `Typing` falls back to the DB check).
    channels: Option<HashSet<i64>>,
}

impl ConnState {
    fn new(me: i64) -> Self {
        Self { me, channels: None }
    }

    /// Cached readability answer, or `None` when unknown (no cache yet, or
    /// no entry for this channel — e.g. joined after the last resync).
    /// Negative answers are never cached: a channel the DB says we cannot
    /// read may become readable before the next resync.
    fn channel_readable(&self, channel: i64) -> Option<bool> {
        self.channels.as_ref().map(|set| set.contains(&channel))
    }

    /// Cache a DB-confirmed readable channel so later keystrokes skip the
    /// DB until the next resync recomputes the whole set.
    fn remember_readable(&mut self, channel: i64) {
        self.channels
            .get_or_insert_with(HashSet::new)
            .insert(channel);
    }
}

async fn run_connected(state: &AppState, socket: WebSocket, me: i64) -> Result<(), ApiError> {
    // 0. Sweep stale voice participation. After a server crash/restart,
    //    voice_participants rows for me survive (the old socket never ran
    //    disconnect_cleanup), so others still see me in Calls. Clear them
    //    now and publish the fresh snapshot per affected channel — the
    //    empty participant list is the clients' "Call ended" signal.
    //    Best-effort: log on failure and still proceed to presence/Ready.
    match sqlx::query_scalar::<_, i64>(
        "DELETE FROM voice_participants WHERE account_id = $1 RETURNING channel_id",
    )
    .bind(me)
    .fetch_all(&state.pg)
    .await
    {
        Ok(channels) => {
            for channel_id in channels {
                crate::voice::publish_channel_snapshot(state, channel_id).await;
            }
        }
        Err(e) => tracing::warn!(me, "stale voice participant sweep failed: {e:#}"),
    }

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
        .send(frame_msg(WsServerMsg {
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

    let Some(bus) = event_bus() else {
        return Err(ApiError::internal(
            "event bus not started (start_event_bus must run in main before serving)",
        ));
    };
    let (sub_tx, sub_rx) = mpsc::channel::<HashSet<Arc<str>>>(4);
    let home = bus.assign();
    let mut forwarder = tokio::spawn(run_bus_forwarder(bus, home, sub_rx, out_tx.clone()));
    let mut conn = ConnState::new(me);
    resync_now(state, &mut conn, &sub_tx).await;

    let (sink, mut stream) = socket.split();
    let writer = tokio::spawn(write_loop(sink, out_rx));

    // 4. Main loop: socket reader and the presence safety tick.
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
                Some(Ok(WsMessage::Binary(data))) => {
                    let decoded =
                        decode_ws_client_msg(&data).map_err(|e| format!("malformed message: {e}"));
                    handle_client_msg(state, &sub_tx, &out, me, decoded, &mut conn).await;
                }
                // Pre-v2 clients spoke JSON text frames; the read side still
                // accepts them (every reply is MessagePack either way).
                Some(Ok(WsMessage::Text(txt))) => {
                    let decoded = serde_json::from_str::<WsClientMsg>(txt.as_str())
                        .map_err(|e| format!("malformed message: {e}"));
                    handle_client_msg(state, &sub_tx, &out, me, decoded, &mut conn).await;
                }
                Some(Ok(WsMessage::Close(_))) => break,
                Some(Err(e)) => {
                    tracing::debug!(me, "socket read error: {e}");
                    break;
                }
                // Pings are answered by axum itself.
                Some(Ok(_)) => {}
            },
        }
    }

    // 5. Teardown: dropping `sub_tx` tells the forwarder to release its
    //    bus topics and exit (bounded wait: a wedged writer could otherwise
    //    stall it mid-send), then let the writer drain and close.
    drop(sub_tx);
    drop(out);
    drop(out_tx);
    if tokio::time::timeout(FORWARDER_DRAIN_TIMEOUT, &mut forwarder)
        .await
        .is_err()
    {
        forwarder.abort();
        tracing::warn!(
            me,
            "event forwarder did not drain; its bus topics were leaked"
        );
    }
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

    // Leave every Call in one statement. An account can be in multiple
    // voice channels (the PK is (channel_id, account_id)), so the old
    // per-channel voice::leave loop paid one DELETE + one snapshot SELECT
    // + one publish per channel. One DELETE ... RETURNING collapses the
    // deletes; per affected channel we publish the fresh VoiceState
    // snapshot (the empty list is the "Call ended" signal). Best-effort
    // publish, like the old leave.
    match sqlx::query_scalar::<_, i64>(
        "DELETE FROM voice_participants WHERE account_id = $1 RETURNING channel_id",
    )
    .bind(me)
    .fetch_all(&state.pg)
    .await
    {
        Ok(channels) => {
            for channel_id in channels {
                crate::voice::publish_channel_snapshot(state, channel_id).await;
            }
        }
        Err(e) => tracing::warn!(me, "voice cleanup query failed: {e:#}"),
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
    sub_tx: &mpsc::Sender<HashSet<Arc<str>>>,
    out: &mpsc::Sender<WsMessage>,
    me: i64,
    decoded: Result<WsClientMsg, String>,
    conn: &mut ConnState,
) {
    let msg: WsClientMsg = match decoded {
        Ok(m) => m,
        Err(e) => {
            send_error(out, None, ErrorCode::InvalidRequest, e);
            return;
        }
    };

    match msg.body {
        WsClientBody::Heartbeat => {
            // Refresh liveness and re-sync the subscription set: this is
            // the documented sync point after joining a guild / opening a
            // DM (see module docs). The resync runs immediately — events on
            // a freshly readable channel start flowing only once its topic
            // is subscribed, so a deferred sync would drop them.
            if let Err(e) = set_presence(&state.redis, me).await {
                tracing::warn!(me, "presence refresh failed: {e}");
            }
            resync_now(state, conn, sub_tx).await;
        }
        WsClientBody::Typing { channel_id } => {
            // Fast path: the connection's channel set (recomputed at
            // connect, every heartbeat resync, and voice joins) already
            // proves readability. Only unknown channels pay a DB check —
            // typically a join that has not seen its first post-join
            // heartbeat yet, and a confirmed read is cached back so the
            // rest of the burst is free.
            let allowed = match conn.channel_readable(channel_id) {
                Some(true) => true,
                _ => match crate::messages::can_read(&state.pg, me, channel_id).await {
                    Ok(false) => false,
                    Ok(true) => {
                        conn.remember_readable(channel_id);
                        true
                    }
                    Err(e) => {
                        tracing::error!(me, "typing membership check failed: {e:#}");
                        send_error(out, Some(msg.id), ErrorCode::Internal, "database error");
                        return;
                    }
                },
            };
            if allowed {
                if let Err(e) = crate::events::publish_to_channel(
                    &state.redis_events,
                    channel_id,
                    WsServerBody::Typing {
                        channel_id,
                        account_id: me,
                    },
                )
                .await
                {
                    tracing::warn!(me, channel_id, "typing fan-out failed: {e}");
                }
            } else {
                send_error(
                    out,
                    Some(msg.id),
                    ErrorCode::Forbidden,
                    "not a member of this channel",
                );
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
                        .send(frame_msg(WsServerMsg {
                            body: WsServerBody::VoiceState {
                                channel_id,
                                participants,
                            },
                        }))
                        .await;
                    // Pick up subscriptions in case the call sits in a
                    // freshly opened DM the heartbeat has not synced yet.
                    resync_now(state, conn, sub_tx).await;
                }
                Err(e) => send_error(out, Some(msg.id), e.code, e.message),
            }
        }
        WsClientBody::VoiceLeave => {
            // The wire message carries no channel id; the PK is
            // (channel_id, account_id) so an account can be in multiple
            // channels. Delete ALL of them and publish the fresh snapshot
            // per affected channel — mirroring disconnect_cleanup. A 0-row
            // delete is a no-op (not in any Call: no error, no event).
            match sqlx::query_scalar::<_, i64>(
                "DELETE FROM voice_participants WHERE account_id = $1 RETURNING channel_id",
            )
            .bind(me)
            .fetch_all(&state.pg)
            .await
            {
                Ok(channels) => {
                    for channel_id in channels {
                        crate::voice::publish_channel_snapshot(state, channel_id).await;
                    }
                    // The updated VoiceState reaches the leaver through
                    // their still-active chan:{id} subscription.
                }
                Err(e) => {
                    tracing::warn!(me, "voice leave query failed: {e:#}");
                    send_error(out, Some(msg.id), ErrorCode::Internal, "database error");
                }
            }
        }
        WsClientBody::CallSignal { call_id, to, kind } => {
            if let Err(e) = crate::voice::relay_signal(state, call_id, me, to, kind).await {
                send_error(out, Some(msg.id), e.code, e.message);
            }
        }
        // `WsClientBody` is `#[non_exhaustive]` with a `#[serde(other)] Unknown`
        // fallback; the wire contract is "server logs and ignores, never errors
        // for an unknown tag", so unknown variants (and any future variant this
        // version does not know) are dropped here without a reply.
        _ => tracing::debug!(me, "ignoring unrecognized ws client body"),
    }
}

/// Run one subscription resync. On failure the cached channel set is left
/// untouched so the next heartbeat retries.
async fn resync_now(
    state: &AppState,
    conn: &mut ConnState,
    sub_tx: &mpsc::Sender<HashSet<Arc<str>>>,
) {
    if let Err(e) = sync_subscriptions(state, conn, sub_tx).await {
        tracing::warn!(conn.me, "subscription resync failed: {e:#}");
    }
}

fn send_error(
    out: &mpsc::Sender<WsMessage>,
    reply_to: Option<u64>,
    code: ErrorCode,
    message: impl Into<String>,
) {
    let msg = WsServerMsg {
        body: WsServerBody::Error {
            reply_to,
            code,
            message: message.into(),
        },
    };
    // try_send: never block the reader on a stalled client; if the queue
    // is full the socket is wedged anyway.
    let _ = out.try_send(frame_msg(msg));
}

// ---------------------------------------------------------------------------
// Subscription plumbing
// ---------------------------------------------------------------------------

/// Every channel id `me` can currently read: all channels of their guilds
/// (text AND voice — VoiceState/Typing ride the same `chan:{id}` topics)
/// plus their DM channels.
async fn my_channels(pg: &PgPool, me: i64) -> sqlx::Result<Vec<i64>> {
    sqlx::query_scalar(
        "SELECT c.id FROM channels c \
         JOIN guild_members gm ON gm.guild_id = c.guild_id \
         WHERE gm.account_id = $1 \
         UNION \
         SELECT dc.channel_id FROM dm_channels dc WHERE dc.a = $1 OR dc.b = $1",
    )
    .bind(me)
    .fetch_all(pg)
    .await
}

/// The full pub/sub topic set for an account: the directed topic plus one
/// topic per readable channel. Topic strings are identical to the ones the
/// REST publishers in [`crate::events`] PUBLISH to.
fn subscription_names(me: i64, channels: &HashSet<i64>) -> HashSet<Arc<str>> {
    let mut set = HashSet::with_capacity(channels.len() + 1);
    set.insert(Arc::from(format!("acct:{me}")));
    for c in channels {
        set.insert(Arc::from(format!("chan:{c}")));
    }
    set
}

/// Recompute the desired topic set (and the Typing fast-path cache) from
/// the database and hand the topic set to the forwarder task.
async fn sync_subscriptions(
    state: &AppState,
    conn: &mut ConnState,
    sub_tx: &mpsc::Sender<HashSet<Arc<str>>>,
) -> sqlx::Result<()> {
    let channels: HashSet<i64> = my_channels(&state.pg, conn.me).await?.into_iter().collect();
    conn.channels = Some(channels.clone());
    // A send error means the forwarder is gone, i.e. the connection is
    // already tearing down.
    let _ = sub_tx.send(subscription_names(conn.me, &channels)).await;
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
    sqlx::query_scalar(
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
    .await
}

async fn fan_out_presence(state: &AppState, me: i64, online: bool) -> Result<(), ApiError> {
    let audience = presence_audience(&state.pg, me).await?;
    // One pipelined round trip for the whole audience (see events.rs).
    if let Err(e) = crate::events::publish_to_accounts(
        &state.redis_events,
        &audience,
        WsServerBody::Presence {
            account_id: me,
            online,
        },
    )
    .await
    {
        tracing::warn!(me, "presence fan-out failed: {e}");
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

    // Wave 1: every snapshot query is independent — fan them out on the
    // pool instead of paying seven sequential round-trips. Only the
    // guild-channel and presence lookups in wave 2 depend on these results.
    let (
        account_row,
        friends_res,
        incoming_requests_res,
        outgoing_requests_res,
        guild_rows_res,
        dm_rows_res,
        mail_rows_res,
    ) = tokio::join!(
        sqlx::query(
            "SELECT id, username, identity_key, \
                    (EXTRACT(EPOCH FROM created_at) * 1000)::bigint AS created_at_ms, \
                    is_admin \
             FROM accounts WHERE id = $1",
        )
        .bind(me)
        .fetch_one(pg),
        briefs(
            pg,
            "SELECT a.id, a.username, a.identity_key \
             FROM friends f \
             JOIN accounts a ON a.id = CASE WHEN f.a = $1 THEN f.b ELSE f.a END \
             WHERE f.a = $1 OR f.b = $1",
            me,
        ),
        briefs(
            pg,
            "SELECT a.id, a.username, a.identity_key \
             FROM friend_requests fr \
             JOIN accounts a ON a.id = fr.from_id \
             WHERE fr.to_id = $1",
            me,
        ),
        briefs(
            pg,
            "SELECT a.id, a.username, a.identity_key \
             FROM friend_requests fr \
             JOIN accounts a ON a.id = fr.to_id \
             WHERE fr.from_id = $1",
            me,
        ),
        sqlx::query(
            "SELECT g.id, g.name, g.owner_id \
             FROM guilds g \
             JOIN guild_members gm ON gm.guild_id = g.id \
             WHERE gm.account_id = $1",
        )
        .bind(me)
        .fetch_all(pg),
        sqlx::query(
            "SELECT dc.channel_id, \
                    a.id AS peer_id, a.username AS peer_username, a.identity_key AS peer_key \
             FROM dm_channels dc \
             JOIN accounts a ON a.id = CASE WHEN dc.a = $1 THEN dc.b ELSE dc.a END \
             WHERE dc.a = $1 OR dc.b = $1",
        )
        .bind(me)
        .fetch_all(pg),
        sqlx::query(
            "SELECT id, sender_id, content, \
                    (EXTRACT(EPOCH FROM created_at) * 1000)::bigint AS created_at_ms \
             FROM mailbox WHERE recipient_id = $1 ORDER BY id",
        )
        .bind(me)
        .fetch_all(pg),
    );

    let row = account_row?;
    let account = AccountInfo {
        id: row.try_get("id")?,
        username: row.try_get("username")?,
        identity_key: row
            .try_get::<Option<String>, _>("identity_key")?
            .unwrap_or_default(),
        created_at_ms: row.try_get("created_at_ms")?,
        is_admin: row.try_get("is_admin")?,
    };
    let mut friends = friends_res?;
    let mut incoming_requests = incoming_requests_res?;
    let mut outgoing_requests = outgoing_requests_res?;

    let guild_rows = guild_rows_res?;
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
    let guild_ids: Vec<i64> = guilds.iter().map(|g| g.id).collect();

    let dm_rows = dm_rows_res?;
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

    let mail_rows = mail_rows_res?;
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

    // Wave 2: the guild-channel query needs the guild ids and the presence
    // probe needs the brief ids — independent of each other, so they share
    // one wait.
    let (chan_rows_res, online_res) = tokio::join!(
        async {
            if guild_ids.is_empty() {
                Ok(Vec::new())
            } else {
                sqlx::query(
                    "SELECT id, guild_id, kind, name FROM channels WHERE guild_id = ANY($1)",
                )
                .bind(&guild_ids)
                .fetch_all(pg)
                .await
            }
        },
        presence_map(&state.redis, &brief_ids),
    );
    // Build a guild_id -> index map once so per-channel attachment is O(1)
    // instead of an O(guilds.len()) linear scan per channel (the previous
    // `find` made snapshot assembly O(guilds * channels) on this loop).
    let guild_idx: HashMap<i64, usize> =
        guilds.iter().enumerate().map(|(i, g)| (g.id, i)).collect();
    for cr in chan_rows_res? {
        let guild_id: i64 = cr.try_get("guild_id")?;
        let Some(&idx) = guild_idx.get(&guild_id) else {
            continue;
        };
        guilds[idx].channels.push(ChannelInfo {
            id: cr.try_get("id")?,
            guild_id: Some(guild_id),
            kind: crate::messages::parse_channel_kind(&cr.try_get::<String, _>("kind")?)
                .ok_or_else(|| ApiError::internal("corrupt channel kind in database"))?,
            name: cr.try_get("name")?,
        });
    }
    let online = match online_res {
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

/// Encode a direct (non-bus) server frame as a binary MessagePack message —
/// the gateway's only write format since protocol v2.
fn frame_msg(msg: WsServerMsg) -> WsMessage {
    WsMessage::Binary(encode_ws_server_msg(&msg).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscription_names_cover_direct_and_channel_topics() {
        let channels = HashSet::from([10, 11]);
        let set = subscription_names(7, &channels);
        assert_eq!(set.len(), 3, "one directed + one per channel");
        assert!(set.contains("acct:7"));
        assert!(set.contains("chan:10"));
        assert!(set.contains("chan:11"));
    }

    #[test]
    fn frame_msg_encodes_msgpack_envelope() {
        let frame = frame_msg(WsServerMsg {
            body: WsServerBody::Presence {
                account_id: 2,
                online: true,
            },
        });
        match frame {
            WsMessage::Binary(data) => {
                let parsed = bysyc_common::protocol::decode_ws_server_msg(&data)
                    .expect("valid msgpack frame");
                assert_eq!(
                    parsed.body,
                    WsServerBody::Presence {
                        account_id: 2,
                        online: true,
                    }
                );
            }
            other => panic!("expected binary frame, got {other:?}"),
        }
    }

    #[test]
    fn event_frame_transcodes_pubsub_json_to_msgpack() {
        // The exact bytes `crate::events` puts on Redis (its pinned envelope).
        let payload = r#"{"body":{"presence":{"account_id":2,"online":true}}}"#;
        let frame = event_frame(payload).expect("pubsub payload transcodes");
        let WsMessage::Binary(data) = frame else {
            panic!("expected binary frame, got {frame:?}");
        };
        let parsed = bysyc_common::protocol::decode_ws_server_msg(&data).expect("decodes");
        assert_eq!(
            parsed,
            WsServerMsg {
                body: WsServerBody::Presence {
                    account_id: 2,
                    online: true,
                }
            }
        );
        assert!(event_frame("not json").is_none());
    }

    #[test]
    fn assign_is_round_robin_over_all_workers() {
        let (bus, _rxs) = EventBus::with_workers(4);
        let homes: Vec<usize> = (0..8).map(|_| bus.assign()).collect();
        assert_eq!(homes, vec![0, 1, 2, 3, 0, 1, 2, 3]);
        let (one, _rxs) = EventBus::with_workers(1);
        for _ in 0..5 {
            assert_eq!(one.assign(), 0);
        }
    }

    #[tokio::test]
    async fn typing_cache_and_membership_start_empty() {
        let conn = ConnState::new(1);
        assert_eq!(conn.channel_readable(10), None);
    }

    fn topic_set(topics: &[&str]) -> HashSet<Arc<str>> {
        topics.iter().map(|t| Arc::from(*t)).collect()
    }

    #[tokio::test]
    async fn bus_subscribes_on_first_holder_and_unsubscribes_on_last() {
        let (bus, mut worker_rxs) = EventBus::with_workers(1);
        let mut cmds = worker_rxs.remove(0);

        // First holder: everything gets subscribed.
        let desired = topic_set(&["acct:7", "chan:10"]);
        let mut first = HashSet::new();
        bus.set_topics(0, &mut first, desired.clone()).await;
        assert_eq!(first, desired);
        let mut adds = 0;
        while let Ok(cmd) = cmds.try_recv() {
            assert!(
                matches!(cmd, WorkerCmd::Add(_)),
                "expected Add, got {cmd:?}"
            );
            adds += 1;
        }
        assert_eq!(adds, 2);

        // A second holder of the same topics must not touch the worker,
        // and releasing it must not unsubscribe the first.
        let mut second = HashSet::new();
        bus.set_topics(0, &mut second, desired.clone()).await;
        assert!(cmds.try_recv().is_err(), "no worker traffic expected");
        bus.set_topics(0, &mut second, HashSet::new()).await;
        assert!(cmds.try_recv().is_err(), "no worker traffic expected");

        // An unchanged desired set short-circuits entirely.
        bus.set_topics(0, &mut first, desired.clone()).await;
        assert!(cmds.try_recv().is_err(), "no worker traffic expected");

        // Last holder out: everything gets unsubscribed.
        bus.set_topics(0, &mut first, HashSet::new()).await;
        let mut removes = 0;
        while let Ok(cmd) = cmds.try_recv() {
            assert!(
                matches!(cmd, WorkerCmd::Remove(_)),
                "expected Remove, got {cmd:?}"
            );
            removes += 1;
        }
        assert_eq!(removes, 2);
    }

    #[tokio::test]
    async fn workers_track_their_holdings_independently() {
        // The same topic homed on two workers (two connections of different
        // homes both read it) is subscribed once per worker; the rings and
        // refcounts never bleed across workers.
        let (bus, mut worker_rxs) = EventBus::with_workers(2);
        let mut cmds0 = worker_rxs.remove(0);
        let mut cmds1 = worker_rxs.remove(0);

        let desired = topic_set(&["chan:10"]);
        let mut a = HashSet::new();
        let mut b = HashSet::new();
        bus.set_topics(0, &mut a, desired.clone()).await;
        bus.set_topics(1, &mut b, desired.clone()).await;
        assert!(matches!(cmds0.try_recv(), Ok(WorkerCmd::Add(_))));
        assert!(matches!(cmds1.try_recv(), Ok(WorkerCmd::Add(_))));

        // Releasing on one worker leaves the other's subscription intact.
        bus.set_topics(0, &mut a, HashSet::new()).await;
        assert!(matches!(cmds0.try_recv(), Ok(WorkerCmd::Remove(_))));
        assert!(cmds1.try_recv().is_err(), "worker 1 must be untouched");

        bus.set_topics(1, &mut b, HashSet::new()).await;
        assert!(matches!(cmds1.try_recv(), Ok(WorkerCmd::Remove(_))));
    }
}

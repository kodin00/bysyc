//! B3: Voice channel participants + signaling relay — the full live-DB
//! flow, running by default against ephemeral testcontainers backing
//! services (no `.env`, no `#[ignore]`).
//!
//! Drives `bysyc_server::voice::{join, leave, relay_signal}` directly
//! against the AppState and asserts on:
//!
//! - The 6-participant cap (`MAX_PARTICIPANTS`): the 7th join is rejected
//!   with `VoiceChannelFull`.
//! - `leave` publishes the fresh `VoiceState` roster to `chan:{voice_id}`.
//! - The empty roster when the last participant leaves is the clients'
//!   "Call ended" signal (`VoiceState{participants: []}`).
//! - `relay_signal` authorization: both participants in a voice call, the
//!   exact pair in a DM channel, everything else `Forbidden`.
//!
//! A WS observer (a guild member who never joins a call) subscribes to
//! `chan:{voice_id}` and reads every published `VoiceState` snapshot, so
//! the assertions cover the published roster, not just the join return
//! value. The voice participants themselves are direct-DB-inserted (no
//! registration, no rate-limit budget) — only the observer registers.

mod common;

use std::time::Duration;
use tokio::time::Instant;

use bysyc_common::protocol::{
    decode_ws_server_msg, CallSignalKind, WsServerBody, WsServerMsg,
};
use bysyc_common::PROTOCOL_VERSION;
use bysyc_server::error::ApiResult;
use bysyc_server::voice::{join, leave, relay_signal, MAX_PARTICIPANTS};
use common::{mint_admin, setup};
use futures_util::StreamExt;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

/// The concrete WS stream type from `connect_async` over plain `ws://`.
type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// How long to wait for the next published VoiceState on the observer's
/// WS. Local redis pub/sub is sub-second; this leaves headroom for the
/// shared event bus's round-robin homing.
const VOICE_TIMEOUT: Duration = Duration::from_secs(10);

/// `ApiError` has no `Debug` impl (the orchestrator owns it), so
/// `Result::expect` is unavailable on `ApiResult` values in tests.
fn ok<T>(r: ApiResult<T>, what: &str) -> T {
    r.unwrap_or_else(|e| panic!("{what}: expected Ok, got {:?} ({})", e.code, e.message))
}

/// The error code from an expected-Err result (same Debug caveat as `ok`).
fn err_code<T>(r: ApiResult<T>, what: &str) -> bysyc_common::protocol::ErrorCode {
    match r {
        Ok(_) => panic!("{what}: expected Err, got Ok"),
        Err(e) => e.code,
    }
}

/// Assert the next binary frame on the observer's WS is a `VoiceState`
/// for `voice_id` whose participant ids equal `expected` (join order).
async fn expect_voice_state(
    ws: &mut WsStream,
    voice_id: i64,
    expected: &[i64],
) {
    let deadline = Instant::now() + VOICE_TIMEOUT;
    loop {
        let msg = tokio::time::timeout_at(deadline, ws.next())
            .await
            .expect("voice state timeout")
            .expect("ws stream ended")
            .expect("ws read error");
        if let Message::Binary(bytes) = msg {
            let decoded: WsServerMsg = decode_ws_server_msg(&bytes).expect("msgpack decode");
            if let WsServerBody::VoiceState {
                channel_id,
                participants,
            } = decoded.body
            {
                assert_eq!(channel_id, voice_id, "voice state for the right channel");
                let got: Vec<i64> = participants.iter().map(|p| p.id).collect();
                assert_eq!(got, expected, "voice state roster (join order)");
                return;
            }
            // Non-VoiceState frames (e.g. stray Presence) are skipped.
        }
    }
}

/// Fixture row count helper.
fn assert_participants(ps: &[bysyc_common::protocol::AccountBrief], expected: &[i64], what: &str) {
    let got: Vec<i64> = ps.iter().map(|p| p.id).collect();
    assert_eq!(got, expected, "{what}: participant ids (join order)");
}

#[tokio::test]
async fn voice_flow_against_testcontainers() {
    let h = setup().await;
    let pg = &h.state.pg;

    // The observer: an admin account (minted straight into the DB so it
    // works even on a shared, already-populated accounts table) that
    // joins the guild as a non-call member. Its WS gateway subscription
    // to chan:{voice_id} is what lets the test observe every published
    // VoiceState snapshot.
    let (observer_token, observer_id) = mint_admin(&h.state).await;

    // Seven voice participants a..g, direct-DB-inserted (no registration,
    // no rate-limit cost). The voice API keys on account_id, not on a
    // session, so these accounts never need to log in.
    let mut ids: Vec<i64> = Vec::new();
    for c in 'a'..='g' {
        let username = format!("s5_voice_test_{}", c);
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO accounts(username, password_hash, identity_key) \
             VALUES ($1, 'x', 'a2V5') RETURNING id",
        )
        .bind(&username)
        .fetch_one(pg)
        .await
        .expect("insert participant account");
        ids.push(id);
    }
    let (a, b) = (ids[0], ids[1]);
    let g = ids[6];

    // Guild owned by A, with one text and one voice channel. The observer
    // and all seven participants are members (membership is what makes the
    // observer's gateway subscribe to chan:{voice_id} and what the join
    // check requires).
    let guild_id: i64 = sqlx::query_scalar(
        "INSERT INTO guilds(name, owner_id) VALUES ('s5-voice-test', $1) RETURNING id",
    )
    .bind(a)
    .fetch_one(pg)
    .await
    .expect("insert guild");
    for id in ids.iter().chain(std::iter::once(&observer_id)) {
        sqlx::query("INSERT INTO guild_members(guild_id, account_id) VALUES ($1, $2)")
            .bind(guild_id)
            .bind(id)
            .execute(pg)
            .await
            .expect("insert guild member");
    }
    let text_id: i64 = sqlx::query_scalar(
        "INSERT INTO channels(guild_id, kind, name) VALUES ($1, 'text', 't') RETURNING id",
    )
    .bind(guild_id)
    .fetch_one(pg)
    .await
    .expect("insert text channel");
    let voice_id: i64 = sqlx::query_scalar(
        "INSERT INTO channels(guild_id, kind, name) VALUES ($1, 'voice', 'v') RETURNING id",
    )
    .bind(guild_id)
    .fetch_one(pg)
    .await
    .expect("insert voice channel");

    // A DM channel between A and B (stored normalized: a < b) for the
    // Private Call relay checks.
    sqlx::query("INSERT INTO friends(a, b) VALUES (LEAST($1,$2), GREATEST($1,$2))")
        .bind(a)
        .bind(b)
        .execute(pg)
        .await
        .expect("insert friends");
    let dm_id: i64 = sqlx::query_scalar(
        "INSERT INTO channels(guild_id, kind, name) VALUES (NULL, 'text', '') RETURNING id",
    )
    .fetch_one(pg)
    .await
    .expect("insert dm channel");
    sqlx::query(
        "INSERT INTO dm_channels(channel_id, a, b) VALUES ($1, LEAST($2,$3), GREATEST($2,$3))",
    )
    .bind(dm_id)
    .bind(a)
    .bind(b)
    .execute(pg)
    .await
    .expect("insert dm pair");

    // Connect the observer's WS gateway. The first frame is Ready; the
    // gateway's connect-time resync subscribes the observer to every
    // channel of every guild they're in (including voice_id). A short
    // settle lets the shared event bus's worker establish the Redis
    // subscription before voice publishes start.
    let observer_url =
        format!("{}?token={}&protocol={}", h.ws_url, observer_token, PROTOCOL_VERSION);
    let (mut observer, _) = connect_async(&observer_url)
        .await
        .expect("observer ws connect");
    let first = observer
        .next()
        .await
        .expect("observer stream ended")
        .expect("observer ws read");
    match first {
        Message::Binary(bytes) => {
            let decoded: WsServerMsg = decode_ws_server_msg(&bytes).expect("msgpack decode");
            assert!(matches!(decoded.body, WsServerBody::Ready { .. }));
        }
        _ => panic!("expected binary Ready frame, got {first:?}"),
    }
    tokio::time::sleep(Duration::from_millis(500)).await;

    // -- text channel is not joinable
    assert_eq!(
        err_code(join(&h.state, text_id, a).await, "text join must fail"),
        bysyc_common::protocol::ErrorCode::InvalidRequest,
    );

    // -- unknown channel
    assert_eq!(
        err_code(join(&h.state, 987_654_321, a).await, "unknown channel"),
        bysyc_common::protocol::ErrorCode::NotFound,
    );

    // -- A joins, sees themselves; observer receives the published roster.
    let ps = ok(join(&h.state, voice_id, a).await, "a joins");
    assert_participants(&ps, &[a], "a joins return value");
    expect_voice_state(&mut observer, voice_id, &[a]).await;

    // -- idempotent re-join: still one row, still publishes.
    let ps = ok(join(&h.state, voice_id, a).await, "a re-joins");
    assert_participants(&ps, &[a], "a re-joins return value");
    expect_voice_state(&mut observer, voice_id, &[a]).await;

    // -- B joins; snapshot has both, join order.
    let ps = ok(join(&h.state, voice_id, b).await, "b joins");
    assert_participants(&ps, &[a, b], "b joins return value");
    expect_voice_state(&mut observer, voice_id, &[a, b]).await;

    // -- fill to the cap (6), observer sees each snapshot grow.
    for id in &ids[2..6] {
        ok(join(&h.state, voice_id, *id).await, "filler joins");
    }
    expect_voice_state(&mut observer, voice_id, &[a, b, ids[2], ids[3], ids[4], ids[5]]).await;
    assert_eq!(MAX_PARTICIPANTS, 6, "fixture assumes a 6-participant cap");

    // -- G (the 7th) is rejected with VoiceChannelFull.
    assert_eq!(
        err_code(join(&h.state, voice_id, g).await, "must be full"),
        bysyc_common::protocol::ErrorCode::VoiceChannelFull,
    );

    // -- relay within the voice call: both participants OK.
    ok(
        relay_signal(&h.state, voice_id, a, b, CallSignalKind::Hangup).await,
        "relay between participants",
    );
    // An outsider (G, not in the call) cannot relay.
    assert_eq!(
        err_code(
            relay_signal(&h.state, voice_id, g, a, CallSignalKind::Hangup).await,
            "outsider cannot relay",
        ),
        bysyc_common::protocol::ErrorCode::Forbidden,
    );

    // -- leave frees a slot; observer sees the roster shrink by one.
    ok(leave(&h.state, voice_id, a).await, "a leaves");
    expect_voice_state(&mut observer, voice_id, &[b, ids[2], ids[3], ids[4], ids[5]]).await;

    // -- G can now join (slot freed).
    ok(join(&h.state, voice_id, g).await, "g joins after slot freed");
    expect_voice_state(&mut observer, voice_id, &[b, ids[2], ids[3], ids[4], ids[5], g]).await;

    // -- not-in-channel leave is a no-op success: no row deleted, so no
    //    VoiceState is published. The observer must NOT receive one.
    ok(leave(&h.state, voice_id, a).await, "leave while absent (no-op)");
    // Assert by negative: nothing arrives within a short window.
    let deadline = Instant::now() + Duration::from_millis(800);
    match tokio::time::timeout_at(deadline, observer.next()).await {
        Err(_) => {} // no frame — expected
        Ok(_) => panic!("no-op leave must not publish a VoiceState"),
    }

    // -- Private Call signaling in the DM: exact pair only.
    ok(
        relay_signal(&h.state, dm_id, a, b, CallSignalKind::Hangup).await,
        "dm pair relay",
    );
    ok(
        relay_signal(&h.state, dm_id, b, a, CallSignalKind::Hangup).await,
        "dm pair relay, reverse direction",
    );
    assert_eq!(
        err_code(
            relay_signal(&h.state, dm_id, a, ids[2], CallSignalKind::Hangup).await,
            "non-pair cannot relay in dm",
        ),
        bysyc_common::protocol::ErrorCode::Forbidden,
    );

    // -- Empty roster = "Call ended": leave everyone, observer sees the
    //    roster shrink step by step until the last leave publishes [].
    for id in [b, ids[2], ids[3], ids[4], ids[5], g] {
        ok(leave(&h.state, voice_id, id).await, "drain participant");
    }
    // The very last leave publishes the empty snapshot. Intermediate
    // leaves each publish a shrinking roster; the observer drains them
    // until the empty one arrives.
    let deadline = Instant::now() + VOICE_TIMEOUT;
    loop {
        let msg = tokio::time::timeout_at(deadline, observer.next())
            .await
            .expect("call-ended snapshot timeout")
            .expect("observer stream ended")
            .expect("observer ws read");
        if let Message::Binary(bytes) = msg {
            let decoded: WsServerMsg = decode_ws_server_msg(&bytes).expect("msgpack decode");
            if let WsServerBody::VoiceState {
                channel_id,
                participants,
            } = decoded.body
            {
                assert_eq!(channel_id, voice_id);
                if participants.is_empty() {
                    break; // the "Call ended" snapshot
                }
                // Otherwise it's an intermediate shrinking roster — keep
                // reading until the empty one arrives.
            }
        }
    }
}

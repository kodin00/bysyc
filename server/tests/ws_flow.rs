//! B2: WebSocket gateway round-trip — binary MessagePack frames over the
//! real axum WS upgrade. Two accounts register, both open the gateway, and
//! the test exercises the documented invariants:
//!
//! - The first frame on a connection is `Ready` (with `id: None`).
//! - A `Heartbeat` produces no `Error` reply (it only resyncs subscriptions
//!   and refreshes presence internally).
//! - A message posted via REST in a channel both sides can read is fanned
//!   out to the non-sender as `Message` with `id: None` (the sender gets
//!   the dto as the HTTP response, not over the gateway).
//! - `VoiceJoin` then `VoiceLeave` each fan out a `VoiceState` snapshot to
//!   the other participant (peer observes roster change).
//! - Dropping the socket triggers `disconnect_cleanup`: the peer receives
//!   `Presence{online:false}` (the leaver is no longer present).
//!
//! Every read is wrapped in `tokio::time::timeout` so a missing event
//! fails the test instead of hanging it.

mod common;

use std::time::Duration;
use tokio::time::Instant;

use bysyc_common::PROTOCOL_VERSION;
use bysyc_common::protocol::{
    CreateGuildInviteRequest, CreateGuildRequest, JoinGuildRequest, WsClientBody, WsClientMsg,
    WsServerBody, WsServerMsg, decode_ws_server_msg, encode_ws_client_msg,
};
use common::{mint_invite, register, setup, unique_name};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

/// The concrete WS stream type from `connect_async` over plain `ws://`.
/// Factored into an alias so helper signatures stay readable.
type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Per-read timeout: the gateway is local, so a few seconds is plenty.
const READ_TIMEOUT: Duration = Duration::from_secs(10);
/// How long to wait for a Heartbeat's non-reply: the server should not
/// produce any frame in this window (a few hundred ms covers the
/// subscription resync).
const NO_REPLY_WINDOW: Duration = Duration::from_millis(800);

/// HTTP client for the REST side of the round-trip.
fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("reqwest client")
}

/// Open the WS gateway as `token`. Returns the live stream.
async fn connect(token: &str, ws_url: &str) -> WsStream {
    let url = format!("{ws_url}?token={token}&protocol={PROTOCOL_VERSION}");
    connect_async(&url).await.expect("ws connect").0
}

/// Send one client frame.
async fn send(ws: &mut WsStream, msg: WsClientMsg) {
    ws.send(Message::Binary(encode_ws_client_msg(&msg).into()))
        .await
        .expect("ws send");
}

/// Decode the next binary frame; skips non-binary frames.
async fn next_msg(ws: &mut WsStream) -> WsServerMsg {
    let deadline = Instant::now() + READ_TIMEOUT;
    loop {
        let msg = tokio::time::timeout_at(deadline, ws.next())
            .await
            .expect("ws read timeout")
            .expect("ws stream ended")
            .expect("ws read error");
        if let Message::Binary(bytes) = msg {
            return decode_ws_server_msg(&bytes).expect("msgpack decode");
        }
        // Pings are answered by axum; Close/Pong/Text are not expected here.
    }
}

/// Read frames until one matches `pred`, skipping unrelated pushes
/// (Presence, etc.). Times out at `READ_TIMEOUT` from the first call.
async fn next_matching<F>(ws: &mut WsStream, pred: F) -> WsServerBody
where
    F: Fn(&WsServerBody) -> bool,
{
    let deadline = Instant::now() + READ_TIMEOUT;
    loop {
        let msg = tokio::time::timeout_at(deadline, ws.next())
            .await
            .expect("ws read timeout")
            .expect("ws stream ended")
            .expect("ws read error");
        if let Message::Binary(bytes) = msg {
            let decoded = decode_ws_server_msg(&bytes).expect("msgpack decode");
            if pred(&decoded.body) {
                return decoded.body;
            }
            // Otherwise keep scanning for the frame we want.
        }
    }
}

/// The first frame must be `Ready`.
fn assert_first_is_ready(msg: &WsServerMsg) {
    assert!(
        matches!(msg.body, WsServerBody::Ready { .. }),
        "first frame must be Ready"
    );
}

#[tokio::test]
async fn ws_round_trip() {
    let h = setup().await;

    // Two accounts; alice owns a guild, bob joins it so both can read the
    // shared text + voice channels.
    let invite = mint_invite(&h.state).await;
    let (alice_token, alice_id) =
        register(&h.base_url, &unique_name("ws_a"), "pw12345", &invite).await;
    let (bob_token, bob_id) = register(
        &h.base_url,
        &unique_name("ws_b"),
        "pw12345",
        &mint_invite(&h.state).await,
    )
    .await;

    let guild: serde_json::Value = http()
        .post(format!("{}/guilds", h.base_url))
        .bearer_auth(&alice_token)
        .json(&CreateGuildRequest {
            name: "ws-test".into(),
        })
        .send()
        .await
        .expect("create guild")
        .json()
        .await
        .expect("decode guild");
    let guild_id = guild["id"].as_i64().expect("guild id");
    // The two default channels: a text (lower id) and a voice channel.
    let channels = guild["channels"].as_array().expect("channels");
    let text_id = channels
        .iter()
        .find(|c| c["kind"] == "text")
        .and_then(|c| c["id"].as_i64())
        .expect("text channel id");
    let voice_id = channels
        .iter()
        .find(|c| c["kind"] == "voice")
        .and_then(|c| c["id"].as_i64())
        .expect("voice channel id");

    let ginv: serde_json::Value = http()
        .post(format!("{}/guilds/{}/invites", h.base_url, guild_id))
        .bearer_auth(&alice_token)
        .json(&CreateGuildInviteRequest {
            max_uses: None,
            ttl_secs: None,
        })
        .send()
        .await
        .expect("mint guild invite")
        .json()
        .await
        .expect("decode guild invite");
    let code = ginv["code"]
        .as_str()
        .expect("guild invite code")
        .to_string();
    let _: serde_json::Value = http()
        .post(format!("{}/guilds/join", h.base_url))
        .bearer_auth(&bob_token)
        .json(&JoinGuildRequest { code })
        .send()
        .await
        .expect("bob joins guild")
        .json()
        .await
        .expect("decode joined guild");

    // Both connect the gateway; both must see Ready first.
    let mut alice_ws = connect(&alice_token, &h.ws_url).await;
    let mut bob_ws = connect(&bob_token, &h.ws_url).await;
    assert_first_is_ready(&next_msg(&mut alice_ws).await);
    assert_first_is_ready(&next_msg(&mut bob_ws).await);

    // Heartbeat: the server resyncs subscriptions and refreshes presence
    // but must NOT send an Error. Other pushes (e.g. Presence from the
    // peer's connect) are fine — drain them, assert none is an Error.
    send(
        &mut alice_ws,
        WsClientMsg {
            id: 1,
            body: WsClientBody::Heartbeat,
        },
    )
    .await;
    let heartbeat_deadline = Instant::now() + NO_REPLY_WINDOW;
    while Instant::now() < heartbeat_deadline {
        // `ws.next()` yields Option<Result<Message, Error>>; `timeout_at`
        // wraps that in another Result<_, Elapsed>. Timeout or stream-end
        // both end the drain (no Error frame arrived); an Error frame fails.
        match tokio::time::timeout_at(heartbeat_deadline, alice_ws.next()).await {
            Err(_) => break,   // window elapsed with no frame — expected
            Ok(None) => break, // stream ended — nothing more to drain
            Ok(Some(Err(e))) => panic!("ws read error after heartbeat: {e}"),
            Ok(Some(Ok(msg))) => {
                if let Message::Binary(bytes) = msg {
                    let decoded = decode_ws_server_msg(&bytes).expect("decode");
                    if let WsServerBody::Error { code, message, .. } = decoded.body {
                        panic!("Heartbeat should not produce an Error: {code:?} — {message}");
                    }
                    // Presence/other pushes are acceptable — keep draining.
                }
            }
        }
    }

    // Bob posts a message via REST in the shared text channel; alice (a
    // subscriber of chan:{text_id}) must receive it as a `Message` push
    // with id: None (server-originated frames carry no correlation id).
    let posted: serde_json::Value = http()
        .post(format!("{}/channels/{}/messages", h.base_url, text_id))
        .bearer_auth(&bob_token)
        .json(&serde_json::json!({
            "kind": "chat",
            "content": "aGk=", // valid base64 ("hi")
            "reply_to": null,
            "attachment_id": null,
        }))
        .send()
        .await
        .expect("post message")
        .json()
        .await
        .expect("decode posted message");
    let msg_id = posted["id"].as_i64().expect("posted message id");

    let received = next_matching(&mut alice_ws, |b| matches!(b, WsServerBody::Message(_))).await;
    match received {
        WsServerBody::Message(dto) => {
            assert_eq!(dto.id, msg_id);
            assert_eq!(dto.channel_id, text_id);
            assert_eq!(dto.sender_id, bob_id, "alice must receive bob's message");
            assert_eq!(dto.content, "aGk=");
        }
        other => panic!("expected Message, got {other:?}"),
    }

    // VoiceJoin: alice joins the call; bob (a chan:{voice_id} subscriber)
    // must receive the VoiceState fan-out with alice in the roster.
    send(
        &mut alice_ws,
        WsClientMsg {
            id: 2,
            body: WsClientBody::VoiceJoin {
                channel_id: voice_id,
            },
        },
    )
    .await;
    let joined = next_matching(&mut bob_ws, |b| {
        matches!(b, WsServerBody::VoiceState { .. })
    })
    .await;
    match joined {
        WsServerBody::VoiceState {
            channel_id,
            participants,
        } => {
            assert_eq!(channel_id, voice_id);
            assert_eq!(participants.len(), 1);
            assert_eq!(participants[0].id, alice_id);
        }
        other => panic!("expected VoiceState after join, got {other:?}"),
    }

    // VoiceLeave: alice leaves; bob must receive the empty roster (the
    // "Call ended" snapshot).
    send(
        &mut alice_ws,
        WsClientMsg {
            id: 3,
            body: WsClientBody::VoiceLeave,
        },
    )
    .await;
    let left = next_matching(
        &mut bob_ws,
        |b| matches!(b, WsServerBody::VoiceState { participants, .. } if participants.is_empty()),
    )
    .await;
    match left {
        WsServerBody::VoiceState {
            channel_id,
            participants,
        } => {
            assert_eq!(channel_id, voice_id);
            assert!(
                participants.is_empty(),
                "leaving the only participant ends the call"
            );
        }
        other => panic!("expected empty VoiceState after leave, got {other:?}"),
    }

    // Disconnect: drop alice's socket. The server's disconnect_cleanup
    // fans out Presence{online:false} to alice's audience (bob is a guild
    // co-member), so bob must receive the offline push.
    drop(alice_ws);
    let offline = next_matching(&mut bob_ws, |b| {
        matches!(b, WsServerBody::Presence { account_id, online } if *account_id == alice_id && !online)
    }).await;
    match offline {
        WsServerBody::Presence { account_id, online } => {
            assert_eq!(account_id, alice_id);
            assert!(!online, "disconnect must publish offline presence");
        }
        other => panic!("expected Presence{{alice, false}} after disconnect, got {other:?}"),
    }
}

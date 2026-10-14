//! Networking: the REST client ([`Net`]), the realtime gateway loop
//! ([`run_ws`]), and the clone-able [`NetHandle`] the rest of the client
//! uses for both.
//!
//! # REST surface (contract for the server crate)
//!
//! Paths pinned by `common/src/protocol.rs` are followed exactly:
//!
//! - `POST /friends/requests` `{"account_id":<i64>}` · `POST
//!   /friends/requests/{id}/accept` · `POST /friends/requests/{id}/decline`
//!   · `DELETE /friends/{id}`
//! - `GET /channels/{id}/messages?before=<id>&limit=<n>` ([`MessagePage`])
//! - `GET /attachments/{id}/download-url` ([`DownloadUrlResponse`])
//! - `GET /ws?token=...&protocol=1` (WebSocket)
//!
//! The paths below are the client's assumed contract for endpoints whose
//! routes the server crate still owns (server modules are stubs at the time
//! of writing); they all live in this one file so realignment is one-line:
//!
//! | Method & path | Purpose |
//! |---|---|
//! | `POST /auth/register` | [`RegisterRequest`] → [`TokenResponse`] |
//! | `POST /auth/login` | [`LoginRequest`] → [`TokenResponse`] |
//! | `POST /auth/logout` | invalidate the session token |
//! | `GET /auth/me` | [`AccountInfo`] (session validation) |
//! | `GET /accounts/by-username/{username}` | username lookup → [`AccountBrief`] |
//! | `GET /friends` | [`FriendList`] |
//! | `POST /keys/otk` | [`UploadOtkRequest`] |
//! | `POST /keys/claim` | `{"account_id":<i64>}` → [`ClaimedKeys`] |
//! | `GET /guilds` | `Vec<`[`GuildInfo`]`>` |
//! | `POST /guilds` | [`CreateGuildRequest`] → [`GuildInfo`] |
//! | `POST /guilds/{id}/channels` | [`CreateChannelRequest`] → [`ChannelInfo`] |
//! | `DELETE /channels/{id}` | delete a channel |
//! | `POST /guilds/{id}/invites` | [`CreateGuildInviteRequest`] → [`GuildInviteDto`] |
//! | `POST /guilds/join` | [`JoinGuildRequest`] → [`GuildInfo`] |
//! | `GET /dms` | `Vec<`[`DmChannel`]`>` |
//! | `POST /dms` | [`OpenDmRequest`] → [`DmChannel`] |
//! | `POST /channels/{id}/messages` | [`SendMessageRequest`] → [`MessageDto`] |
//! | `GET /mailbox` | `Vec<`[`MailboxItem`]`>` |
//! | `POST /attachments` | [`CreateAttachmentRequest`] → [`CreateAttachmentResponse`] |
//! | `GET /turn` | [`TurnInfo`] for C5's calls |
//!
//! Errors: every failing REST response is parsed as [`ApiError`] and the
//! human-readable `message` is surfaced (as `Err(String)`); a body that is
//! not `ApiError` degrades to `Err("HTTP <status>")`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bysyc_common::PROTOCOL_VERSION;
use bysyc_common::protocol::{
    ApiError, ClaimedKeys, CreateAttachmentRequest, CreateAttachmentResponse, CreateChannelRequest,
    CreateGuildInviteRequest, CreateGuildRequest, DmChannel, DownloadUrlResponse, ErrorCode,
    FriendList, GuildInfo, GuildInviteDto, JoinGuildRequest, LoginRequest, MailboxItem, MessageDto,
    MessagePage, OpenDmRequest, RegisterRequest, SendMessageRequest, TokenResponse,
    UploadOtkRequest, WsClientBody, WsClientMsg, WsServerBody, WsServerMsg,
};
use eframe::egui::Context;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::state::{ClientState, Phase, apply_server_msg, guard};
use crate::store::Store;

/// Placeholder identity key uploaded at registration until C2 (crypto)
/// replaces it with the real vodozemac identity — base64 of
/// "placeholder-identity", non-empty so servers that validate presence pass.
pub const PLACEHOLDER_IDENTITY_KEY: &str = "cGxhY2Vob2xkZXItaWRlbnRpdHk=";

/// TURN relay info served by the Instance for C5's WebRTC calls. Client-side
/// shape (belongs in `common` once S5 pins it).
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TurnInfo {
    /// STUN/TURN URLs, e.g. `turn:host:3478`.
    pub urls: Vec<String>,
    /// TURN credentials when the relay requires them.
    pub username: Option<String>,
    pub credential: Option<String>,
}

static MSG_ID: AtomicU64 = AtomicU64::new(1);

/// Next client-chosen correlation id for [`WsClientMsg`].
pub fn next_msg_id() -> u64 {
    MSG_ID.fetch_add(1, Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// REST
// ---------------------------------------------------------------------------

/// HTTP client for one Instance. Cheap to clone (`reqwest::Client` inside);
/// the token is the caller's session token.
#[derive(Clone)]
pub struct Net {
    base: String,
    token: String,
    http: reqwest::Client,
}

impl Net {
    /// Unauthenticated client (register/login).
    pub fn new(base: &str) -> Self {
        Net {
            base: base.trim().trim_end_matches('/').to_string(),
            token: String::new(),
            http: reqwest::Client::new(),
        }
    }

    /// Client carrying a session token for all calls.
    pub fn authenticated(base: &str, token: &str) -> Self {
        Net {
            token: token.to_string(),
            ..Net::new(base)
        }
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    /// Request builder with the bearer token attached when present.
    fn authed(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let b = self.http.request(method, self.url(path));
        if self.token.is_empty() {
            b
        } else {
            b.bearer_auth(&self.token)
        }
    }

    /// Send a request, map any failure to a human-readable string.
    async fn exec<T: serde::de::DeserializeOwned>(
        &self,
        builder: reqwest::RequestBuilder,
    ) -> Result<T, String> {
        let resp = builder.send().await.map_err(|e| format!("network: {e}"))?;
        let status = resp.status();
        let bytes = resp.bytes().await.map_err(|e| format!("network: {e}"))?;
        if !status.is_success() {
            if let Ok(api) = serde_json::from_slice::<ApiError>(&bytes) {
                return Err(api.message);
            }
            return Err(format!("HTTP {}", status.as_u16()));
        }
        serde_json::from_slice(&bytes).map_err(|e| format!("bad response: {e}"))
    }

    // -- auth --------------------------------------------------------------

    pub async fn register(&self, req: &RegisterRequest) -> Result<TokenResponse, String> {
        self.exec(self.http.post(self.url("/auth/register")).json(req))
            .await
    }

    pub async fn login(&self, req: &LoginRequest) -> Result<TokenResponse, String> {
        self.exec(self.http.post(self.url("/auth/login")).json(req))
            .await
    }

    pub async fn logout(&self) -> Result<(), String> {
        self.exec(self.authed(reqwest::Method::POST, "/auth/logout"))
            .await
    }

    pub async fn me(&self) -> Result<bysyc_common::protocol::AccountInfo, String> {
        self.exec(self.authed(reqwest::Method::GET, "/auth/me"))
            .await
    }

    /// Resolve a username to its [`AccountBrief`] (client-assumed endpoint —
    /// needed because friend requests take an account id).
    pub async fn lookup_username(
        &self,
        username: &str,
    ) -> Result<bysyc_common::protocol::AccountBrief, String> {
        self.exec(self.authed(
            reqwest::Method::GET,
            &format!("/accounts/by-username/{username}"),
        ))
        .await
    }

    // -- friends -----------------------------------------------------------

    pub async fn friends(&self) -> Result<FriendList, String> {
        self.exec(self.authed(reqwest::Method::GET, "/friends"))
            .await
    }

    pub async fn send_friend_request(&self, account_id: i64) -> Result<(), String> {
        self.exec(
            self.authed(reqwest::Method::POST, "/friends/requests")
                .json(&serde_json::json!({ "account_id": account_id })),
        )
        .await
    }

    pub async fn accept_friend_request(&self, account_id: i64) -> Result<(), String> {
        self.exec(self.authed(
            reqwest::Method::POST,
            &format!("/friends/requests/{account_id}/accept"),
        ))
        .await
    }

    pub async fn decline_friend_request(&self, account_id: i64) -> Result<(), String> {
        self.exec(self.authed(
            reqwest::Method::POST,
            &format!("/friends/requests/{account_id}/decline"),
        ))
        .await
    }

    pub async fn remove_friend(&self, account_id: i64) -> Result<(), String> {
        self.exec(self.authed(reqwest::Method::DELETE, &format!("/friends/{account_id}")))
            .await
    }

    // -- keys (Olm prekeys, C2) ---------------------------------------------

    pub async fn upload_otks(&self, req: &UploadOtkRequest) -> Result<(), String> {
        self.exec(self.authed(reqwest::Method::POST, "/keys/otk").json(req))
            .await
    }

    pub async fn claim_otk(&self, account_id: i64) -> Result<ClaimedKeys, String> {
        self.exec(
            self.authed(reqwest::Method::POST, "/keys/claim")
                .json(&serde_json::json!({ "account_id": account_id })),
        )
        .await
    }

    // -- guilds / channels ---------------------------------------------------

    pub async fn guilds(&self) -> Result<Vec<GuildInfo>, String> {
        self.exec(self.authed(reqwest::Method::GET, "/guilds"))
            .await
    }

    pub async fn create_guild(&self, req: &CreateGuildRequest) -> Result<GuildInfo, String> {
        self.exec(self.authed(reqwest::Method::POST, "/guilds").json(req))
            .await
    }

    pub async fn create_channel(
        &self,
        guild_id: i64,
        req: &CreateChannelRequest,
    ) -> Result<bysyc_common::protocol::ChannelInfo, String> {
        self.exec(
            self.authed(
                reqwest::Method::POST,
                &format!("/guilds/{guild_id}/channels"),
            )
            .json(req),
        )
        .await
    }

    pub async fn delete_channel(&self, channel_id: i64) -> Result<(), String> {
        self.exec(self.authed(reqwest::Method::DELETE, &format!("/channels/{channel_id}")))
            .await
    }

    pub async fn create_guild_invite(
        &self,
        guild_id: i64,
        req: &CreateGuildInviteRequest,
    ) -> Result<GuildInviteDto, String> {
        self.exec(
            self.authed(
                reqwest::Method::POST,
                &format!("/guilds/{guild_id}/invites"),
            )
            .json(req),
        )
        .await
    }

    pub async fn join_guild(&self, req: &JoinGuildRequest) -> Result<GuildInfo, String> {
        self.exec(self.authed(reqwest::Method::POST, "/guilds/join").json(req))
            .await
    }

    // -- DMs -----------------------------------------------------------------

    pub async fn dms(&self) -> Result<Vec<DmChannel>, String> {
        self.exec(self.authed(reqwest::Method::GET, "/dms")).await
    }

    pub async fn open_dm(&self, req: &OpenDmRequest) -> Result<DmChannel, String> {
        self.exec(self.authed(reqwest::Method::POST, "/dms").json(req))
            .await
    }

    // -- messages --------------------------------------------------------------

    pub async fn channel_messages(
        &self,
        channel_id: i64,
        before: Option<i64>,
        limit: u32,
    ) -> Result<MessagePage, String> {
        let mut path = format!("/channels/{channel_id}/messages?limit={limit}");
        if let Some(b) = before {
            path.push_str(&format!("&before={b}"));
        }
        self.exec(self.authed(reqwest::Method::GET, &path)).await
    }

    pub async fn send_channel_message(
        &self,
        channel_id: i64,
        req: &SendMessageRequest,
    ) -> Result<MessageDto, String> {
        self.exec(
            self.authed(
                reqwest::Method::POST,
                &format!("/channels/{channel_id}/messages"),
            )
            .json(req),
        )
        .await
    }

    // -- mailbox (C2 acks) -------------------------------------------------------

    pub async fn mailbox(&self) -> Result<Vec<MailboxItem>, String> {
        self.exec(self.authed(reqwest::Method::GET, "/mailbox"))
            .await
    }

    // -- attachments --------------------------------------------------------------

    pub async fn create_attachment(
        &self,
        req: &CreateAttachmentRequest,
    ) -> Result<CreateAttachmentResponse, String> {
        self.exec(self.authed(reqwest::Method::POST, "/attachments").json(req))
            .await
    }

    pub async fn attachment_download_url(
        &self,
        attachment_id: i64,
    ) -> Result<DownloadUrlResponse, String> {
        self.exec(self.authed(
            reqwest::Method::GET,
            &format!("/attachments/{attachment_id}/download-url"),
        ))
        .await
    }

    // -- calls (C5) ------------------------------------------------------------------

    pub async fn turn_info(&self) -> Result<TurnInfo, String> {
        self.exec(self.authed(reqwest::Method::GET, "/turn")).await
    }
}

/// Send one message to a channel. Shared by the composer and (later) control
/// messages C2/C3 queue through the same path.
pub async fn send_message(
    net: &Net,
    channel_id: i64,
    req: &SendMessageRequest,
) -> Result<MessageDto, String> {
    net.send_channel_message(channel_id, req).await
}

// ---------------------------------------------------------------------------
// NetHandle
// ---------------------------------------------------------------------------

/// Clone-able handle for every part of the client that talks to the
/// Instance: `out` queues [`WsClientMsg`]s (typing, mailbox acks, voice
/// join/leave, call signals) — they are delivered on the current socket and
/// buffered while reconnecting — and `net` is the REST client.
#[derive(Clone)]
pub struct NetHandle {
    pub out: mpsc::Sender<WsClientMsg>,
    pub net: Net,
}

// ---------------------------------------------------------------------------
// WebSocket gateway
// ---------------------------------------------------------------------------

/// Derive the WS gateway URL from the REST base URL, percent-encoding the
/// token (tokens are opaque and may contain URL-sensitive bytes).
pub fn ws_url_from_base(base: &str, token: &str) -> String {
    let trimmed = base.trim().trim_end_matches('/');
    let host = if let Some(h) = trimmed.strip_prefix("https://") {
        format!("wss://{h}")
    } else if let Some(h) = trimmed.strip_prefix("http://") {
        format!("ws://{h}")
    } else {
        format!("ws://{trimmed}")
    };
    format!(
        "{host}/ws?token={}&protocol={PROTOCOL_VERSION}",
        pct_encode(token)
    )
}

fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Create the outgoing queue + [`NetHandle`], then spawn [`run_ws`] on the
/// runtime. The returned task runs until the session's generation is bumped
/// (logout or a superseding login).
pub fn spawn_ws(
    rt: &tokio::runtime::Handle,
    state: Arc<Mutex<ClientState>>,
    store: Arc<Mutex<Store>>,
    ctx: Context,
    base: String,
    token: String,
) -> tokio::task::JoinHandle<()> {
    let (tx, rx) = mpsc::channel::<WsClientMsg>(256);
    let handle = NetHandle {
        out: tx,
        net: Net::authenticated(&base, &token),
    };
    let generation = guard(&state).ws_generation;
    rt.spawn(run_ws(
        state, store, ctx, base, token, generation, handle, rx,
    ))
}

/// Whether this loop is still the session's WS task.
fn alive(state: &Arc<Mutex<ClientState>>, generation: u64) -> bool {
    let st = guard(state);
    st.ws_generation == generation && !matches!(st.phase, Phase::Disconnected)
}

/// Surface reconnect status without dropping the logged-in world.
fn set_connecting(state: &Arc<Mutex<ClientState>>, ctx: &Context, msg: String) {
    let mut st = guard(state);
    match &mut st.phase {
        Phase::LoggedIn(m) => m.connection = crate::state::ConnStatus::Reconnecting(msg),
        Phase::Connecting(s) => *s = msg,
        Phase::Disconnected => {}
    }
    drop(st);
    ctx.request_repaint();
}

/// Tear the session down everywhere on auth failure: local state first (the
/// generation bump stops this loop), then the keychain.
fn sign_out_everywhere(state: &Arc<Mutex<ClientState>>, ctx: &Context, reason: &str) {
    let username = {
        let mut st = guard(state);
        let u = st.main().map(|m| m.account.username.clone());
        st.sign_out_local(reason);
        u
    };
    if let Some(u) = username {
        crate::store::keyring_delete(&u);
    }
    ctx.request_repaint();
}

/// The realtime gateway task: connect → apply `Ready` → stream deltas,
/// reconnecting forever with exponential backoff (1 s → 30 s cap). Queued
/// outgoing messages are drained once a socket is up. On reconnects the
/// friend graph and guild list are re-GET-ed as a cheap resync.
#[allow(clippy::too_many_arguments)]
pub async fn run_ws(
    state: Arc<Mutex<ClientState>>,
    store: Arc<Mutex<Store>>,
    ctx: Context,
    base: String,
    token: String,
    generation: u64,
    handle: NetHandle,
    mut outgoing: mpsc::Receiver<WsClientMsg>,
) {
    let net = handle.net.clone();
    let mut backoff = Duration::from_secs(1);
    let mut first_connect = true;

    loop {
        if !alive(&state, generation) {
            return;
        }
        let url = ws_url_from_base(&base, &token);
        match tokio_tungstenite::connect_async(url.as_str()).await {
            Ok((stream, _response)) => {
                backoff = Duration::from_secs(1);
                let (mut write, mut read) = stream.split();
                let mut heartbeat = tokio::time::interval(Duration::from_secs(30));
                heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                heartbeat.tick().await; // the first tick completes immediately

                let session: Result<(), String> = loop {
                    tokio::select! {
                        biased;
                        _ = heartbeat.tick() => {
                            let msg = WsClientMsg { id: next_msg_id(), body: WsClientBody::Heartbeat };
                            match serde_json::to_string(&msg) {
                                Ok(text) => {
                                    if write.send(tokio_tungstenite::tungstenite::Message::text(text))
                                        .await
                                        .is_err()
                                    {
                                        break Err("write failed".into());
                                    }
                                }
                                Err(_) => unreachable!("WsClientMsg is always serializable"),
                            }
                            if !alive(&state, generation) {
                                return;
                            }
                        }
                        queued = outgoing.recv() => {
                            match queued {
                                Some(msg) => {
                                    if let Ok(text) = serde_json::to_string(&msg) {
                                        if write.send(tokio_tungstenite::tungstenite::Message::text(text))
                                            .await
                                            .is_err()
                                        {
                                            break Err("write failed".into());
                                        }
                                    }
                                }
                                // All NetHandles dropped (session torn down).
                                None => return,
                            }
                        }
                        frame = read.next() => {
                            match frame {
                                None | Some(Err(_)) => break Err("connection lost".into()),
                                Some(Ok(msg)) => match msg {
                                    tokio_tungstenite::tungstenite::Message::Text(text) => {
                                        match serde_json::from_str::<WsServerMsg>(&text) {
                                            Ok(msg) => {
                                                if let WsServerBody::Error {
                                                    code: ErrorCode::Unauthorized,
                                                    message,
                                                    ..
                                                } = &msg.body
                                                {
                                                    let reason =
                                                        message.clone();
                                                    sign_out_everywhere(&state, &ctx, &reason);
                                                    return;
                                                }
                                                if matches!(msg.body, WsServerBody::Ready { .. }) {
                                                    apply_server_msg(&state, &ctx, msg);
                                                    if let Some(m) = guard(&state).main_mut() {
                                                        m.net = Some(handle.clone());
                                                    }
                                                    if !first_connect {
                                                        resync(&net, &state).await;
                                                    }
                                                    first_connect = false;
                                                } else {
                                                    if let WsServerBody::Message(ref dto) = msg.body {
                                                        if let Ok(s) = store.lock() {
                                                            let _ = s.append_message(dto);
                                                        }
                                                    }
                                                    apply_server_msg(&state, &ctx, msg);
                                                }
                                                if !alive(&state, generation) {
                                                    return;
                                                }
                                            }
                                            Err(e) => {
                                                eprintln!("bysyc: undecodable ws frame: {e}")
                                            }
                                        }
                                    }
                                    tokio_tungstenite::tungstenite::Message::Close(_) => {
                                        break Err("closed by server".into());
                                    }
                                    // Ping/Pong are answered by the transport
                                    // itself; binary frames are not part of
                                    // the protocol.
                                    _ => {}
                                },
                            }
                        }
                    }
                };
                let _ = session;
                if !alive(&state, generation) {
                    return;
                }
                set_connecting(&state, &ctx, "connection lost — reconnecting…".into());
            }
            Err(err) => {
                if !alive(&state, generation) {
                    return;
                }
                let text = format!("{err}");
                // Auth was pre-validated over REST; a 401/403 here means the
                // token was revoked server-side — stop retrying.
                if text.contains("401") || text.contains("403") {
                    sign_out_everywhere(&state, &ctx, "Session expired — sign in again");
                    return;
                }
                set_connecting(&state, &ctx, format!("reconnecting: {err}"));
            }
        }
        ctx.request_repaint();
        tokio::time::sleep(backoff).await;
        backoff = std::cmp::min(backoff * 2, Duration::from_secs(30));
    }
}

/// Cheap reconnect resync: fresh friend graph + guild list over REST.
async fn resync(net: &Net, state: &Arc<Mutex<ClientState>>) {
    if let Ok(fl) = net.friends().await {
        if let Some(m) = guard(state).main_mut() {
            m.resync_friends(fl);
        }
    }
    if let Ok(guilds) = net.guilds().await {
        if let Some(m) = guard(state).main_mut() {
            m.resync_guilds(guilds);
        }
    }
}

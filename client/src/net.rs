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
//! - `GET /ws?token=...&protocol=2` (WebSocket; frames are binary MessagePack)
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
//! | `POST /auth/invites` | admin-only: mint a single-use registration invite → `{ "code": <string> }` |
//! | `GET /accounts/by-username/{username}` | username lookup → [`AccountBrief`] |
//! | `GET /friends` | [`FriendList`] |
//! | `PUT /keys/identity` | `{"identity_key":<b64>}` → 204 (keep the published key fresh) |
//! | `POST /keys/otk` | [`UploadOtkRequest`] → 204 |
//! | `GET /keys/{account_id}` | atomically claim one OTK → [`ClaimedKeys`] |
//! | `POST /mailbox` | `{"to":<i64>,"content":<b64>}` → 204 (directed Olm items) |
//! | `GET /guilds` | `Vec<`[`GuildInfo`]`>` |
//! | `POST /guilds` | [`CreateGuildRequest`] → [`GuildInfo`] |
//! | `POST /guilds/{id}/channels` | [`CreateChannelRequest`] → [`ChannelInfo`] |
//! | `DELETE /channels/{id}` | delete a channel |
//! | `POST /guilds/{id}/invites` | [`CreateGuildInviteRequest`] → [`GuildInviteDto`] |
//! | `POST /guilds/join` | [`JoinGuildRequest`] → [`GuildInfo`] |
//! | `GET /dms` | `Vec<`[`DmChannel`]`>` |
//! | `POST /dms` | [`OpenDmRequest`] → [`DmChannel`] |
//! | `POST /channels/{id}/messages` | [`SendMessageRequest`] → [`MessageDto`] |
//! | `DELETE /channels/{id}/messages/{id}` | delete a message → 204 (every member is told via a WS `MessageDeleted` broadcast) |
//! | `GET /mailbox` | `Vec<`[`MailboxItem`]`>` |
//! | `POST /attachments` | [`CreateAttachmentRequest`] → [`CreateAttachmentResponse`] |
//! | `POST /attachments/image` | raw WebP body → [`ImageUploadResponse`] (server-side images) |
//! | `GET /turn` | [`TurnInfo`] for C5's calls |
//!
//! Errors: every failing REST response is parsed as [`ApiError`] and the
//! human-readable `message` is surfaced (as `Err(String)`); a body that is
//! not `ApiError` degrades to `Err("HTTP <status>")`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use bysyc_common::PROTOCOL_VERSION;
use bysyc_common::protocol::{
    ApiError, ChannelKind, ClaimedKeys, CreateAttachmentRequest, CreateAttachmentResponse,
    CreateChannelRequest, CreateGuildInviteRequest, CreateGuildRequest, DmChannel,
    DownloadUrlResponse, ErrorCode, FriendList, GuildInfo, GuildInviteDto, JoinGuildRequest,
    LoginRequest, MailboxItem, MessageDto, MessagePage, OpenDmRequest, RegisterRequest,
    SendMessageRequest, TokenResponse, TurnInfo, UploadOtkRequest, WsClientBody, WsClientMsg,
    WsServerBody, decode_ws_server_msg, encode_ws_client_msg,
};
use eframe::egui::Context;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;

use crate::crypto::Engine;
use crate::state::{ClientState, Phase, apply_server_msg, guard};
use crate::store::Store;

static MSG_ID: AtomicU64 = AtomicU64::new(1);

/// Next client-chosen correlation id for [`WsClientMsg`].
pub fn next_msg_id() -> u64 {
    MSG_ID.fetch_add(1, Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// REST
// ---------------------------------------------------------------------------

/// The one HTTP pool every [`Net`] shares (login, session restore, WS
/// resync calls, background key publishes). Minting a `reqwest::Client`
/// per call site would give each its own connection pool and TLS session
/// cache, so the app would re-handshake with the Instance per flow; the
/// token is attached per request instead, so sharing never shares auth.
static HTTP: OnceLock<Arc<reqwest::Client>> = OnceLock::new();

fn shared_http() -> Arc<reqwest::Client> {
    HTTP.get_or_init(|| Arc::new(reqwest::Client::new())).clone()
}

/// HTTP client for one Instance. Cheap to clone (`reqwest::Client` inside);
/// the token is the caller's session token.
#[derive(Clone)]
pub struct Net {
    base: String,
    token: String,
    http: Arc<reqwest::Client>,
}

impl Net {
    /// Unauthenticated client (register/login).
    pub fn new(base: &str) -> Self {
        Net {
            base: base.trim().trim_end_matches('/').to_string(),
            token: String::new(),
            http: shared_http(),
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

    /// [`Net::exec`] for endpoints that answer `204 No Content` (logout, key
    /// uploads, mailbox posts): nothing is parsed from the empty body.
    async fn exec_empty(&self, builder: reqwest::RequestBuilder) -> Result<(), String> {
        let resp = builder.send().await.map_err(|e| format!("network: {e}"))?;
        let status = resp.status();
        let bytes = resp.bytes().await.map_err(|e| format!("network: {e}"))?;
        if !status.is_success() {
            if let Ok(api) = serde_json::from_slice::<ApiError>(&bytes) {
                return Err(api.message);
            }
            return Err(format!("HTTP {}", status.as_u16()));
        }
        Ok(())
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
        self.exec_empty(self.authed(reqwest::Method::POST, "/auth/logout"))
            .await
    }

    pub async fn me(&self) -> Result<bysyc_common::protocol::AccountInfo, String> {
        self.exec(self.authed(reqwest::Method::GET, "/auth/me"))
            .await
    }

    /// Admin-only: mint a single-use registration invite code. Returns the
    /// bare code; non-admin callers get a 403 from the server.
    pub async fn create_invite(&self) -> Result<String, String> {
        let v: serde_json::Value =
            self.exec(self.authed(reqwest::Method::POST, "/auth/invites")).await?;
        v.get("code")
            .and_then(|c| c.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| "invite response missing code".into())
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
        // The server answers with the refreshed FriendList; the world is
        // updated from the WS events instead, so only error-check the body.
        self.exec::<serde_json::Value>(
            self.authed(reqwest::Method::POST, "/friends/requests")
                .json(&serde_json::json!({ "account_id": account_id })),
        )
        .await
        .map(|_| ())
    }

    pub async fn accept_friend_request(&self, account_id: i64) -> Result<(), String> {
        self.exec::<serde_json::Value>(self.authed(
            reqwest::Method::POST,
            &format!("/friends/requests/{account_id}/accept"),
        ))
        .await
        .map(|_| ())
    }

    pub async fn decline_friend_request(&self, account_id: i64) -> Result<(), String> {
        self.exec::<serde_json::Value>(self.authed(
            reqwest::Method::POST,
            &format!("/friends/requests/{account_id}/decline"),
        ))
        .await
        .map(|_| ())
    }

    pub async fn remove_friend(&self, account_id: i64) -> Result<(), String> {
        self.exec(self.authed(reqwest::Method::DELETE, &format!("/friends/{account_id}")))
            .await
    }

    // -- keys (Olm prekeys, C2/C3) --------------------------------------------

    /// Keep the Instance's copy of our identity key fresh (`PUT
    /// /keys/identity`, 204). Done after every login/register alongside the
    /// OTK upload; registration also carries the key in its body.
    pub async fn put_identity(&self, identity_key: &str) -> Result<(), String> {
        self.exec_empty(
            self.authed(reqwest::Method::PUT, "/keys/identity")
                .json(&serde_json::json!({ "identity_key": identity_key })),
        )
        .await
    }

    pub async fn upload_otks(&self, req: &UploadOtkRequest) -> Result<(), String> {
        self.exec_empty(self.authed(reqwest::Method::POST, "/keys/otk").json(req))
            .await
    }

    /// Claim a peer's identity key plus one one-time prekey. Destructive on
    /// the server: the OTK (if any) is handed out at most once.
    pub async fn claim_otk(&self, account_id: i64) -> Result<ClaimedKeys, String> {
        self.exec(self.authed(reqwest::Method::GET, &format!("/keys/{account_id}")))
            .await
    }

    // -- mailbox (directed Olm items) -----------------------------------------

    /// Queue one directed ciphertext item (a Megolm `SessionShare` in an Olm
    /// envelope) for a peer, online or offline (`POST /mailbox`, 204).
    pub async fn post_mailbox(&self, to: i64, content: &str) -> Result<(), String> {
        self.exec_empty(
            self.authed(reqwest::Method::POST, "/mailbox")
                .json(&serde_json::json!({ "to": to, "content": content })),
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

    /// Delete one of my messages. The server answers `204` and broadcasts a
    /// `MessageDeleted` to every member (including us — the local removal
    /// done at send time just makes it instant, and is idempotent).
    pub async fn delete_message(&self, channel_id: i64, message_id: i64) -> Result<(), String> {
        self.exec_empty(
            self.authed(
                reqwest::Method::DELETE,
                &format!("/channels/{channel_id}/messages/{message_id}"),
            ),
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

    /// Upload a server-side (NOT client-encrypted) image: the raw WebP
    /// bytes are the request body — no multipart, no query parameters. The
    /// server validates the RIFF/WEBP magic bytes, stores the bytes under
    /// its own random name, and answers with the attachment metadata
    /// (`encrypted == false`, empty nonce); there is no presigned PUT for
    /// this path.
    pub async fn upload_image(
        &self,
        webp_bytes: &[u8],
    ) -> Result<bysyc_common::protocol::ImageUploadResponse, String> {
        self.exec(
            self.authed(reqwest::Method::POST, "/attachments/image")
                .header(reqwest::header::CONTENT_TYPE, "image/webp")
                .body(webp_bytes.to_vec()),
        )
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

/// Publish the engine's identity key and a batch of one-time prekeys to the
/// Instance. Called once per login (and per session restore); failures are
/// logged, not fatal — peers can still reach us with previously uploaded keys.
pub async fn publish_keys(net: &Net, engine: &Arc<Engine>) {
    if let Err(e) = net.put_identity(&engine.identity_key()).await {
        eprintln!("bysyc: identity key upload failed: {e}");
    }
    let otks = engine.uploadable_otks(10);
    if !otks.is_empty() {
        if let Err(e) = net
            .upload_otks(&UploadOtkRequest {
                one_time_keys: otks,
            })
            .await
        {
            eprintln!("bysyc: one-time key upload failed: {e}");
        }
    }
}

// ---------------------------------------------------------------------------
// Megolm session bootstrap (the C3 send path's network half)
// ---------------------------------------------------------------------------

/// Share the current outbound Megolm session of `channel_id` with `peer_ids`:
/// claim each peer's identity key + one OTK, wrap the session key
/// (`Engine::share_envelopes`), and mailbox each Olm envelope. Also refreshes
/// [`crate::state::MainState::identities`] from the claim responses.
///
/// Order matters (see the engine docs): this runs *before*
/// [`Engine::drain_pending_shares`], so a creation/rotation share still
/// carries its index-0 key. Returns how many peers received the share.
pub async fn share_session_with_peers(
    state: &Arc<Mutex<ClientState>>,
    engine: &Arc<Engine>,
    net: &Net,
    channel_id: i64,
    peer_ids: Vec<i64>,
) -> usize {
    let mut with_keys: Vec<(i64, String, Option<(String, String)>)> = Vec::new();
    for peer in &peer_ids {
        match net.claim_otk(*peer).await {
            Ok(claimed) => {
                {
                    let mut st = guard(state);
                    if let Some(m) = st.main_mut() {
                        m.identities.insert(*peer, claimed.identity_key.clone());
                    }
                }
                let otk = claimed
                    .one_time_key
                    .as_deref()
                    .and_then(|s| s.split_once(':'))
                    .map(|(id, key)| (id.to_string(), key.to_string()));
                with_keys.push((*peer, claimed.identity_key, otk));
            }
            Err(e) => eprintln!("bysyc: claiming keys for peer {peer} failed: {e}"),
        }
    }

    let envelopes = engine.share_envelopes(channel_id, &with_keys);
    let mut delivered = 0usize;
    for (peer, ciphertext) in envelopes {
        match net.post_mailbox(peer, &ciphertext).await {
            Ok(()) => delivered += 1,
            Err(e) => eprintln!("bysyc: mailing session share to peer {peer} failed: {e}"),
        }
    }

    // Must be empty after a successful share loop; leftovers mean a share
    // nobody received (the queue is persisted, so the next send retries it).
    let leftover = engine.drain_pending_shares();
    if !leftover.is_empty() {
        eprintln!(
            "bysyc: {} pending megolm share(s) undelivered for channel {channel_id} \
             (will re-share on the next send)",
            leftover.len()
        );
    }
    delivered
}

/// Persist the outbound-Megolm channel set to the local store (drives
/// newcomer sharing after a restart).
pub fn persist_outbound(state: &Arc<Mutex<ClientState>>, store: &Arc<Mutex<Store>>) {
    let set = {
        let st = guard(state);
        st.main().map(|m| m.outbound.clone()).unwrap_or_default()
    };
    let s = guard(store);
    if let Err(e) = s.save_outbound_channels(&set) {
        eprintln!("bysyc: persisting outbound channel set failed: {e}");
    }
}

/// Share every guild text channel we hold an outbound session for with a
/// member who just joined, so they can decrypt from their join point onward
/// (ADR 0001). Spawned by [`drain_followups`] on `MemberJoined`.
async fn share_to_newcomer(
    state: Arc<Mutex<ClientState>>,
    store: Arc<Mutex<Store>>,
    net: Net,
    guild_id: i64,
    member: i64,
) {
    let (engine, channels) = {
        let st = guard(&state);
        let Some(m) = st.main() else { return };
        let Some(engine) = m.engine.clone() else {
            return;
        };
        let Some(g) = m.guilds.iter().find(|g| g.id == guild_id) else {
            return;
        };
        let channels: Vec<i64> = g
            .channels
            .iter()
            .filter(|c| c.kind == ChannelKind::Text && m.outbound.contains(&c.id))
            .map(|c| c.id)
            .collect();
        (engine, channels)
    };
    for ch in channels {
        share_session_with_peers(&state, &engine, &net, ch, vec![member]).await;
        persist_outbound(&state, &store);
    }
}

/// Act on follow-up work [`apply_server_msg`] queued: mailbox acks
/// (`AckMailbox`), and session shares for guild newcomers. Runs after every
/// applied server message inside the WS loop.
pub fn drain_followups(
    state: &Arc<Mutex<ClientState>>,
    store: &Arc<Mutex<Store>>,
    handle: &NetHandle,
) {
    let (acks, newcomers) = {
        let mut st = guard(state);
        match st.main_mut() {
            Some(m) => (
                std::mem::take(&mut m.outbox_acks),
                std::mem::take(&mut m.pending_newcomers),
            ),
            None => (Vec::new(), Vec::new()),
        }
    };
    if !acks.is_empty() {
        let _ = handle.out.try_send(WsClientMsg {
            id: next_msg_id(),
            body: WsClientBody::AckMailbox { ids: acks },
        });
    }
    for (guild_id, member) in newcomers {
        tokio::spawn(share_to_newcomer(
            Arc::clone(state),
            Arc::clone(store),
            handle.net.clone(),
            guild_id,
            member,
        ));
    }
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

impl NetHandle {
    /// Ask the gateway to re-sync channel subscriptions now. The gateway
    /// docs make the client heartbeat the sync point after joining a guild
    /// or opening a DM; without this nudge, live events on the new channel
    /// lag behind by up to the 30 s periodic heartbeat.
    pub fn heartbeat(&self) {
        let _ = self.out.try_send(WsClientMsg {
            id: next_msg_id(),
            body: WsClientBody::Heartbeat,
        });
    }
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
/// generation bump stops this loop), then the saved token.
fn sign_out_everywhere(state: &Arc<Mutex<ClientState>>, ctx: &Context, reason: &str) {
    let username = {
        let mut st = guard(state);
        let u = st.main().map(|m| m.account.username.clone());
        st.sign_out_local(reason);
        u
    };
    if let Some(u) = username {
        crate::store::token_delete(&u);
    }
    ctx.request_repaint();
}

/// Chat frames drained off one socket before a single transactional
/// insert ([`Store::insert_message_page`]); the drain also fires on any
/// non-message frame, every heartbeat tick, and when the session ends —
/// whichever ends the burst first.
const WS_INSERT_BATCH: usize = 32;

/// Insert the WS receive-path message batch in one transaction. A
/// per-frame autocommit INSERT paid a WAL fsync per message whenever a
/// burst (history replay, a busy channel) landed.
fn flush_pending(store: &Arc<Mutex<Store>>, pending: &mut Vec<MessageDto>) {
    if pending.is_empty() {
        return;
    }
    let dtos = std::mem::take(pending);
    if let Ok(s) = store.lock() {
        if let Err(e) = s.insert_message_page(&dtos) {
            eprintln!("bysyc: caching {} ws message(s) failed: {e}", dtos.len());
        }
    }
}

/// ±30% spread on each reconnect sleep: every client dropped by the same
/// Instance restart would otherwise retry in lockstep.
fn jittered(d: Duration) -> Duration {
    use rand::RngExt;
    d.mul_f64(rand::rng().random_range(0.7..=1.3))
}

/// A session must have carried a Ready and stayed up at least this long
/// before the reconnect backoff resets. Anything shorter keeps the backoff
/// growing, so a flapping Instance that completes the handshake and then
/// drops us is retried with real spacing instead of every second.
const MIN_SESSION_UPTIME: Duration = Duration::from_secs(10);

/// The realtime gateway task: connect → apply `Ready` → stream deltas,
/// reconnecting forever with exponential backoff (1 s → 30 s cap, each
/// sleep jittered ±30%; the backoff only resets after a session that
/// carried a Ready stayed up [`MIN_SESSION_UPTIME`]). Queued outgoing
/// messages are drained once a socket is up. On reconnects the friend
/// graph and guild list are re-GET-ed as a cheap resync.
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
                let connected_at = Instant::now();
                let mut saw_ready = false;
                let (mut write, mut read) = stream.split();
                let mut heartbeat = tokio::time::interval(Duration::from_secs(30));
                heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                heartbeat.tick().await; // the first tick completes immediately

                // Chat frames waiting for one transactional insert
                // (see `flush_pending`).
                let mut pending: Vec<MessageDto> = Vec::new();

                let session: Result<(), String> = loop {
                    tokio::select! {
                        biased;
                        _ = heartbeat.tick() => {
                            // The periodic tick also bounds how long a
                            // partial batch can sit uncached.
                            flush_pending(&store, &mut pending);
                            let msg = WsClientMsg { id: next_msg_id(), body: WsClientBody::Heartbeat };
                            if write
                                .send(tokio_tungstenite::tungstenite::Message::binary(
                                    encode_ws_client_msg(&msg),
                                ))
                                .await
                                .is_err()
                            {
                                break Err("write failed".into());
                            }
                            if !alive(&state, generation) {
                                return;
                            }
                        }
                        queued = outgoing.recv() => {
                            match queued {
                                Some(msg) => {
                                    if write
                                        .send(tokio_tungstenite::tungstenite::Message::binary(
                                            encode_ws_client_msg(&msg),
                                        ))
                                        .await
                                        .is_err()
                                    {
                                        break Err("write failed".into());
                                    }
                                }
                                // All NetHandles dropped (session torn down).
                                None => {
                                    flush_pending(&store, &mut pending);
                                    return;
                                }
                            }
                        }
                        frame = read.next() => {
                            match frame {
                                None | Some(Err(_)) => break Err("connection lost".into()),
                                Some(Ok(msg)) => match msg {
                                    tokio_tungstenite::tungstenite::Message::Binary(data) => {
                                        match decode_ws_server_msg(&data) {
                                            Ok(msg) => {
                                                if let WsServerBody::Error {
                                                    code: ErrorCode::Unauthorized,
                                                    message,
                                                    ..
                                                } = &msg.body
                                                {
                                                    flush_pending(&store, &mut pending);
                                                    let reason =
                                                        message.clone();
                                                    sign_out_everywhere(&state, &ctx, &reason);
                                                    return;
                                                }
                                                if matches!(msg.body, WsServerBody::Ready { .. }) {
                                                    saw_ready = true;
                                                    flush_pending(&store, &mut pending);
                                                    apply_server_msg(&state, &store, &ctx, msg);
                                                    if let Some(m) = guard(&state).main_mut() {
                                                        m.net = Some(handle.clone());
                                                    }
                                                    drain_followups(&state, &store, &handle);
                                                    if !first_connect {
                                                        resync(&net, &state).await;
                                                    }
                                                    first_connect = false;
                                                } else {
                                                    if let WsServerBody::Message(ref dto) = msg.body {
                                                        if dto.kind != bysyc_common::protocol::MessageKind::Control {
                                                            pending.push(dto.clone());
                                                            if pending.len() >= WS_INSERT_BATCH {
                                                                flush_pending(&store, &mut pending);
                                                            }
                                                        }
                                                    } else {
                                                        // Any other frame
                                                        // type ends the
                                                        // burst.
                                                        flush_pending(&store, &mut pending);
                                                    }
                                                    apply_server_msg(&state, &store, &ctx, msg);
                                                    drain_followups(&state, &store, &handle);
                                                }
                                                if !alive(&state, generation) {
                                                    flush_pending(&store, &mut pending);
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
                                    // itself; since protocol v2 the gateway
                                    // speaks binary MessagePack frames only,
                                    // so a text frame never arrives.
                                    _ => {}
                                },
                            }
                        }
                    }
                };
                flush_pending(&store, &mut pending);
                // A completed handshake is not a session: reset the backoff
                // only for one that carried a Ready and stayed up. A
                // connection that dies within seconds keeps the backoff
                // growing instead of resetting to 1 s per TCP success.
                if saw_ready && connected_at.elapsed() >= MIN_SESSION_UPTIME {
                    backoff = Duration::from_secs(1);
                }
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
        tokio::time::sleep(jittered(backoff)).await;
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

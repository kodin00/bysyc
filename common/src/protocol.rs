//! Wire protocol shared by the bysyc client and the server.
//!
//! This module is *the* contract between the two crates: every value that
//! crosses the network boundary is defined here exactly once so client and
//! server cannot drift.
//!
//! # Conventions
//!
//! - All entity ids (account, guild, channel, message, attachment, mailbox
//!   item, ...) are [`i64`].
//! - All timestamps are `i64` Unix epoch **milliseconds** (fields named
//!   `*_at_ms` or ending in `_ms`).
//! - All binary payloads (ciphertext, keys, nonces) travel as **base64**
//!   [`String`]s and are opaque to the server — it stores and forwards them
//!   but can never read them.
//! - Struct fields serialize as `snake_case` (serde's default). Every enum
//!   carries `#[serde(rename_all = "snake_case")]`, so variant names are
//!   lowercase (`"voice"`, `"hangup"`, `"rate_limited"`, ...).
//! - Enums use serde's default **externally tagged** representation: a unit
//!   variant is a bare string (`"heartbeat"`, `"voice_leave"`), while a
//!   struct or newtype variant is a single-key object
//!   (`{"typing":{"channel_id":10}}`, `{"message":{...}}`).
//!
//! # Versioning and the WebSocket endpoint
//!
//! Both sides speak [`crate::PROTOCOL_VERSION`]. The realtime gateway is
//! opened with
//!
//! ```text
//! GET /ws?token=<session token>&protocol=<PROTOCOL_VERSION>
//! ```
//!
//! A `protocol` query parameter that does not match is rejected with
//! [`ErrorCode::ProtocolVersion`].
//!
//! # REST error envelope
//!
//! Every failing REST response carries a JSON body of [`ApiError`]. The
//! [`ErrorCode`] -> HTTP status mapping is documented variant by variant on
//! [`ErrorCode`].
//!
//! # Endpoint quick reference
//!
//! Routes whose shape is part of this contract:
//!
//! | Method & path | Purpose | Bodies |
//! |---|---|---|
//! | `POST /friends/requests` | send a Friend Request | request JSON body `{"account_id":<i64>}` |
//! | `POST /friends/requests/{id}/accept` | accept an incoming Friend Request | — |
//! | `POST /friends/requests/{id}/decline` | decline an incoming Friend Request | — |
//! | `DELETE /friends/{id}` | remove a Friend | — |
//! | `GET /channels/{id}/messages?before=<id>&limit=50` | page channel history | [`MessagePage`] |
//! | `GET /attachments/{id}/download-url` | presigned download URL | [`DownloadUrlResponse`] |
//! | `GET /ws?token=...&protocol=1` | WebSocket gateway | [`WsClientMsg`] / [`WsServerMsg`] |
//!
//! The remaining REST routes (auth, keys, guild/channel creation, invites,
//! attachments, DMs) are owned by the server crate; the request/response
//! types below are the shared contract for them.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Basics
// ---------------------------------------------------------------------------

/// Minimal public view of an Account, used wherever another Account is
/// referenced: friend lists, presence-bearing events, voice participants,
/// friend requests (the brief describes *the other side* of the request).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AccountBrief {
    /// Account id.
    pub id: i64,
    /// Display username, unique on the Instance.
    pub username: String,
    /// Base64 public part of the Account's long-term identity keypair.
    pub identity_key: String,
    /// Whether the Account currently holds an open WebSocket connection.
    /// Only meaningful in pushes (presence); snapshots may be stale.
    pub online: bool,
}

/// The caller's own Account as returned by auth endpoints.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AccountInfo {
    /// Account id.
    pub id: i64,
    /// Display username, unique on the Instance.
    pub username: String,
    /// Base64 public part of the Account's long-term identity keypair.
    pub identity_key: String,
    /// When the Account was created, Unix epoch milliseconds.
    pub created_at_ms: i64,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Machine-readable error code carried by every REST failure (see
/// [`ApiError`]) and by [`WsServerBody::Error`] on the WebSocket.
///
/// HTTP status mapping (normative for the server):
///
/// | Variant | HTTP | Typical cause |
/// |---|---|---|
/// | [`Unauthorized`] | 401 | missing/expired/invalid session token |
/// | [`Forbidden`] | 403 | authenticated but not allowed (not a member, not the Owner, ...) |
/// | [`NotFound`] | 404 | no such id, or not visible to the caller |
/// | [`UsernameTaken`] | 400 | registration with an existing username |
/// | [`InvalidInvite`] | 400 | registration or guild-join code unknown/expired/exhausted |
/// | [`RateLimited`] | 429 | too many requests; back off and retry |
/// | [`VoiceChannelFull`] | 409 | voice channel already at the 6-participant cap |
/// | [`ProtocolVersion`] | 400 | `protocol` parameter ≠ [`crate::PROTOCOL_VERSION`] |
/// | [`InvalidRequest`] | 400 | malformed body, bad enum value, `Dm` where only text/voice allowed, ... |
/// | [`Internal`] | 500 | unexpected server fault |
///
/// [`Unauthorized`]: ErrorCode::Unauthorized
/// [`Forbidden`]: ErrorCode::Forbidden
/// [`NotFound`]: ErrorCode::NotFound
/// [`UsernameTaken`]: ErrorCode::UsernameTaken
/// [`InvalidInvite`]: ErrorCode::InvalidInvite
/// [`RateLimited`]: ErrorCode::RateLimited
/// [`VoiceChannelFull`]: ErrorCode::VoiceChannelFull
/// [`ProtocolVersion`]: ErrorCode::ProtocolVersion
/// [`InvalidRequest`]: ErrorCode::InvalidRequest
/// [`Internal`]: ErrorCode::Internal
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// 401 — missing, expired or invalid session token.
    Unauthorized,
    /// 403 — authenticated, but not permitted to do this.
    Forbidden,
    /// 404 — unknown id, or an entity the caller cannot see.
    NotFound,
    /// 400 — registration username already exists.
    UsernameTaken,
    /// 400 — Registration Invite or Guild Invite code unknown, expired, or
    /// used up.
    InvalidInvite,
    /// 429 — too many requests; the client must back off.
    RateLimited,
    /// 409 — the voice channel is already at the participant cap (6).
    VoiceChannelFull,
    /// 400 — wire protocol version mismatch.
    ProtocolVersion,
    /// 400 — the request body is malformed or semantically invalid.
    InvalidRequest,
    /// 500 — unexpected server-side failure.
    Internal,
}

/// The JSON body of every failing REST response.
///
/// ```json
/// { "code": "unauthorized", "message": "session token expired" }
/// ```
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ApiError {
    /// Machine-readable error classification; determines the HTTP status
    /// (see [`ErrorCode`]).
    pub code: ErrorCode,
    /// Human-readable explanation, safe to show in logs and UI toasts.
    pub message: String,
}

// ---------------------------------------------------------------------------
// Auth REST
// ---------------------------------------------------------------------------

/// Body of the registration endpoint. Creating an Account requires a
/// admin-issued Registration Invite (see `CONTEXT.md`).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RegisterRequest {
    /// Desired username; taken usernames yield [`ErrorCode::UsernameTaken`].
    pub username: String,
    /// Password (the Instance stores only its hash).
    pub password: String,
    /// Registration Invite code issued by the Instance administrator.
    pub invite_code: String,
    /// Base64 public part of the device-generated long-term identity
    /// keypair. Uploaded once at registration; the private half never
    /// leaves the device.
    pub identity_key: String,
}

/// Body of the login endpoint.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct LoginRequest {
    /// Username to sign in.
    pub username: String,
    /// Password.
    pub password: String,
}

/// Successful auth response (registration and login alike).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TokenResponse {
    /// Opaque session token. Presented by the client on REST calls and as
    /// the `token` query parameter of the `GET /ws` upgrade.
    pub token: String,
    /// The freshly authenticated Account.
    pub account: AccountInfo,
}

// ---------------------------------------------------------------------------
// Keys REST (Olm prekey bootstrap)
// ---------------------------------------------------------------------------

/// Batch-upload of Olm one-time prekeys (base64 public parts) so peers can
/// start an encrypted DM while this Account is offline.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct UploadOtkRequest {
    /// Base64 one-time prekey public parts to pool on the server.
    pub one_time_keys: Vec<String>,
}

/// Result of claiming a peer's one-time key. Claiming is destructive:
/// the server hands an OTK out at most once and deletes it immediately
/// after, so each successful claim yields a key no other session ever sees.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ClaimedKeys {
    /// Base64 identity key of the claimed-from Account.
    pub identity_key: String,
    /// One claimed one-time prekey, or `None` when the peer's OTK pool is
    /// empty (the caller falls back to session establishment without a
    /// one-time key).
    pub one_time_key: Option<String>,
}

// ---------------------------------------------------------------------------
// Friends REST
// ---------------------------------------------------------------------------

/// Full friend-graph snapshot for the caller.
///
/// Friend Requests are represented by an [`AccountBrief`] of *the other
/// side*: entries in `incoming` are Accounts that want to befriend the
/// caller; entries in `outgoing` are Accounts the caller has asked.
///
/// The mutating operations are REST-only (no dedicated DTOs):
///
/// - `POST /friends/requests` with JSON body `{"account_id":<i64>}` — send a
///   Friend Request.
/// - `POST /friends/requests/{id}/accept` — accept; `id` is the *other*
///   Account's id. Both sides become Friends and both are pushed
///   [`WsServerBody::FriendRequestAccepted`] / may open a DM.
/// - `POST /friends/requests/{id}/decline` — decline (or cancel an outgoing
///   request); `id` is the other Account's id.
/// - `DELETE /friends/{id}` — remove an existing Friend; the other side is
///   pushed [`WsServerBody::FriendRemoved`].
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FriendList {
    /// Accepted friendships, both directions active.
    pub friends: Vec<AccountBrief>,
    /// Pending requests addressed to the caller (brief = requester).
    pub incoming: Vec<AccountBrief>,
    /// Pending requests sent by the caller (brief = recipient).
    pub outgoing: Vec<AccountBrief>,
}

// ---------------------------------------------------------------------------
// Guilds and channels REST
// ---------------------------------------------------------------------------

/// The two shapes a Channel can take. `Dm` exists only on channels the
/// server itself creates for DMs; clients may create only `Text` and
/// `Voice` ([`CreateChannelRequest`] with `Dm` yields
/// [`ErrorCode::InvalidRequest`]).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ChannelKind {
    /// Text Channel: Messages (Megolm-encrypted).
    Text,
    /// Voice Channel: hosts a Call (full-mesh WebRTC, max 6 participants).
    Voice,
    /// Direct-message channel between exactly two Friends; server-created
    /// only (see [`DmChannel`] / [`OpenDmRequest`]).
    Dm,
}

/// A single Channel. For DMs `guild_id` is `None` and `kind` is
/// [`ChannelKind::Dm`].
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ChannelInfo {
    /// Channel id.
    pub id: i64,
    /// Owning Guild, or `None` for a DM channel.
    pub guild_id: Option<i64>,
    /// Which of text/voice/dm this channel is.
    pub kind: ChannelKind,
    /// Channel name (DM channels may carry a synthesized name; clients
    /// usually render the peer's username instead).
    pub name: String,
}

/// A Guild with its Channels, as delivered in snapshots and join events.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct GuildInfo {
    /// Guild id.
    pub id: i64,
    /// Guild name.
    pub name: String,
    /// Account id of the Owner (creator). In v1 only the Owner creates or
    /// deletes Channels and Guild Invites.
    pub owner_id: i64,
    /// All Channels of this Guild known to the caller.
    pub channels: Vec<ChannelInfo>,
}

/// Body of "create guild".
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CreateGuildRequest {
    /// New Guild's name.
    pub name: String,
}

/// Body of "create channel" inside a Guild the caller owns. `kind` must be
/// [`ChannelKind::Text`] or [`ChannelKind::Voice`]; sending `Dm` is rejected
/// with [`ErrorCode::InvalidRequest`].
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CreateChannelRequest {
    /// New Channel's name.
    pub name: String,
    /// Text or Voice. `Dm` is not client-creatable.
    pub kind: ChannelKind,
}

/// Body of "create guild invite", issued by the Guild Owner. Both limits are
/// optional; `None` means unconstrained.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CreateGuildInviteRequest {
    /// Maximum number of times the code may be accepted, or `None` for
    /// unlimited.
    pub max_uses: Option<i64>,
    /// Lifetime of the code in seconds from issuance, or `None` for no
    /// expiry.
    pub ttl_secs: Option<i64>,
}

/// A Guild Invite as stored and handed out. Joining is `POST` with
/// [`JoinGuildRequest`] and consumes one use; a full, expired, or unknown
/// code yields [`ErrorCode::InvalidInvite`].
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct GuildInviteDto {
    /// The shareable code itself.
    pub code: String,
    /// Guild this code admits into.
    pub guild_id: i64,
    /// Acceptance limit, or `None` for unlimited.
    pub max_uses: Option<i64>,
    /// Acceptances so far.
    pub uses: i64,
    /// Absolute expiry, Unix epoch milliseconds, or `None` for no expiry.
    pub expires_at_ms: Option<i64>,
}

/// Body of "join guild" with a previously shared code.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct JoinGuildRequest {
    /// Guild Invite code to redeem.
    pub code: String,
}

/// A DM channel paired with the Account on the other side. Returned by
/// "open DM" (see [`OpenDmRequest`]) and included in the WebSocket
/// [`WsServerBody::Ready`] snapshot.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct DmChannel {
    /// The DM channel itself (`kind == Dm`, `guild_id == None`).
    pub channel: ChannelInfo,
    /// The other Account in this two-party conversation.
    pub peer: AccountBrief,
}

/// Body of "open DM" with a Friend. Idempotent: the server returns the
/// existing [`DmChannel`] when one already exists, otherwise creates one.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct OpenDmRequest {
    /// Account id of the Friend to talk to. Non-friends yield
    /// [`ErrorCode::Forbidden`].
    pub account_id: i64,
}

// ---------------------------------------------------------------------------
// Messages REST
// ---------------------------------------------------------------------------

/// Metadata about a client-side-encrypted attachment. Bytes are encrypted
/// on the device (content-key derived from `nonce`); the server only ever
/// sees ciphertext in object storage.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AttachmentMeta {
    /// Attachment id.
    pub id: i64,
    /// Original file name chosen by the sender.
    pub name: String,
    /// Ciphertext size in bytes.
    pub size: i64,
    /// Base64 client-generated nonce from which the attachment's content
    /// key is derived; needed to decrypt after download.
    pub nonce: String,
}

/// Why a Message exists.
///
/// `Control` Messages are crypto housekeeping (e.g. Olm-wrapped Megolm
/// session-key transport between Members — the WhatsApp sender-key model of
/// ADR 0001). They ride the same delivery path as chat Messages so ordering
/// is preserved, but clients never render them and the server never reads
/// them.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MessageKind {
    /// Human-visible conversation Message.
    Chat,
    /// Crypto housekeeping envelope; never rendered by clients.
    Control,
}

/// A Message: the ciphertext envelope clients exchange through the
/// Instance. `content` is base64 ciphertext and opaque to the server.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MessageDto {
    /// Message id (server-assigned, monotonically increasing per channel).
    pub id: i64,
    /// Channel the Message was posted to (guild text channel or DM).
    pub channel_id: i64,
    /// Sender's Account id.
    pub sender_id: i64,
    /// Whether clients render this Message (`Chat`) or process it
    /// internally (`Control`).
    pub kind: MessageKind,
    /// Base64 ciphertext (Olm for DMs, Megolm for guild channels). Opaque
    /// to the server; contents depend on `kind` and the session state of
    /// each recipient.
    pub content: String,
    /// Id of the Message this one replies to, if any.
    pub reply_to: Option<i64>,
    /// Attachment referenced by this Message, if any.
    pub attachment: Option<AttachmentMeta>,
    /// When the server accepted the Message, Unix epoch milliseconds.
    pub created_at_ms: i64,
}

/// Body of "send message" into a channel.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SendMessageRequest {
    /// `Chat` for user text, `Control` for crypto housekeeping.
    pub kind: MessageKind,
    /// Base64 ciphertext envelope.
    pub content: String,
    /// Id of the Message being replied to, or `None`.
    pub reply_to: Option<i64>,
    /// Id of a previously created attachment ([`CreateAttachmentRequest`])
    /// attached to this Message, or `None`.
    pub attachment_id: Option<i64>,
}

/// One page of channel history, oldest-first, returned by
///
/// ```text
/// GET /channels/{id}/messages?before=<message id>&limit=50
/// ```
///
/// Omit `before` for the newest page; each subsequent page passes the id of
/// the oldest Message currently held. `limit` caps the page size (default
/// 50). `has_more` tells the client whether another (older) page exists.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MessagePage {
    /// Messages in this page, oldest first.
    pub messages: Vec<MessageDto>,
    /// Whether older history exists past this page.
    pub has_more: bool,
}

// ---------------------------------------------------------------------------
// Attachments REST
// ---------------------------------------------------------------------------

/// Body of "create attachment": reserve storage for a client-side-encrypted
/// file before uploading.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CreateAttachmentRequest {
    /// File name to store alongside the ciphertext.
    pub name: String,
    /// Ciphertext size in bytes (the client encrypts before requesting).
    pub size: i64,
    /// Base64 client-generated nonce; the attachment content key is derived
    /// from it and echoed back in [`AttachmentMeta`].
    pub nonce: String,
}

/// Result of "create attachment": the reserved attachment plus a
/// short-lived presigned `PUT` URL. The client uploads the ciphertext bytes
/// with a plain HTTP `PUT` to `upload_url` (no auth header; the signature
/// in the URL is the authorization), then references `attachment.id` from
/// [`SendMessageRequest::attachment_id`].
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CreateAttachmentResponse {
    /// Reserved attachment (id, name, size, nonce).
    pub attachment: AttachmentMeta,
    /// Presigned `PUT` endpoint for the ciphertext bytes.
    pub upload_url: String,
}

/// Returned by `GET /attachments/{id}/download-url`: a short-lived
/// presigned download URL for the ciphertext bytes.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct DownloadUrlResponse {
    /// Presigned `GET` URL for the (encrypted) bytes.
    pub url: String,
    /// When the signature expires, Unix epoch milliseconds. Clients should
    /// re-request rather than cache past this point.
    pub expires_at_ms: i64,
}

// ---------------------------------------------------------------------------
// WebSocket gateway
// ---------------------------------------------------------------------------

/// WebRTC signaling exchanged for a Call. `call_id` is the id of the
/// (voice) channel hosting the Call; presence in the channel is presence
/// in the Call.
///
/// Clients send this inside [`WsClientBody::CallSignal`] addressed to one
/// peer Account (`to`); the server relays it as
/// [`WsServerBody::CallSignal`] with `from` set to the sender.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CallSignalKind {
    /// SDP offer initiating (or re-offering) a peer connection.
    Offer {
        /// SDP body, base64 or plain as produced by the WebRTC stack.
        sdp: String,
    },
    /// SDP answer accepting an offer.
    Answer {
        /// SDP body.
        sdp: String,
    },
    /// One trickle-ICE candidate.
    Candidate {
        /// SDP "a=candidate:" line payload.
        candidate: String,
        /// Media (m-line) index the candidate belongs to, when known.
        mid: Option<u16>,
    },
    /// Leave the Call / tear down the peer connection.
    Hangup,
}

/// Envelope for every client→server WebSocket message.
///
/// # Examples
///
/// ```
/// use bysyc_common::protocol::{WsClientBody, WsClientMsg};
///
/// let msg = WsClientMsg { id: 7, body: WsClientBody::Heartbeat };
/// assert_eq!(
///     serde_json::to_string(&msg).unwrap(),
///     r#"{"id":7,"body":"heartbeat"}"#,
/// );
/// ```
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct WsClientMsg {
    /// Client-chosen correlation id. Echoed back as
    /// [`WsServerBody::Error::reply_to`] when this message fails, so the
    /// client can attribute the error. Otherwise ignored by the server.
    pub id: u64,
    /// The payload proper.
    pub body: WsClientBody,
}

/// Payload of a client→server WebSocket message.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum WsClientBody {
    /// Liveness ping; the server answers nothing special (the transport
    /// itself proves liveness) but may use it to reset idle timers.
    Heartbeat,
    /// "I am typing in this channel." Fanned out to other Members as
    /// [`WsServerBody::Typing`].
    Typing {
        /// Channel the caller is typing in.
        channel_id: i64,
    },
    /// Acknowledge directed Mailbox items (see [`MailboxItem`]) as
    /// decrypted and persisted; the server drops them so they are not
    /// redelivered on reconnect.
    AckMailbox {
        /// Ids of [`MailboxItem`]s to acknowledge.
        ids: Vec<i64>,
    },
    /// Join the Call hosted by a voice channel (presence in the channel is
    /// presence in the Call). Fails with [`ErrorCode::VoiceChannelFull`]
    /// when the channel already holds 6 participants. On success everyone
    /// in the channel receives a fresh [`WsServerBody::VoiceState`].
    VoiceJoin {
        /// Voice channel to join.
        channel_id: i64,
    },
    /// Leave the current Call, if any. Everyone remaining receives a fresh
    /// [`WsServerBody::VoiceState`].
    VoiceLeave,
    /// Relay WebRTC signaling to one peer in a Call.
    CallSignal {
        /// Channel id of the Call (voice channel or DM channel for a
        /// Private Call).
        call_id: i64,
        /// Recipient Account id.
        to: i64,
        /// The signaling payload.
        kind: CallSignalKind,
    },
}

/// Envelope for every server→client WebSocket message. The first message on
/// any connection is [`WsServerBody::Ready`].
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct WsServerMsg {
    /// Server-assigned sequence number for this message on this
    /// connection, when applicable; `None` otherwise.
    pub id: Option<i64>,
    /// The payload proper.
    pub body: WsServerBody,
}

/// One directed (1:1) ciphertext control item queued for an offline or
/// not-yet-caught-up Account — typically an Olm message carrying Megolm
/// session keys (ADR 0001's sender-key bootstrap). Delivered inside
/// [`WsServerBody::Ready`] on connect and as
/// [`WsServerBody::MailboxAppend`] the moment it arrives while online. The
/// client must [`WsClientBody::AckMailbox`] each item after decrypting and
/// persisting it; unacknowledged items are redelivered on reconnect.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MailboxItem {
    /// Mailbox item id (used for acknowledgement).
    pub id: i64,
    /// Sender's Account id.
    pub sender_id: i64,
    /// Base64 ciphertext of the directed control message; opaque to the
    /// server.
    pub content: String,
    /// When the server accepted the item, Unix epoch milliseconds.
    pub created_at_ms: i64,
}

/// Payload of a server→client WebSocket message.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum WsServerBody {
    /// Initial snapshot, sent as the first message of the connection:
    /// everything the client needs to render its world before any delta
    /// events arrive.
    Ready {
        /// The authenticated Account.
        account: AccountInfo,
        /// Accepted Friends (drives presence and DM eligibility).
        friends: Vec<AccountBrief>,
        /// Pending inbound Friend Requests (brief = requester).
        incoming_requests: Vec<AccountBrief>,
        /// Pending outbound Friend Requests (brief = recipient).
        outgoing_requests: Vec<AccountBrief>,
        /// Guilds the Account belongs to, channels included.
        guilds: Vec<GuildInfo>,
        /// Open DM channels with the peer on the other side.
        dm_channels: Vec<DmChannel>,
        /// Undelivered directed control items; ack after decrypting.
        mailbox: Vec<MailboxItem>,
    },
    /// A new Message in a channel the Account can see (chat or control).
    Message(MessageDto),
    /// A directed control item arrived while online; ack after decrypting
    /// and persisting.
    MailboxAppend(MailboxItem),
    /// A Friend (or otherwise watched Account) went online or offline.
    Presence {
        /// The Account whose connectivity changed.
        account_id: i64,
        /// New connectivity state.
        online: bool,
    },
    /// Someone is typing in a channel.
    Typing {
        /// Channel being typed into.
        channel_id: i64,
        /// Who is typing.
        account_id: i64,
    },
    /// An Account sent the caller a Friend Request.
    FriendRequested {
        /// The requester.
        from: AccountBrief,
    },
    /// A Friend Request the caller sent was accepted; the pair are now
    /// Friends and may open a DM.
    FriendRequestAccepted {
        /// The Account that accepted.
        by: AccountBrief,
    },
    /// A Friend relationship ended (either side removed the other).
    FriendRemoved {
        /// The Account that is no longer a Friend.
        account_id: i64,
    },
    /// The caller just joined a Guild (e.g. by redeeming an invite); full
    /// snapshot of it. Existing Members separately receive
    /// [`WsServerBody::MemberJoined`].
    GuildJoined {
        /// The Guild, channels included.
        guild: GuildInfo,
    },
    /// A Channel was created in a Guild the caller can see.
    ChannelCreated {
        /// Guild that gained the Channel.
        guild_id: i64,
        /// The new Channel.
        channel: ChannelInfo,
    },
    /// A Channel was deleted from a Guild the caller can see. Clients drop
    /// local state (messages stay in the local cache until pruned).
    ChannelDeleted {
        /// Guild that lost the Channel.
        guild_id: i64,
        /// The deleted Channel.
        channel_id: i64,
    },
    /// A Member left a Guild (voluntarily or removed). Broadcast to the
    /// remaining Members; the leaver receives nothing.
    MemberLeft {
        /// Guild that was left.
        guild_id: i64,
        /// The Account that left.
        account_id: i64,
    },
    /// Another Account joined a Guild the caller is in (broadcast to the
    /// pre-existing Members; the joiner gets [`WsServerBody::GuildJoined`]
    /// instead).
    MemberJoined {
        /// Guild that was joined.
        guild_id: i64,
        /// The new Member.
        account: AccountBrief,
    },
    /// Full participant list of a voice channel. Sent on every join/leave
    /// as a complete snapshot — clients *replace* their view, they do not
    /// merge. An empty list means the Call ended.
    VoiceState {
        /// Voice channel whose Call state changed.
        channel_id: i64,
        /// Everyone currently in the Call.
        participants: Vec<AccountBrief>,
    },
    /// Relayed WebRTC signaling from a peer in a Call (mirror of
    /// [`WsClientBody::CallSignal`]).
    CallSignal {
        /// Channel id of the Call.
        call_id: i64,
        /// Sender's Account id.
        from: i64,
        /// The signaling payload.
        kind: CallSignalKind,
    },
    /// A client message (or gateway operation) failed. For failures tied to
    /// a specific client message, `reply_to` echoes that
    /// [`WsClientMsg::id`].
    Error {
        /// The [`WsClientMsg::id`] this error answers, when attributable.
        reply_to: Option<u64>,
        /// Machine-readable classification (same codes as REST).
        code: ErrorCode,
        /// Human-readable explanation.
        message: String,
    },
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::DeserializeOwned;

    /// Serialize to JSON and back; the result must be identical.
    fn roundtrip<T>(value: T)
    where
        T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        let json = serde_json::to_string(&value).expect("serialize");
        let back: T = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(&back, &value, "roundtrip mismatch for: {json}");
    }

    fn brief() -> AccountBrief {
        AccountBrief {
            id: 1,
            username: "alice".into(),
            identity_key: "aWRlbnRpdHlLZXk=".into(),
            online: true,
        }
    }

    fn info() -> AccountInfo {
        AccountInfo {
            id: 1,
            username: "alice".into(),
            identity_key: "aWRlbnRpdHlLZXk=".into(),
            created_at_ms: 1_700_000_000_000,
        }
    }

    fn text_channel() -> ChannelInfo {
        ChannelInfo {
            id: 10,
            guild_id: Some(5),
            kind: ChannelKind::Text,
            name: "general".into(),
        }
    }

    fn dm_channel() -> DmChannel {
        DmChannel {
            channel: ChannelInfo {
                id: 11,
                guild_id: None,
                kind: ChannelKind::Dm,
                name: "alice/bob".into(),
            },
            peer: brief(),
        }
    }

    fn guild() -> GuildInfo {
        GuildInfo {
            id: 5,
            name: "crew".into(),
            owner_id: 1,
            channels: vec![text_channel()],
        }
    }

    fn message_dto() -> MessageDto {
        MessageDto {
            id: 100,
            channel_id: 10,
            sender_id: 1,
            kind: MessageKind::Chat,
            content: "aGVsbG8gd29ybGQ=".into(),
            reply_to: None,
            attachment: None,
            created_at_ms: 1_700_000_000_123,
        }
    }

    fn mailbox_item() -> MailboxItem {
        MailboxItem {
            id: 200,
            sender_id: 1,
            content: "bWFpbGJveA==".into(),
            created_at_ms: 1_700_000_000_456,
        }
    }

    #[test]
    fn ws_client_msg_roundtrips_every_variant() {
        roundtrip(WsClientMsg {
            id: 1,
            body: WsClientBody::Heartbeat,
        });
        roundtrip(WsClientMsg {
            id: 2,
            body: WsClientBody::Typing { channel_id: 10 },
        });
        roundtrip(WsClientMsg {
            id: 3,
            body: WsClientBody::AckMailbox {
                ids: vec![200, 201],
            },
        });
        roundtrip(WsClientMsg {
            id: 4,
            body: WsClientBody::VoiceJoin { channel_id: 12 },
        });
        roundtrip(WsClientMsg {
            id: 5,
            body: WsClientBody::VoiceLeave,
        });
        // One CallSignal per CallSignalKind so all four kinds are covered.
        for (n, kind) in [
            CallSignalKind::Offer {
                sdp: "v=0\r\no=- 1 1 IN IP4 127.0.0.1".into(),
            },
            CallSignalKind::Answer {
                sdp: "v=0\r\no=- 2 1 IN IP4 127.0.0.1".into(),
            },
            CallSignalKind::Candidate {
                candidate: "candidate:1 1 UDP 2130706431 192.168.1.4 50000 typ host".into(),
                mid: Some(0),
            },
            CallSignalKind::Hangup,
        ]
        .into_iter()
        .enumerate()
        {
            roundtrip(WsClientMsg {
                id: 6 + n as u64,
                body: WsClientBody::CallSignal {
                    call_id: 12,
                    to: 2,
                    kind,
                },
            });
        }
    }

    #[test]
    fn ws_server_msg_roundtrips_every_variant() {
        roundtrip(WsServerMsg {
            id: Some(1),
            body: WsServerBody::Ready {
                account: info(),
                friends: vec![brief()],
                incoming_requests: vec![],
                outgoing_requests: vec![],
                guilds: vec![guild()],
                dm_channels: vec![dm_channel()],
                mailbox: vec![mailbox_item()],
            },
        });
        roundtrip(WsServerMsg {
            id: Some(2),
            body: WsServerBody::Message(message_dto()),
        });
        roundtrip(WsServerMsg {
            id: Some(3),
            body: WsServerBody::MailboxAppend(mailbox_item()),
        });
        roundtrip(WsServerMsg {
            id: Some(4),
            body: WsServerBody::Presence {
                account_id: 2,
                online: false,
            },
        });
        roundtrip(WsServerMsg {
            id: Some(5),
            body: WsServerBody::Typing {
                channel_id: 10,
                account_id: 2,
            },
        });
        roundtrip(WsServerMsg {
            id: Some(6),
            body: WsServerBody::FriendRequested { from: brief() },
        });
        roundtrip(WsServerMsg {
            id: Some(7),
            body: WsServerBody::FriendRequestAccepted { by: brief() },
        });
        roundtrip(WsServerMsg {
            id: Some(8),
            body: WsServerBody::FriendRemoved { account_id: 2 },
        });
        roundtrip(WsServerMsg {
            id: Some(9),
            body: WsServerBody::GuildJoined { guild: guild() },
        });
        roundtrip(WsServerMsg {
            id: Some(10),
            body: WsServerBody::ChannelCreated {
                guild_id: 5,
                channel: text_channel(),
            },
        });
        roundtrip(WsServerMsg {
            id: Some(11),
            body: WsServerBody::MemberJoined {
                guild_id: 5,
                account: brief(),
            },
        });
        roundtrip(WsServerMsg {
            id: Some(12),
            body: WsServerBody::VoiceState {
                channel_id: 12,
                participants: vec![brief()],
            },
        });
        roundtrip(WsServerMsg {
            id: Some(13),
            body: WsServerBody::CallSignal {
                call_id: 12,
                from: 2,
                kind: CallSignalKind::Candidate {
                    candidate: "candidate:2 1 UDP 1694498815 10.0.0.7 50001 typ srflx".into(),
                    mid: None,
                },
            },
        });
        roundtrip(WsServerMsg {
            id: Some(14),
            body: WsServerBody::Error {
                reply_to: Some(6),
                code: ErrorCode::VoiceChannelFull,
                message: "voice channel is full".into(),
            },
        });
        // The sequence id is optional.
        roundtrip(WsServerMsg {
            id: None,
            body: WsServerBody::Presence {
                account_id: 3,
                online: true,
            },
        });
    }

    #[test]
    fn enums_serialize_snake_case() {
        assert_eq!(
            serde_json::to_value(ChannelKind::Voice).unwrap(),
            serde_json::json!("voice")
        );
        assert_eq!(
            serde_json::to_value(ChannelKind::Text).unwrap(),
            serde_json::json!("text")
        );
        assert_eq!(
            serde_json::to_value(ChannelKind::Dm).unwrap(),
            serde_json::json!("dm")
        );
        assert_eq!(
            serde_json::to_value(CallSignalKind::Hangup).unwrap(),
            serde_json::json!("hangup")
        );
        assert_eq!(
            serde_json::to_value(MessageKind::Control).unwrap(),
            serde_json::json!("control")
        );
        assert_eq!(
            serde_json::to_value(ErrorCode::RateLimited).unwrap(),
            serde_json::json!("rate_limited")
        );
        assert_eq!(
            serde_json::to_value(ErrorCode::VoiceChannelFull).unwrap(),
            serde_json::json!("voice_channel_full")
        );
        assert_eq!(
            serde_json::to_value(ErrorCode::ProtocolVersion).unwrap(),
            serde_json::json!("protocol_version")
        );
    }

    #[test]
    fn wire_shapes_are_externally_tagged_snake_case() {
        let heartbeat = WsClientMsg {
            id: 7,
            body: WsClientBody::Heartbeat,
        };
        assert_eq!(
            serde_json::to_value(&heartbeat).unwrap(),
            serde_json::json!({"id": 7, "body": "heartbeat"})
        );
        // Struct variants are single-key objects around the payload.
        let typing = WsClientMsg {
            id: 8,
            body: WsClientBody::Typing { channel_id: 10 },
        };
        assert_eq!(
            serde_json::to_value(&typing).unwrap(),
            serde_json::json!({"id": 8, "body": {"typing": {"channel_id": 10}}})
        );
        let error = ApiError {
            code: ErrorCode::Unauthorized,
            message: "session token expired".into(),
        };
        assert_eq!(
            serde_json::to_value(&error).unwrap(),
            serde_json::json!({"code": "unauthorized", "message": "session token expired"})
        );
    }

    #[test]
    fn rest_dtos_roundtrip() {
        roundtrip(RegisterRequest {
            username: "bob".into(),
            password: "hunter2".into(),
            invite_code: "letmein".into(),
            identity_key: "a2V5".into(),
        });
        roundtrip(LoginRequest {
            username: "bob".into(),
            password: "hunter2".into(),
        });
        roundtrip(TokenResponse {
            token: "tok".into(),
            account: info(),
        });
        roundtrip(UploadOtkRequest {
            one_time_keys: vec!["b3RrMQ==".into(), "b3RrMg==".into()],
        });
        roundtrip(ClaimedKeys {
            identity_key: "a2V5".into(),
            one_time_key: Some("b3RrMQ==".into()),
        });
        roundtrip(ClaimedKeys {
            identity_key: "a2V5".into(),
            one_time_key: None,
        });
        roundtrip(FriendList {
            friends: vec![brief()],
            incoming: vec![],
            outgoing: vec![],
        });
        roundtrip(CreateGuildRequest {
            name: "crew".into(),
        });
        roundtrip(CreateChannelRequest {
            name: "general".into(),
            kind: ChannelKind::Text,
        });
        roundtrip(CreateGuildInviteRequest {
            max_uses: Some(5),
            ttl_secs: None,
        });
        roundtrip(GuildInviteDto {
            code: "abc123".into(),
            guild_id: 5,
            max_uses: Some(5),
            uses: 1,
            expires_at_ms: Some(1_700_000_360_000),
        });
        roundtrip(JoinGuildRequest {
            code: "abc123".into(),
        });
        roundtrip(OpenDmRequest { account_id: 2 });
        roundtrip(SendMessageRequest {
            kind: MessageKind::Chat,
            content: "aGVsbG8=".into(),
            reply_to: Some(99),
            attachment_id: None,
        });
        roundtrip(MessagePage {
            messages: vec![message_dto()],
            has_more: true,
        });
        roundtrip(CreateAttachmentRequest {
            name: "cat.png".into(),
            size: 4096,
            nonce: "bm9uY2U=".into(),
        });
        roundtrip(CreateAttachmentResponse {
            attachment: AttachmentMeta {
                id: 300,
                name: "cat.png".into(),
                size: 4096,
                nonce: "bm9uY2U=".into(),
            },
            upload_url: "https://s3/put-here".into(),
        });
        roundtrip(DownloadUrlResponse {
            url: "https://s3/get-here".into(),
            expires_at_ms: 1_700_000_360_000,
        });
    }
}

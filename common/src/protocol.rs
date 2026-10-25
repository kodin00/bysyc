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
//! [`ErrorCode::ProtocolVersion`]. Since v2 the gateway carries
//! [`WsClientMsg`] / [`WsServerMsg`] as **binary** WebSocket frames encoded
//! with MessagePack (see the codec helpers at the bottom of this module);
//! REST bodies remain JSON, built from the same types.
//!
//! # Versioning and compatibility
//!
//! - Every wire enum ([`ErrorCode`], [`ChannelKind`], [`MessageKind`],
//!   [`CallSignalKind`], [`WsClientBody`], [`WsServerBody`]) is
//!   `#[non_exhaustive]` and carries an `Unknown` fallback variant annotated
//!   `#[serde(other)]`. An unrecognized variant tag on the wire deserializes
//!   to `Unknown` rather than producing an `Err`, so an older peer is not
//!   killed by a newer peer's vocabulary.
//! - Clients MUST handle `Unknown` gracefully: log and ignore, never tear
//!   down the connection over it.
//! - Servers MUST NOT rely on clients understanding newer variants; anything
//!   new a server emits lands as `Unknown` on an older client and is ignored.
//! - v2 servers do NOT support v1 clients. v1 used JSON text frames on the
//!   gateway; v2 uses binary MessagePack. The two are wire-incompatible with
//!   no on-the-wire negotiation, and a v1 client is rejected at the
//!   `protocol` query parameter rather than silently degraded.
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
//! | `DELETE /channels/{id}/messages/{message_id}` | delete one of the caller's own messages | — |
//! | `POST /attachments/image` | upload a WebP image (server-stored, unencrypted) | raw WebP bytes → [`ImageUploadResponse`] |
//! | `GET /attachments/{id}/download-url` | presigned download URL | [`DownloadUrlResponse`] |
//! | `GET /ws?token=...&protocol=2` | WebSocket gateway | [`WsClientMsg`] / [`WsServerMsg`] (binary MessagePack) |
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
    /// True for the Instance's single admin (the first account to register).
    pub is_admin: bool,
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
#[non_exhaustive]
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
    /// Fallback for an unrecognized error code on the wire. A newer server
    /// may emit codes this version does not know; clients log and ignore.
    /// Never produced by this server, only absorbed on read.
    #[serde(other)]
    Unknown,
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

/// Batch-upload of Olm one-time prekeys so peers can start an encrypted DM
/// while this Account is offline.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct UploadOtkRequest {
    /// One-time prekey entries, each the single string `"{key_id}:{b64
    /// pubkey}"` (the id must not contain `:`). Stored and re-served
    /// verbatim on claim.
    pub one_time_keys: Vec<String>,
}

/// TURN relay credentials for Calls, returned by `GET /turn`. Static
/// long-term credentials for the whole Instance in v1.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TurnInfo {
    /// Candidate URLs, e.g. `turn:host:3478`.
    pub urls: Vec<String>,
    /// TURN username (shared, v1).
    pub username: String,
    /// TURN password (shared, v1).
    pub credential: String,
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
#[non_exhaustive]
pub enum ChannelKind {
    /// Text Channel: Messages (Megolm-encrypted).
    Text,
    /// Voice Channel: hosts a Call (full-mesh WebRTC, max 6 participants).
    Voice,
    /// Direct-message channel between exactly two Friends; server-created
    /// only (see [`DmChannel`] / [`OpenDmRequest`]).
    Dm,
    /// Fallback for an unrecognized channel kind on the wire.
    #[serde(other)]
    Unknown,
}

/// A single Channel. For DMs `guild_id` is `None` (and omitted on the wire)
/// and `kind` is [`ChannelKind::Dm`].
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ChannelInfo {
    /// Channel id.
    pub id: i64,
    /// Owning Guild, or `None` for a DM channel.
    #[serde(skip_serializing_if = "Option::is_none")]
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
#[serde(deny_unknown_fields)]
pub struct CreateGuildRequest {
    /// New Guild's name.
    pub name: String,
}

/// Body of "create channel" inside a Guild the caller owns. `kind` must be
/// [`ChannelKind::Text`] or [`ChannelKind::Voice`]; sending `Dm` is rejected
/// with [`ErrorCode::InvalidRequest`].
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CreateChannelRequest {
    /// New Channel's name.
    pub name: String,
    /// Text or Voice. `Dm` is not client-creatable.
    pub kind: ChannelKind,
}

/// Body of "create guild invite", issued by the Guild Owner. Both limits are
/// optional; `None` means unconstrained.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct OpenDmRequest {
    /// Account id of the Friend to talk to. Non-friends yield
    /// [`ErrorCode::Forbidden`].
    pub account_id: i64,
}

// ---------------------------------------------------------------------------
// Messages REST
// ---------------------------------------------------------------------------

/// Serde default for [`AttachmentMeta::encrypted`]: every attachment
/// created before the flag existed is ciphertext, so a missing field means
/// `true`.
fn default_true() -> bool {
    true
}

/// Metadata about an attachment. For encrypted attachments (everything but
/// image uploads) the bytes are encrypted on the device (content-key derived
/// from `nonce`); the server only ever sees ciphertext in object storage.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AttachmentMeta {
    /// Attachment id.
    pub id: i64,
    /// Original file name chosen by the sender. For image attachments the
    /// name is server-assigned (`img_...webp`) — original file names are
    /// never revealed for those.
    pub name: String,
    /// Ciphertext size in bytes (the stored size, either way).
    pub size: i64,
    /// Base64 client-generated nonce from which the attachment's content
    /// key is derived; needed to decrypt after download. Empty for
    /// unencrypted image attachments (nothing to derive).
    pub nonce: String,
    /// Whether the stored bytes are client-side ciphertext. `false` only
    /// for server-stored WebP images (`POST /attachments/image`) — the one
    /// attachment kind whose bytes the Instance has seen.
    #[serde(default = "default_true")]
    pub encrypted: bool,
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
#[non_exhaustive]
pub enum MessageKind {
    /// Human-visible conversation Message.
    Chat,
    /// Crypto housekeeping envelope; never rendered by clients.
    Control,
    /// Fallback for an unrecognized message kind on the wire.
    #[serde(other)]
    Unknown,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<i64>,
    /// Attachment referenced by this Message, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachment: Option<AttachmentMeta>,
    /// When the server accepted the Message, Unix epoch milliseconds.
    pub created_at_ms: i64,
}

/// Body of "send message" into a channel.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

/// Result of `POST /attachments/image`: the stored image attachment. There
/// is no `upload_url` — unlike [`CreateAttachmentResponse`], the bytes were
/// uploaded to the Instance itself, which validated them as WebP and stored
/// them server-side (under a server-assigned name; `encrypted == false`).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ImageUploadResponse {
    /// The stored image attachment.
    pub attachment: AttachmentMeta,
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
#[non_exhaustive]
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
        #[serde(skip_serializing_if = "Option::is_none")]
        mid: Option<u16>,
    },
    /// Leave the Call / tear down the peer connection.
    Hangup,
    /// Fallback for an unrecognized signaling payload on the wire. Relayed
    /// verbatim by the server; clients that do not understand it drop it.
    #[serde(other)]
    Unknown,
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
#[serde(remote = "Self", rename_all = "snake_case")]
#[non_exhaustive]
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
    /// Fallback for an unrecognized client→server variant. The server logs
    /// and ignores it; it never replies with an error for an unknown tag.
    #[serde(other)]
    Unknown,
}

/// Envelope for every server→client WebSocket message. The first message on
/// any connection is [`WsServerBody::Ready`]. The envelope carries only the
/// payload; per-message correlation, where attributable, lives inside
/// [`WsServerBody::Error::reply_to`] (echoing [`WsClientMsg::id`]). The
/// server never assigns its own sequence number.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct WsServerMsg {
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
#[serde(remote = "Self", rename_all = "snake_case")]
#[non_exhaustive]
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
    /// A Message was deleted from a channel the Account can see. Clients
    /// drop it from their local cache; history paging no longer returns it.
    /// Unlike [`WsServerBody::Message`], the deleting sender receives this
    /// too — the `DELETE` response is a bodyless `204`.
    MessageDeleted {
        /// Channel the Message was removed from.
        channel_id: i64,
        /// The deleted Message.
        message_id: i64,
    },
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
        #[serde(skip_serializing_if = "Option::is_none")]
        reply_to: Option<u64>,
        /// Machine-readable classification (same codes as REST).
        code: ErrorCode,
        /// Human-readable explanation.
        message: String,
    },
    /// Fallback for an unrecognized server→client variant. Clients MUST log
    /// and ignore rather than tear down the connection; a newer server may
    /// emit variants this version does not yet know.
    #[serde(other)]
    Unknown,
}

// The two body enums carry payloads, so `#[serde(other)]` alone is not enough:
// serde resolves the unknown tag to `Unknown` but then asks the format for a
// *unit* variant, which fails when the tag arrives as `{"tag": {..payload..}}`.
// They therefore derive with `remote = "Self"` (generating inherent
// `serialize`/`deserialize` fns) and wrap them below.

/// Deserialize a payload-carrying wire enum, mapping an unrecognized tag —
/// bare string or single-key map with any payload — to its `Unknown` variant.
///
/// The input is buffered once as a [`serde_json::Value`] (a self-describing
/// intermediate, whatever the source format). A tag is "unrecognized" when the
/// derived impl maps the bare tag string to `Unknown`; a known tag with a
/// malformed payload still errors.
fn deserialize_forward_compat<'de, D, T>(
    deserializer: D,
    derived: fn(serde_json::Value) -> Result<T, serde_json::Error>,
    is_unknown: fn(&T) -> bool,
) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    let value = serde_json::Value::deserialize(deserializer)?;
    if let serde_json::Value::Object(map) = &value
        && map.len() == 1
        && let Some(tag) = map.keys().next()
        && let Ok(unknown) = derived(serde_json::Value::String(tag.clone()))
        && is_unknown(&unknown)
    {
        return Ok(unknown);
    }
    derived(value).map_err(D::Error::custom)
}

impl Serialize for WsClientBody {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        Self::serialize(self, serializer)
    }
}

impl<'de> Deserialize<'de> for WsClientBody {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_forward_compat(deserializer, Self::deserialize, |b| {
            matches!(b, Self::Unknown)
        })
    }
}

impl Serialize for WsServerBody {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        Self::serialize(self, serializer)
    }
}

impl<'de> Deserialize<'de> for WsServerBody {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_forward_compat(deserializer, Self::deserialize, |b| {
            matches!(b, Self::Unknown)
        })
    }
}

// ---------------------------------------------------------------------------
// WebSocket frame codec (binary MessagePack; REST stays JSON)
// ---------------------------------------------------------------------------

/// Encode one server→client frame for the gateway's binary WebSocket
/// messages.
///
/// The encoding is *named* — struct fields become map keys, mirroring the
/// JSON shape. That is required, not a preference: several `Option` fields
/// skip serialization when `None`, and MessagePack's compact positional
/// struct representation cannot omit fields. Both sides of the gateway use
/// these helpers, so the representation cannot drift.
pub fn encode_ws_server_msg(msg: &WsServerMsg) -> Vec<u8> {
    rmp_serde::to_vec_named(msg).expect("WsServerMsg always serializes")
}

/// Encode one client→server frame (see [`encode_ws_server_msg`]).
pub fn encode_ws_client_msg(msg: &WsClientMsg) -> Vec<u8> {
    rmp_serde::to_vec_named(msg).expect("WsClientMsg always serializes")
}

/// Decode one server→client frame from a binary WebSocket message. Accepts
/// both named and positional MessagePack (the decoder is agnostic; only the
/// encoders above are pinned to named).
pub fn decode_ws_server_msg(bytes: &[u8]) -> Result<WsServerMsg, rmp_serde::decode::Error> {
    rmp_serde::from_slice(bytes)
}

/// Decode one client→server frame from a binary WebSocket message.
pub fn decode_ws_client_msg(bytes: &[u8]) -> Result<WsClientMsg, rmp_serde::decode::Error> {
    rmp_serde::from_slice(bytes)
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
            is_admin: true,
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
            body: WsServerBody::Message(message_dto()),
        });
        roundtrip(WsServerMsg {
            body: WsServerBody::MessageDeleted {
                channel_id: 10,
                message_id: 100,
            },
        });
        roundtrip(WsServerMsg {
            body: WsServerBody::MailboxAppend(mailbox_item()),
        });
        roundtrip(WsServerMsg {
            body: WsServerBody::Presence {
                account_id: 2,
                online: false,
            },
        });
        roundtrip(WsServerMsg {
            body: WsServerBody::Typing {
                channel_id: 10,
                account_id: 2,
            },
        });
        roundtrip(WsServerMsg {
            body: WsServerBody::FriendRequested { from: brief() },
        });
        roundtrip(WsServerMsg {
            body: WsServerBody::FriendRequestAccepted { by: brief() },
        });
        roundtrip(WsServerMsg {
            body: WsServerBody::FriendRemoved { account_id: 2 },
        });
        roundtrip(WsServerMsg {
            body: WsServerBody::GuildJoined { guild: guild() },
        });
        roundtrip(WsServerMsg {
            body: WsServerBody::ChannelCreated {
                guild_id: 5,
                channel: text_channel(),
            },
        });
        roundtrip(WsServerMsg {
            body: WsServerBody::MemberJoined {
                guild_id: 5,
                account: brief(),
            },
        });
        roundtrip(WsServerMsg {
            body: WsServerBody::VoiceState {
                channel_id: 12,
                participants: vec![brief()],
            },
        });
        roundtrip(WsServerMsg {
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
            body: WsServerBody::Error {
                reply_to: Some(6),
                code: ErrorCode::VoiceChannelFull,
                message: "voice channel is full".into(),
            },
        });
        roundtrip(WsServerMsg {
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
                encrypted: true,
            },
            upload_url: "https://s3/put-here".into(),
        });
        roundtrip(ImageUploadResponse {
            attachment: AttachmentMeta {
                id: 301,
                name: "img_ab12cd34ef56.webp".into(),
                size: 2048,
                nonce: String::new(),
                encrypted: false,
            },
        });
        roundtrip(DownloadUrlResponse {
            url: "https://s3/get-here".into(),
            expires_at_ms: 1_700_000_360_000,
        });
    }

    #[test]
    fn attachment_meta_without_encrypted_deserializes_as_encrypted() {
        // JSON produced before the `encrypted` flag existed (every stored
        // attachment was ciphertext) must keep deserializing, as `true`.
        let legacy = serde_json::json!({
            "id": 300,
            "name": "cat.png",
            "size": 4096,
            "nonce": "bm9uY2U="
        });
        let meta: AttachmentMeta = serde_json::from_value(legacy).expect("legacy json parses");
        assert!(meta.encrypted);
    }

    /// The gateway's binary frames are MessagePack; round-trip the same
    /// representative shapes the JSON tests pin, through the codec helpers
    /// both sides of the gateway actually call.
    #[test]
    fn ws_frames_msgpack_roundtrip() {
        fn roundtrip_bin<T>(
            value: T,
            encode: fn(&T) -> Vec<u8>,
            decode: fn(&[u8]) -> Result<T, rmp_serde::decode::Error>,
        ) where
            T: PartialEq + std::fmt::Debug,
        {
            let bytes = encode(&value);
            let back = decode(&bytes).expect("msgpack decodes");
            assert_eq!(&back, &value, "msgpack roundtrip mismatch");
        }

        // Server frames: a plain chat Message with all-None options, the
        // same Message with reply + attachment set, an Error attributing a
        // client id, one attributing none, a call-signal candidate with and
        // without `mid`, and the full Ready snapshot.
        let mut with_optional = message_dto();
        with_optional.reply_to = Some(99);
        with_optional.attachment = Some(AttachmentMeta {
            id: 300,
            name: "cat.png".into(),
            size: 4096,
            nonce: "bm9uY2U=".into(),
            encrypted: true,
        });
        let enc = |v: &WsServerMsg| encode_ws_server_msg(v);
        let dec: fn(&[u8]) -> Result<WsServerMsg, _> = decode_ws_server_msg;
        roundtrip_bin(
            WsServerMsg {
                body: WsServerBody::Message(message_dto()),
            },
            enc,
            dec,
        );
        roundtrip_bin(
            WsServerMsg {
                body: WsServerBody::Message(with_optional),
            },
            enc,
            dec,
        );
        roundtrip_bin(
            WsServerMsg {
                body: WsServerBody::Error {
                    reply_to: Some(6),
                    code: ErrorCode::VoiceChannelFull,
                    message: "voice channel is full".into(),
                },
            },
            enc,
            dec,
        );
        roundtrip_bin(
            WsServerMsg {
                body: WsServerBody::Error {
                    reply_to: None,
                    code: ErrorCode::InvalidRequest,
                    message: "malformed message".into(),
                },
            },
            enc,
            dec,
        );
        roundtrip_bin(
            WsServerMsg {
                body: WsServerBody::CallSignal {
                    call_id: 12,
                    from: 2,
                    kind: CallSignalKind::Candidate {
                        candidate: "candidate:2 1 UDP 1694498815 10.0.0.7 50001 typ srflx".into(),
                        mid: Some(0),
                    },
                },
            },
            enc,
            dec,
        );
        roundtrip_bin(
            WsServerMsg {
                body: WsServerBody::Ready {
                    account: info(),
                    friends: vec![brief()],
                    incoming_requests: vec![],
                    outgoing_requests: vec![],
                    guilds: vec![
                        guild(),
                        GuildInfo {
                            id: 6,
                            name: "empty".into(),
                            owner_id: 1,
                            channels: vec![],
                        },
                    ],
                    dm_channels: vec![dm_channel()],
                    mailbox: vec![mailbox_item()],
                },
            },
            enc,
            dec,
        );

        // Client frames: a bare unit variant and a struct variant.
        let enc_c = |v: &WsClientMsg| encode_ws_client_msg(v);
        let dec_c: fn(&[u8]) -> Result<WsClientMsg, _> = decode_ws_client_msg;
        roundtrip_bin(
            WsClientMsg {
                id: 1,
                body: WsClientBody::Heartbeat,
            },
            enc_c,
            dec_c,
        );
        roundtrip_bin(
            WsClientMsg {
                id: 2,
                body: WsClientBody::Typing { channel_id: 10 },
            },
            enc_c,
            dec_c,
        );
        roundtrip_bin(
            WsClientMsg {
                id: 3,
                body: WsClientBody::AckMailbox {
                    ids: vec![200, 201],
                },
            },
            enc_c,
            dec_c,
        );
    }

    /// An unknown variant tag on the wire — sent by a newer peer or a buggy
    /// one — MUST deserialize to the enum's `Unknown` fallback rather than
    /// `Err`, so an older client can log and ignore it instead of dropping
    /// the connection. Covers both the struct-style (single-key map, the
    /// realistic case of a newer server's new variant) and the unit-style
    /// (bare tag) shape, in each gateway direction.
    #[test]
    fn msgpack_unknown_variants_decode_to_unknown() {
        // Server frame, unknown struct-variant tag: a newer server emits a
        // variant this client does not know.
        let frame = serde_json::json!({"body": {"bogus": {"x": 1}}});
        let bytes = rmp_serde::to_vec_named(&frame).expect("encode");
        let msg = decode_ws_server_msg(&bytes).expect("server frame decodes, not Err");
        assert!(matches!(msg.body, WsServerBody::Unknown));

        // Server frame, unknown unit-style tag (a bare string variant).
        let frame = serde_json::json!({"body": "bogus"});
        let bytes = rmp_serde::to_vec_named(&frame).expect("encode");
        let msg = decode_ws_server_msg(&bytes).expect("server frame decodes, not Err");
        assert!(matches!(msg.body, WsServerBody::Unknown));

        // Client frame, unknown struct-variant tag.
        let frame = serde_json::json!({"id": 9, "body": {"bogus": {"y": 2}}});
        let bytes = rmp_serde::to_vec_named(&frame).expect("encode");
        let msg = decode_ws_client_msg(&bytes).expect("client frame decodes, not Err");
        assert!(matches!(msg.body, WsClientBody::Unknown));

        // Client frame, unknown unit-style tag.
        let frame = serde_json::json!({"id": 9, "body": "bogus"});
        let bytes = rmp_serde::to_vec_named(&frame).expect("encode");
        let msg = decode_ws_client_msg(&bytes).expect("client frame decodes, not Err");
        assert!(matches!(msg.body, WsClientBody::Unknown));
    }

    /// `skip_serializing_if` must reach the msgpack encoding too (the reason
    /// the codec is pinned to the named representation): a None option field
    /// leaves no trace in the frame bytes.
    #[test]
    fn msgpack_encoding_omits_none_option_fields() {
        let plain = encode_ws_server_msg(&WsServerMsg {
            body: WsServerBody::Message(message_dto()),
        });
        assert!(!plain.windows(8).any(|w| w == b"reply_to"));
        assert!(!plain.windows(10).any(|w| w == b"attachment"));

        let mut with = message_dto();
        with.reply_to = Some(99);
        with.attachment = Some(AttachmentMeta {
            id: 300,
            name: "cat.png".into(),
            size: 4096,
            nonce: "bm9uY2U=".into(),
            encrypted: true,
        });
        let rich = encode_ws_server_msg(&WsServerMsg {
            body: WsServerBody::Message(with),
        });
        assert!(rich.windows(8).any(|w| w == b"reply_to"));
        assert!(rich.windows(10).any(|w| w == b"attachment"));
    }

    /// Omitted keys (the new JSON shape on REST and in the client's local
    /// store) and explicit nulls (rows persisted before the skip) must both
    /// deserialize to `None` — no consumer relies on the null being present.
    #[test]
    fn json_missing_and_null_option_fields_both_deserialize_none() {
        let omitted = serde_json::json!({
            "id": 100,
            "channel_id": 10,
            "sender_id": 1,
            "kind": "chat",
            "content": "aGVsbG8=",
            "created_at_ms": 1_700_000_000_123i64
        });
        let nulls = serde_json::json!({
            "id": 100,
            "channel_id": 10,
            "sender_id": 1,
            "kind": "chat",
            "content": "aGVsbG8=",
            "reply_to": null,
            "attachment": null,
            "created_at_ms": 1_700_000_000_123i64
        });
        for v in [omitted, nulls] {
            let dto: MessageDto = serde_json::from_value(v).expect("deserializes");
            assert_eq!(dto.reply_to, None);
            assert_eq!(dto.attachment, None);
        }
    }
}

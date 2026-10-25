//! Client world state shared between the UI thread and background network
//! tasks through `Arc<Mutex<ClientState>>`.
//!
//! The UI locks per frame (friends-scale data, short critical sections);
//! network tasks lock to push deltas and then call [`egui::Context::request_repaint`].
//!
//! `apply_server_msg` (in [`apply`]) is the single entry point through which
//! every server-pushed [`WsServerMsg`] mutates the world — the WS loop in
//! [`crate::net`] calls it, nothing else touches these fields ad hoc.
//! It only performs cheap mutations under the lock: the expensive tail of
//! each event (Megolm/Olm decrypt, engine bootstrap, SQLite plaintext and
//! message-row writes) is staged onto the crypto queue ([`worker`]) and run
//! by one worker thread holding no lock, which re-locks briefly to publish
//! its results. The single FIFO queue keeps per-channel decrypt order
//! identical to arrival order.
//!
//! # Submodules
//!
//! - [`mod@crate::state`]: the world ([`MainState`]) and the session root
//!   ([`ClientState`]), plus the small lock/time helpers every other
//!   submodule reaches for (`now_ms`, `guard`, `push_capped`, the queue
//!   caps, `TYPING_TTL_SECS`, `MAILBOX_STALE_MS`).
//! - [`worker`]: the deferred crypto queue — [`worker::CryptoJob`] plus the
//!   one-worker lifecycle that drains it.
//! - [`apply`]: [`apply::apply_server_msg`] (the WS receive entry point) and
//!   the file-envelope helpers shared between it and the worker.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use bysyc_common::protocol::{
    AccountBrief, AccountInfo, CallSignalKind, ChannelKind, DmChannel, FriendList, GuildInfo,
    MailboxItem, MessageDto,
};

use crate::crypto::{Engine, Envelope};
use crate::net::NetHandle;
use crate::store::Store;

mod apply;
mod worker;

// `backfill_plaintexts` (below, on MainState) hands off to the file-envelope
// helpers that live in `apply`; bring them in by the short names the rest of
// this module used to call them by.
use apply::{load_file_envelopes, retry_undecrypted};

// Re-export the public items that moved into the submodules so every
// `crate::state::*` / `state::*` call site continues to resolve unchanged.
pub use apply::{apply_server_msg, file_row_text, human_size, is_image_name};

/// Current Unix time in whole milliseconds.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Lock ignoring poisoning: one panicking thread must not take the UI down.
pub fn guard<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// How long a typing indicator stays valid after the last `Typing` event.
pub const TYPING_TTL_SECS: u64 = 6;

/// A mailbox item older than this is acked and dropped unread: session shares
/// older than a week predate any rotation window we care about (ADR 0001
/// rotates at 100 messages / 1 week), so they cannot unlock anything the
/// user still sees.
pub const MAILBOX_STALE_MS: i64 = 7 * 24 * 60 * 60 * 1000;

/// Caps for the producer→consumer queues the WS path pushes and other
/// subsystems drain per frame or per socket tick
/// ([`MainState::pending_signals`], [`MainState::pending_newcomers`],
/// [`MainState::outbox_acks`]): a flooding server must not grow client
/// memory without bound. Pushes past a cap drop the OLDEST entry.
pub(super) const MAX_PENDING_SIGNALS: usize = 128;
pub(super) const MAX_PENDING_NEWCOMERS: usize = 128;
pub(super) const MAX_OUTBOX_ACKS: usize = 1024;

/// Push `item` onto `v`, evicting the oldest entry once `cap` is reached
/// (the drains consume whatever survived; a dropped head is treated as
/// consumed rather than queued forever).
pub(super) fn push_capped<T>(v: &mut Vec<T>, item: T, cap: usize) {
    if v.len() >= cap {
        v.remove(0);
    }
    v.push(item);
}

// ---------------------------------------------------------------------------
// Phases
// ---------------------------------------------------------------------------

/// Top-level application phase. `Connecting` exists only between a
/// login/restore click and the first WS `Ready`; once [`Phase::LoggedIn`],
/// a dropped socket keeps the world and flips [`MainState::connection`].
#[allow(clippy::large_enum_variant)] // lives behind Arc<Mutex<ClientState>>; boxing the live variant would only add an alloc
pub enum Phase {
    /// No session — show the login view.
    Disconnected,
    /// Auth in flight or waiting for the first WS `Ready` (status text).
    Connecting(String),
    /// Signed in; the whole world lives in [`MainState`].
    LoggedIn(MainState),
}

/// Socket state while logged in.
pub enum ConnStatus {
    Online,
    /// Backing off before the next reconnect attempt (reason shown to user).
    Reconnecting(String),
}

/// What the main view is currently showing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Selection {
    /// A guild text channel.
    Channel(i64),
    /// A DM channel (id is the channel id, not the peer account id).
    Dm(i64),
    /// The friends home.
    Friends,
}

// ---------------------------------------------------------------------------
// Attachments (C4)
// ---------------------------------------------------------------------------

/// Progress of one attachment upload, shown above the composer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UploadPhase {
    /// Reading + AES-GCM encrypting the bytes (worker thread).
    Encrypting,
    /// `POST /attachments` + presigned `PUT` of the ciphertext.
    Uploading,
    /// Megolm session share (if needed) + message POST.
    Sending,
    /// Fully sent; the status row disappears on the next frame.
    Done,
    /// Terminal failure (message shown, dismissible).
    Failed(String),
}

/// One row of the upload strip above the composer.
#[derive(Clone, Debug)]
pub struct UploadStatus {
    /// Monotonic id; background tasks update their row by id.
    pub id: u64,
    /// File name.
    pub name: String,
    pub phase: UploadPhase,
}

// ---------------------------------------------------------------------------
// World
// ---------------------------------------------------------------------------

/// Everything the client knows once signed in.
pub struct MainState {
    pub account: AccountInfo,
    pub friends: Vec<AccountBrief>,
    pub incoming_requests: Vec<AccountBrief>,
    pub outgoing_requests: Vec<AccountBrief>,
    pub guilds: Vec<GuildInfo>,
    pub dms: Vec<DmChannel>,
    pub selected: Selection,
    /// Per-channel message cache, oldest first, newest last. Pending
    /// optimistic sends carry negative ids and stay at the tail.
    pub messages: HashMap<i64, Vec<MessageDto>>,
    /// Per-channel set of the message ids held in `messages` — the dedup
    /// index for `append_message`/`merge_messages`, kept in lockstep with
    /// the vec so dedup is a hash lookup instead of a linear scan per row.
    /// Optimistic temps (negative ids, pushed raw by the composer) are
    /// never tracked and never deduped.
    known_ids: HashMap<i64, HashSet<i64>>,
    /// Per-channel: who is typing and when their last event arrived.
    pub typing: HashMap<i64, (i64, Instant)>,
    /// Account ids currently holding a WS connection (from Ready + Presence).
    pub online: HashSet<i64>,
    /// Clone-able handle to REST + the WS outgoing queue.
    pub net: Option<NetHandle>,
    /// Channel ids with unseen messages (drives badges).
    pub unread: HashSet<i64>,
    /// Voice channels → current participants (complete snapshots, replaced).
    pub voice: HashMap<i64, Vec<AccountBrief>>,
    /// Relayed call signaling C5 drains; tuple is (from, call_id, kind).
    pub pending_signals: Vec<(i64, i64, CallSignalKind)>,
    /// Undelivered directed control items for C2 (crypto) to decrypt + ack.
    pub mailbox: Vec<MailboxItem>,
    /// Channels whose history was already fetched from the Instance.
    pub loaded: HashSet<i64>,
    /// Per channel: whether older server history exists past what we hold.
    pub has_more: HashMap<i64, bool>,
    /// Last transient error surfaced to the user.
    pub notice: Option<String>,
    /// Socket state.
    pub connection: ConnStatus,
    // -- E2EE (C3) ------------------------------------------------------------
    /// The crypto engine; `None` only if bootstrap failed (chat then refuses
    /// to send rather than going out in the clear).
    pub engine: Option<Arc<Engine>>,
    /// account id → base64 identity key, learned from every AccountBrief the
    /// server sends and from OTK-claim responses. Feeds Olm sender
    /// authentication (this is the trust-on-first-use set, v1).
    pub identities: HashMap<i64, String>,
    /// guild id → known member ids (owner + self + MemberJoined discoveries;
    /// the server does not push full rosters). Drives the share roster.
    pub guild_members: HashMap<i64, HashSet<i64>>,
    /// Channels we hold an outbound Megolm session for (persisted; drives
    /// newcomer sharing and bootstrap detection after a restart).
    pub outbound: HashSet<i64>,
    /// channel → session id of the outbound session as of the last send; a
    /// change means rotation, which re-triggers the share loop.
    pub outbound_sid: HashMap<i64, String>,
    /// (guild, member) pairs waiting for a share-to-newcomer task (drained by
    /// [`crate::net::drain_followups`]).
    pub pending_newcomers: Vec<(i64, i64)>,
    /// Mailbox ids to ack on the next drain (set by [`MainState::process_mailbox`]).
    pub outbox_acks: Vec<i64>,
    /// Latest guild invite code to show/copy: (guild name, code). Transient
    /// UI state that outlives the REST task, like [`MainState::notice`].
    pub invite: Option<(String, String)>,
    // -- Attachments (C4) -------------------------------------------------------
    /// Decoded [`Envelope::File`] payloads keyed by MESSAGE id: the
    /// attachment's content key/nonce exist only inside the E2EE envelope,
    /// so this map is what lets the UI fetch, decrypt and render files
    /// (see [`crate::views::attachments`]). Not persisted itself, but every
    /// producer also stores the envelope JSON in the local store, and
    /// [`MainState::backfill_plaintexts`] rebuilds this map from it — so
    /// rows keep their chip and preview after a restart instead of falling
    /// back to the stored "[file: …]" plaintext.
    pub file_meta: HashMap<i64, Envelope>,
    /// Live attachment uploads for the composer strip.
    pub uploads: Vec<UploadStatus>,
    /// Attachment ids with an image fetch/decode in flight (spawn guard).
    pub img_inflight: HashSet<i64>,
    /// Attachment ids whose fetch or decode failed terminally (render an
    /// "unavailable" note instead of retrying every frame).
    pub img_failed: HashSet<i64>,
    /// Chosen microphone device name (None = system default). Loaded from
    /// the local store at login and edited by the settings view; read by
    /// the call engine when it opens its cpal streams.
    pub audio_input: Option<String>,
    /// Chosen speaker/output device name (None = system default).
    pub audio_output: Option<String>,
    /// Last admin-minted registration invite code (shown + copied in Settings).
    pub reg_invite: Option<String>,
}

impl MainState {
    #[allow(clippy::too_many_arguments)]
    fn from_ready(
        account: AccountInfo,
        friends: Vec<AccountBrief>,
        incoming_requests: Vec<AccountBrief>,
        outgoing_requests: Vec<AccountBrief>,
        guilds: Vec<GuildInfo>,
        dms: Vec<DmChannel>,
        mailbox: Vec<MailboxItem>,
        boot: Option<EngineBoot>,
    ) -> Self {
        let online = friends.iter().filter(|f| f.online).map(|f| f.id).collect();
        let (engine, outbound) = match boot {
            Some(b) => (Some(b.engine), b.outbound),
            None => (None, HashSet::new()),
        };
        MainState {
            account,
            friends,
            incoming_requests,
            outgoing_requests,
            guilds,
            dms,
            selected: Selection::Friends,
            messages: HashMap::new(),
            known_ids: HashMap::new(),
            typing: HashMap::new(),
            online,
            net: None, // stamped by the WS task right after Ready is applied
            unread: HashSet::new(),
            voice: HashMap::new(),
            pending_signals: Vec::new(),
            mailbox,
            loaded: HashSet::new(),
            has_more: HashMap::new(),
            notice: None,
            connection: ConnStatus::Online,
            engine,
            identities: HashMap::new(),
            guild_members: HashMap::new(),
            outbound,
            outbound_sid: HashMap::new(),
            pending_newcomers: Vec::new(),
            outbox_acks: Vec::new(),
            invite: None,
            file_meta: HashMap::new(),
            uploads: Vec::new(),
            img_inflight: HashSet::new(),
            img_failed: HashSet::new(),
            audio_input: None,
            audio_output: None,
            reg_invite: None,
        }
    }

    /// The persisted microphone device name, if the user picked one in
    /// settings (None = system default). Read by [`crate::call`] when it
    /// opens its input stream.
    pub fn audio_input_device(&self) -> Option<String> {
        self.audio_input.clone()
    }

    /// The persisted speaker/output device name, if the user picked one.
    pub fn audio_output_device(&self) -> Option<String> {
        self.audio_output.clone()
    }

    /// The channel id the main view should render, if any.
    pub fn selected_channel(&self) -> Option<i64> {
        match self.selected {
            Selection::Channel(c) | Selection::Dm(c) => Some(c),
            Selection::Friends => None,
        }
    }

    pub fn is_selected_channel(&self, channel_id: i64) -> bool {
        self.selected_channel() == Some(channel_id)
    }

    /// Guild owning the currently selected channel, if a guild channel is
    /// selected.
    pub fn current_guild(&self) -> Option<&GuildInfo> {
        match self.selected {
            Selection::Channel(c) => self
                .guilds
                .iter()
                .find(|g| g.channels.iter().any(|ch| ch.id == c)),
            _ => None,
        }
    }

    /// First text channel of a guild (used when picking a guild in the nav).
    pub fn first_text_channel(&self, guild_id: i64) -> Option<i64> {
        self.guilds
            .iter()
            .find(|g| g.id == guild_id)?
            .channels
            .iter()
            .find(|c| c.kind == ChannelKind::Text)
            .map(|c| c.id)
    }

    /// Best-effort display name for an account id seen anywhere.
    pub fn account_name(&self, id: i64) -> String {
        if self.account.id == id {
            return self.account.username.clone();
        }
        self.friends
            .iter()
            .chain(self.dms.iter().map(|d| &d.peer))
            .chain(self.incoming_requests.iter())
            .chain(self.outgoing_requests.iter())
            .find(|a| a.id == id)
            .map(|a| a.username.clone())
            .unwrap_or_else(|| format!("#{id}"))
    }

    /// Display name of a channel: DMs render the peer's username.
    pub fn channel_name(&self, channel_id: i64) -> String {
        if let Some(dm) = self.dms.iter().find(|d| d.channel.id == channel_id) {
            return format!("@{}", dm.peer.username);
        }
        self.guilds
            .iter()
            .flat_map(|g| &g.channels)
            .find(|c| c.id == channel_id)
            .map(|c| format!("#{}", c.name))
            .unwrap_or_else(|| format!("channel {channel_id}"))
    }

    /// Append a server-confirmed message, deduplicating by id (the same dto
    /// can arrive via both the REST response and the WS echo).
    pub fn append_message(&mut self, dto: MessageDto) {
        if self
            .known_ids
            .entry(dto.channel_id)
            .or_default()
            .insert(dto.id)
        {
            self.messages.entry(dto.channel_id).or_default().push(dto);
        }
    }

    /// Replace the optimistic placeholder `temp_id` (negative) with the
    /// server-confirmed dto, deduplicating against what already arrived.
    pub fn replace_temp(&mut self, temp_id: i64, dto: MessageDto) {
        if let Some(v) = self.messages.get_mut(&dto.channel_id) {
            v.retain(|m| m.id != temp_id);
        }
        self.append_message(dto);
    }

    /// Union-merge a batch of messages into a channel, keeping the vector
    /// sorted oldest-first with pending temps pinned at the tail.
    pub fn merge_messages(&mut self, channel_id: i64, incoming: Vec<MessageDto>) {
        if incoming.is_empty() {
            return;
        }
        let mut fresh = Vec::with_capacity(incoming.len());
        {
            let ids = self.known_ids.entry(channel_id).or_default();
            for dto in incoming {
                if ids.insert(dto.id) {
                    fresh.push(dto);
                }
            }
        }
        if fresh.is_empty() {
            return;
        }
        let v = self.messages.entry(channel_id).or_default();
        v.extend(fresh);
        sort_messages(v);
    }

    /// Replace the friend graph from a fresh `GET /friends`.
    pub fn resync_friends(&mut self, fl: FriendList) {
        self.online = fl
            .friends
            .iter()
            .filter(|f| f.online)
            .map(|f| f.id)
            .collect();
        self.friends = fl.friends;
        self.incoming_requests = fl.incoming;
        self.outgoing_requests = fl.outgoing;
    }

    /// Replace the guild list from a fresh `GET /guilds`.
    pub fn resync_guilds(&mut self, guilds: Vec<GuildInfo>) {
        self.guilds = guilds;
        self.validate_selection();
    }

    /// Drop the selection if it no longer points at something we can see.
    pub fn validate_selection(&mut self) {
        match self.selected {
            Selection::Channel(c) => {
                if !self
                    .guilds
                    .iter()
                    .any(|g| g.channels.iter().any(|ch| ch.id == c))
                {
                    self.selected = Selection::Friends;
                }
            }
            Selection::Dm(c) => {
                if !self.dms.iter().any(|d| d.channel.id == c) {
                    self.selected = Selection::Friends;
                }
            }
            Selection::Friends => {}
        }
    }

    // -- E2EE helpers (C3) ------------------------------------------------------

    /// Seed derived crypto world state after (re)connect: identity keys from
    /// every AccountBrief the server handed us, and guild rosters seeded
    /// with owner + self. MemberJoined events widen the rosters over time,
    /// so seeding merges rather than replaces.
    fn seed_world(&mut self) {
        self.identities
            .insert(self.account.id, self.account.identity_key.clone());
        for a in self
            .friends
            .iter()
            .chain(self.incoming_requests.iter())
            .chain(self.outgoing_requests.iter())
            .chain(self.dms.iter().map(|d| &d.peer))
        {
            self.identities.insert(a.id, a.identity_key.clone());
        }
        for g in &self.guilds {
            let roster = self.guild_members.entry(g.id).or_default();
            roster.insert(g.owner_id);
            roster.insert(self.account.id);
        }
    }

    /// Who a channel's Megolm session must be shared with: the DM peer, or
    /// (guild channels) the owner + ourselves + every member discovered via
    /// `MemberJoined`. The sender's current session reaches exactly these
    /// accounts; history before a member's join point stays unreadable by
    /// design (ADR 0001).
    pub fn channel_peer_ids(&self, channel_id: i64) -> Vec<i64> {
        if let Some(dm) = self.dms.iter().find(|d| d.channel.id == channel_id) {
            return vec![dm.peer.id];
        }
        let Some(g) = self
            .guilds
            .iter()
            .find(|g| g.channels.iter().any(|c| c.id == channel_id))
        else {
            return Vec::new();
        };
        let mut ids: Vec<i64> = self
            .guild_members
            .get(&g.id)
            .map(|r| r.iter().copied().collect())
            .unwrap_or_default();
        if !ids.contains(&g.owner_id) {
            ids.push(g.owner_id);
        }
        if !ids.contains(&self.account.id) {
            ids.push(self.account.id);
        }
        ids
    }

    /// Drop a message from the live cache (an [`Envelope::Delete`] landed).
    pub fn remove_message(&mut self, channel_id: i64, target: i64) {
        if let Some(v) = self.messages.get_mut(&channel_id) {
            v.retain(|m| m.id != target);
        }
        if let Some(ids) = self.known_ids.get_mut(&channel_id) {
            ids.remove(&target);
        }
    }

    /// Retry decryption for cached history rows that still have no plaintext
    /// (e.g. loaded before the session share arrived), and rebuild
    /// [`MainState::file_meta`] from the envelopes persisted in the store —
    /// attachment rows from earlier runs already carry their placeholder
    /// plaintext, so the retry loop below would never visit them again (and
    /// our own sent rows are outside it by design: the engine holds no
    /// self-import). The heavy lifting lives in [`retry_undecrypted`] /
    /// [`load_file_envelopes`], which touch engine and store only — the WS
    /// `Ready` path runs them on the crypto worker; this method remains for
    /// callers that already hold the world (history pagination).
    pub fn backfill_plaintexts(&mut self, store: &Arc<Mutex<Store>>, channel_id: i64) {
        let known: HashSet<i64> = self.file_meta.keys().copied().collect();
        for (id, fe) in load_file_envelopes(store, channel_id, &known) {
            self.file_meta.insert(id, fe);
        }
        let Some(engine) = self.engine.clone() else {
            return;
        };
        let (_, files) = retry_undecrypted(&engine, self.account.id, store, channel_id);
        for (id, fe) in files {
            self.file_meta.insert(id, fe);
        }
    }
}

/// Ascending by id, with optimistic temps (negative ids) kept at the tail.
fn sort_messages(v: &mut [MessageDto]) {
    v.sort_by(|a, b| match (a.id < 0, b.id < 0) {
        (false, false) | (true, true) => a.id.cmp(&b.id),
        (true, false) => std::cmp::Ordering::Greater,
        (false, true) => std::cmp::Ordering::Less,
    });
}

// ---------------------------------------------------------------------------
// ClientState
// ---------------------------------------------------------------------------

/// A crypto engine built by the login/restore task before the WS `Ready`
/// arrives, so the first mailbox batch (session shares!) can decrypt the
/// moment the world exists.
pub struct EngineBoot {
    pub engine: Arc<Engine>,
    /// Persisted outbound-Megolm channel set loaded alongside the engine.
    pub outbound: HashSet<i64>,
}

/// Root state. `ws_generation` invalidates stale WS loops: every spawned
/// loop carries the generation current at its start and exits once the
/// counter moves (logout, or a new login superseding it).
pub struct ClientState {
    pub phase: Phase,
    pub ws_generation: u64,
    /// Last login/restore failure to show on the login view.
    pub login_error: Option<String>,
    /// Engine staged by login/restore, consumed by the first WS `Ready`.
    pub pending_engine: Option<EngineBoot>,
    /// Deferred crypto/store work drained by the crypto worker
    /// (see [`stage_crypto_job`]); owned here so each session has its own
    /// worker lifecycle and stale jobs die with the generation.
    jobs: Arc<worker::CryptoQueue>,
}

impl ClientState {
    pub fn new() -> Self {
        ClientState {
            phase: Phase::Disconnected,
            ws_generation: 0,
            login_error: None,
            pending_engine: None,
            jobs: Arc::new(worker::CryptoQueue::default()),
        }
    }

    pub fn main(&self) -> Option<&MainState> {
        match &self.phase {
            Phase::LoggedIn(m) => Some(m),
            _ => None,
        }
    }

    pub fn main_mut(&mut self) -> Option<&mut MainState> {
        match &mut self.phase {
            Phase::LoggedIn(m) => Some(m),
            _ => None,
        }
    }

    pub fn is_logged_in(&self) -> bool {
        matches!(self.phase, Phase::LoggedIn(_))
    }

    /// Tear the session down locally (does not touch the saved token — the
    /// caller does that where it knows the username). Bumps
    /// `ws_generation` so the owning WS loop stops reconnecting.
    pub fn sign_out_local(&mut self, reason: &str) {
        self.ws_generation += 1;
        self.phase = Phase::Disconnected;
        self.pending_engine = None;
        if !reason.is_empty() {
            self.login_error = Some(reason.to_string());
        }
    }
}

impl Default for ClientState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bysyc_common::protocol::{ChannelInfo, MessageKind};

    fn acct(id: i64, name: &str) -> AccountInfo {
        AccountInfo {
            id,
            username: name.into(),
            identity_key: format!("identity-{id}"),
            created_at_ms: 0,
            is_admin: false,
        }
    }

    fn brief(id: i64, name: &str) -> AccountBrief {
        AccountBrief {
            id,
            username: name.into(),
            identity_key: format!("identity-{id}"),
            online: false,
        }
    }

    fn channel(id: i64, guild: Option<i64>, kind: ChannelKind, name: &str) -> ChannelInfo {
        ChannelInfo {
            id,
            guild_id: guild,
            kind,
            name: name.into(),
        }
    }

    fn world() -> MainState {
        let me = acct(1, "me");
        let owner = brief(2, "owner");
        let peer = brief(3, "peer");
        let guilds = vec![GuildInfo {
            id: 100,
            name: "guild".into(),
            owner_id: 2,
            channels: vec![
                channel(101, Some(100), ChannelKind::Text, "general"),
                channel(102, Some(100), ChannelKind::Voice, "voice"),
            ],
        }];
        let dms = vec![DmChannel {
            channel: channel(200, None, ChannelKind::Dm, "dm"),
            peer: peer.clone(),
        }];
        MainState::from_ready(
            me,
            vec![owner.clone()],
            vec![],
            vec![],
            guilds,
            dms,
            Vec::new(),
            None,
        )
    }

    #[test]
    fn dm_roster_is_just_the_peer() {
        let m = world();
        assert_eq!(m.channel_peer_ids(200), vec![3]);
    }

    #[test]
    fn guild_roster_seeds_owner_and_self_then_widens() {
        let mut m = world();
        m.seed_world();
        let sorted = |mut v: Vec<i64>| {
            v.sort_unstable();
            v
        };
        // Owner + self, nobody else discovered yet.
        assert_eq!(sorted(m.channel_peer_ids(101)), vec![1, 2]);
        // A MemberJoined discovery widens the share roster.
        m.guild_members.entry(100).or_default().insert(9);
        assert_eq!(sorted(m.channel_peer_ids(101)), vec![1, 2, 9]);
        // Leaving shrinks it again.
        m.guild_members.get_mut(&100).unwrap().remove(&9);
        assert_eq!(sorted(m.channel_peer_ids(101)), vec![1, 2]);
        // Unknown channel shares with nobody.
        assert!(m.channel_peer_ids(999).is_empty());
    }

    #[test]
    fn seed_world_learns_every_visible_identity() {
        let mut m = world();
        m.seed_world();
        assert_eq!(m.identities.get(&1).map(String::as_str), Some("identity-1"));
        assert_eq!(m.identities.get(&2).map(String::as_str), Some("identity-2"));
        assert_eq!(m.identities.get(&3).map(String::as_str), Some("identity-3"));
        // Re-seeding after a reconnect must not lose anything.
        m.seed_world();
        assert_eq!(m.identities.len(), 3);
    }

    #[test]
    fn delete_envelope_removes_target_from_cache() {
        let mut m = world();
        for id in 1..=3 {
            m.append_message(bysyc_common::protocol::MessageDto {
                id,
                channel_id: 200,
                sender_id: 3,
                kind: MessageKind::Chat,
                content: format!("ct-{id}"),
                reply_to: None,
                attachment: None,
                created_at_ms: id,
            });
        }
        m.remove_message(200, 2);
        let ids: Vec<i64> = m.messages[&200].iter().map(|x| x.id).collect();
        assert_eq!(ids, vec![1, 3]);
    }

    #[test]
    fn human_size_units() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(1024), "1.0 KiB");
        assert_eq!(human_size(2048), "2.0 KiB");
        assert_eq!(human_size(12345), "12.1 KiB");
        assert_eq!(human_size(48 * 1024 * 1024), "48.0 MiB");
        assert_eq!(human_size(3 * 1024 * 1024 * 1024), "3.0 GiB");
        assert_eq!(human_size(-5), "0 B");
    }

    #[test]
    fn image_name_dispatch() {
        for name in [
            "cat.png",
            "photo.JPG",
            "photo.Jpeg",
            "anim.gif",
            "shot.webp",
            "a.b.png",
        ] {
            assert!(is_image_name(name), "{name} should be an image");
        }
        for name in [
            "notes.txt",
            "archive.tar.gz",
            "png",
            ".png/",
            "movie.mkv",
            "noext",
        ] {
            assert!(!is_image_name(name), "{name} should not be an image");
        }
    }

    /// Minimal in-memory [`crate::crypto::KeyStore`] so state tests can run
    /// a real engine (the crypto crate's own `MemKeyStore` is test-gated).
    #[derive(Default)]
    struct TestKeys(std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>);

    impl crate::crypto::KeyStore for TestKeys {
        fn get(&self, scope: &str) -> Option<Vec<u8>> {
            self.0.lock().unwrap().get(scope).cloned()
        }
        fn put(&self, scope: &str, blob: &[u8]) {
            self.0.lock().unwrap().insert(scope.into(), blob.to_vec());
        }
        fn delete(&self, scope: &str) {
            self.0.lock().unwrap().remove(scope);
        }
    }

    /// The receive path end-to-end up to the network boundary: a File
    /// envelope Megolm-encrypted into the channel decrypts during history
    /// backfill, lands in `file_meta` keyed by MESSAGE id, and its stored
    /// plaintext is the "[file: name (size)]" placeholder.
    #[test]
    fn file_envelope_backfill_stashes_meta_and_plaintext() {
        use crate::crypto::Engine;
        use bysyc_common::protocol::AttachmentMeta;

        const CH: i64 = 101;
        const MSG: i64 = 55;
        const SENDER: i64 = 2;
        const ATT: i64 = 300;

        let engine = Engine::new(Arc::new(TestKeys::default()), "pass".into()).unwrap();
        let fe = Envelope::File {
            name: "cat.png".into(),
            size: 12345,
            nonce: "bm9uY2U=".into(),
            key: "a2V5".into(),
            attachment_id: ATT,
        };
        // "Send" it: encrypt, then hand ourselves the index-0 session key
        // exactly the way a real receiver's mailbox share would.
        let (_, ct) = engine.megolm_encrypt(CH, &fe.to_json().unwrap()).unwrap();
        let share = engine.drain_pending_shares().pop().unwrap();
        engine
            .megolm_import(CH, SENDER, &share.session_id, &share.session_key)
            .unwrap();

        let store = Arc::new(Mutex::new(
            Store::open(std::path::Path::new(":memory:")).expect("open store"),
        ));
        let dto = bysyc_common::protocol::MessageDto {
            id: MSG,
            channel_id: CH,
            sender_id: SENDER,
            kind: MessageKind::Chat,
            content: ct,
            reply_to: None,
            attachment: Some(AttachmentMeta {
                id: ATT,
                name: "cat.png".into(),
                size: 12361,
                nonce: "bm9uY2U=".into(),
                encrypted: true,
            }),
            created_at_ms: 1,
        };
        {
            let s = guard(&store);
            let _ = s.append_message(&dto);
        }

        let mut m = world();
        m.engine = Some(Arc::new(engine));
        assert!(m.file_meta.is_empty());
        m.backfill_plaintexts(&store, CH);

        let stashed = m
            .file_meta
            .get(&MSG)
            .cloned()
            .expect("file envelope stashed");
        assert_eq!(stashed, fe, "stashed by message id, not attachment id");
        assert!(!m.file_meta.contains_key(&ATT), "keyed by message id");
        assert_eq!(
            guard(&store).plaintext(MSG).as_deref(),
            Some("[file: cat.png (12.1 KiB)]")
        );
    }

    /// The restart path for attachments: rows sent or decrypted in an
    /// earlier run already carry their plaintext (so the undecrypted-retry
    /// set is empty), and only the persisted envelope can bring the chip
    /// back. The rebuild runs even without an engine — it touches no crypto.
    #[test]
    fn file_envelopes_rebuild_meta_after_restart() {
        const CH: i64 = 101;
        const MSG: i64 = 77;
        let store = Arc::new(Mutex::new(
            Store::open(std::path::Path::new(":memory:")).expect("open store"),
        ));
        let fe = Envelope::File {
            name: "cat.png".into(),
            size: 12345,
            nonce: "bm9uY2U=".into(),
            key: "a2V5".into(),
            attachment_id: 300,
        };
        {
            let s = guard(&store);
            let _ = s.append_message(&bysyc_common::protocol::MessageDto {
                id: MSG,
                channel_id: CH,
                sender_id: 7,
                kind: MessageKind::Chat,
                content: "ct".into(),
                reply_to: None,
                attachment: None,
                created_at_ms: 1,
            });
            let _ = s.set_file_envelope(MSG, &fe.to_json().unwrap());
            let _ = s.set_plaintext(MSG, &file_row_text(&fe));
        }
        // A "restarted" world: empty `file_meta`, nothing left to decrypt.
        let mut m = world();
        assert!(m.file_meta.is_empty());
        assert!(guard(&store).undecrypted(CH).is_empty());
        m.backfill_plaintexts(&store, CH);
        assert_eq!(m.file_meta.get(&MSG), Some(&fe));
    }
}

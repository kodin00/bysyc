//! Client world state shared between the UI thread and background network
//! tasks through `Arc<Mutex<ClientState>>`.
//!
//! The UI locks per frame (friends-scale data, short critical sections);
//! network tasks lock to push deltas and then call [`egui::Context::request_repaint`].
//!
//! `apply_server_msg` is the single entry point through which every
//! server-pushed [`WsServerMsg`] mutates the world — the WS loop in
//! [`crate::net`] calls it, nothing else touches these fields ad hoc.
//! It only performs cheap mutations under the lock: the expensive tail of
//! each event (Megolm/Olm decrypt, engine bootstrap, SQLite plaintext and
//! message-row writes) is staged onto the crypto queue and run by one
//! worker thread holding no lock, which re-locks briefly to publish its
//! results. The single FIFO queue keeps per-channel decrypt order
//! identical to arrival order.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use bysyc_common::protocol::{
    AccountBrief, AccountInfo, CallSignalKind, ChannelKind, DmChannel, FriendList, GuildInfo,
    MailboxItem, MessageDto, MessageKind, WsClientBody, WsClientMsg, WsServerBody, WsServerMsg,
};
use eframe::egui::Context;

use crate::crypto::{Engine, Envelope};
use crate::net::NetHandle;
use crate::store::Store;

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
const MAX_PENDING_SIGNALS: usize = 128;
const MAX_PENDING_NEWCOMERS: usize = 128;
const MAX_OUTBOX_ACKS: usize = 1024;

/// Push `item` onto `v`, evicting the oldest entry once `cap` is reached
/// (the drains consume whatever survived; a dropped head is treated as
/// consumed rather than queued forever).
fn push_capped<T>(v: &mut Vec<T>, item: T, cap: usize) {
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
}

impl MainState {
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
        }
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
        if self.known_ids.entry(dto.channel_id).or_default().insert(dto.id) {
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

/// Result of decrypting one message ciphertext into renderable text.
enum Decrypted {
    Text(String),
    /// A File envelope (C4): the caller stashes it into
    /// [`MainState::file_meta`] and renders the "[file: …]" placeholder.
    File(Envelope),
    /// A Delete envelope: hide `target` (and the carrier).
    Deleted(i64),
    /// Could not decrypt or parse.
    Failed,
}

/// Megolm-decrypt `content` from `sender` in `channel` and map the envelope
/// to its renderable form. File envelopes come back whole so the caller can
/// keep their key/nonce; their display text is [`file_row_text`].
fn decrypt_envelope_text(engine: &Engine, channel: i64, sender: i64, content: &str) -> Decrypted {
    let Ok(plaintext) = engine.megolm_decrypt(channel, sender, "", content) else {
        return Decrypted::Failed;
    };
    match serde_json::from_str::<Envelope>(&plaintext) {
        Ok(Envelope::Chat { text, .. }) => Decrypted::Text(text),
        Ok(fe @ Envelope::File { .. }) => Decrypted::File(fe),
        Ok(Envelope::Delete { target }) => Decrypted::Deleted(target),
        Ok(Envelope::SessionShare { .. }) | Err(_) => Decrypted::Failed,
    }
}

/// Persist a File envelope next to its message row so attachment rendering
/// survives a restart: `file_meta` is RAM-only, sender rows can never be
/// re-decrypted (the engine holds no Megolm self-import), and receiver rows
/// leave the `undecrypted` retry set once their plaintext lands. A failure
/// only costs the chip after the next restart, so it is logged, not
/// propagated.
fn persist_file_envelope(store: &Arc<Mutex<Store>>, msg_id: i64, fe: &Envelope) {
    if let Ok(json) = fe.to_json() {
        if let Err(e) = guard(store).set_file_envelope(msg_id, &json) {
            eprintln!("bysyc: persisting file envelope for message {msg_id} failed: {e}");
        }
    }
}

/// File envelopes persisted for `channel_id` whose message row has no chip
/// stashed yet (`known` = the ids already in `file_meta`). The restart half
/// of [`MainState::backfill_plaintexts`]: persisted envelopes are the only
/// thing that can bring a chip back once the row carries its placeholder
/// plaintext. Store reads only — no state access.
fn load_file_envelopes(
    store: &Arc<Mutex<Store>>,
    channel_id: i64,
    known: &HashSet<i64>,
) -> Vec<(i64, Envelope)> {
    let mut out = Vec::new();
    for (id, json) in guard(store).file_envelopes(channel_id) {
        if !known.contains(&id) {
            if let Ok(fe) = Envelope::from_json(&json) {
                out.push((id, fe));
            }
        }
    }
    out
}

/// Retry decryption for every still-NULL row of `channel_id` (rows cached
/// before the session share arrived), persisting plaintexts and file
/// envelopes as they land. Engine calls first, store writes batched after —
/// the engine pickles into the store while we hold no store lock (lock
/// order state → engine → store). Returns the plaintexts written and the
/// File envelopes stashed, for the caller to publish into `file_meta`.
/// Touches engine and store only — safe to run with no state lock held.
fn retry_undecrypted(
    engine: &Engine,
    own_id: i64,
    store: &Arc<Mutex<Store>>,
    channel_id: i64,
) -> (Vec<(i64, String)>, Vec<(i64, Envelope)>) {
    let rows = guard(store).undecrypted(channel_id);
    let mut texts: Vec<(i64, String)> = Vec::new();
    let mut files: Vec<(i64, Envelope)> = Vec::new();
    for (id, sender, content) in rows {
        if sender == own_id {
            continue; // own rows get their plaintext from the send task
        }
        match decrypt_envelope_text(engine, channel_id, sender, &content) {
            Decrypted::Text(text) => texts.push((id, text)),
            Decrypted::File(fe) => {
                let line = file_row_text(&fe);
                persist_file_envelope(store, id, &fe);
                files.push((id, fe));
                texts.push((id, line));
            }
            Decrypted::Deleted(_) | Decrypted::Failed => {}
        }
    }
    if !texts.is_empty() {
        let s = guard(store);
        for (id, text) in &texts {
            let _ = s.set_plaintext(*id, text);
        }
    }
    (texts, files)
}

/// One-liner shown for a File envelope row (also stored as the message
/// plaintext, so the row still reads sensibly after a restart).
pub fn file_row_text(fe: &Envelope) -> String {
    match fe {
        Envelope::File { name, size, .. } => {
            format!("[file: {name} ({})]", human_size(*size))
        }
        _ => "[file]".into(),
    }
}

/// Human-readable byte size: "0 B", "512 B", "2.0 KiB", "48.0 MiB", …
pub fn human_size(bytes: i64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let bytes = bytes.max(0); // negative sizes format as 0 B
    let mut size = bytes as f64;
    let mut unit = 0usize;
    while size >= 1024.0 && unit + 1 < UNITS.len() {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}

/// Whether a file name looks like a directly renderable image, by extension
/// (png/jpg/jpeg/gif/webp, case-insensitive).
pub fn is_image_name(name: &str) -> bool {
    match name.rsplit_once('.') {
        Some((_, ext)) => matches!(
            ext.to_ascii_lowercase().as_str(),
            "png" | "jpg" | "jpeg" | "gif" | "webp"
        ),
        None => false,
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
        assert!(m.file_meta.get(&ATT).is_none(), "keyed by message id");
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
    jobs: Arc<CryptoQueue>,
}

impl ClientState {
    pub fn new() -> Self {
        ClientState {
            phase: Phase::Disconnected,
            ws_generation: 0,
            login_error: None,
            pending_engine: None,
            jobs: Arc::new(CryptoQueue::default()),
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

// ---------------------------------------------------------------------------
// Crypto worker
// ---------------------------------------------------------------------------

/// Deferred crypto/store work: everything the WS receive path used to run
/// while holding the state mutex — Megolm/Olm decrypt, engine bootstrap
/// (1024-round KDF), plaintext and message-row writes. Jobs are staged in
/// arrival order, executed sequentially by one worker thread holding no
/// locks, and published back under a brief state lock; the single FIFO
/// keeps decrypt order per channel identical to arrival order.
enum CryptoJob {
    /// Megolm-decrypt one incoming chat message, persist its plaintext (or
    /// apply its Delete envelope), then insert the row into the live cache.
    Chat { generation: u64, dto: MessageDto },
    /// Hide a deleted message in the store and live cache. Queued (not
    /// applied inline) so it lands after any still-pending decrypt of the
    /// same row; both removals are idempotent.
    Deleted {
        generation: u64,
        channel_id: i64,
        message_id: i64,
    },
    /// Olm-decrypt + import a batch of mailbox items, ack what was consumed
    /// and retry-decrypt every channel a fresh share unlocked.
    Mailbox { generation: u64, items: Vec<MailboxItem> },
    /// Bootstrap the engine from the local store when login staged none
    /// (crash between WS connect and login task). The KDF plus unpickling
    /// of every session is far too slow for the state lock the UI needs
    /// every frame.
    EnsureEngine { generation: u64, username: String },
    /// Retry decryption for one loaded channel's cached rows and rebuild
    /// its attachment chips from persisted envelopes.
    Backfill { generation: u64, channel_id: i64 },
}

/// The staging queue plus a one-worker latch. Locking is leaf-level:
/// staging happens while the state lock may be held (order state → queue);
/// the worker takes the queue lock only to pop or to stage a follow-up,
/// never while holding anything else, so the two locks never nest the
/// other way around.
#[derive(Default)]
struct CryptoQueue {
    inner: Mutex<CryptoQueueInner>,
}

#[derive(Default)]
struct CryptoQueueInner {
    queue: VecDeque<CryptoJob>,
    /// Whether a worker thread currently exists. Set under `inner` before
    /// spawning; cleared by the worker when it observes the queue empty
    /// under the same lock — so a job staged in any interleaving either
    /// reaches the running worker or spawns a fresh one.
    worker_alive: bool,
}

/// Append `job` and make sure exactly one worker thread is draining the
/// queue (see [`CryptoWorker::run`] for the empty-exit protocol).
fn stage_crypto_job(
    q: &Arc<CryptoQueue>,
    job: CryptoJob,
    state: &Arc<Mutex<ClientState>>,
    store: &Arc<Mutex<Store>>,
    ctx: &Context,
) {
    let spawn = {
        let mut inner = guard(&q.inner);
        inner.queue.push_back(job);
        if inner.worker_alive {
            false
        } else {
            inner.worker_alive = true;
            true
        }
    };
    if spawn {
        let q = Arc::clone(q);
        let state = Arc::clone(state);
        let store = Arc::clone(store);
        let ctx = ctx.clone();
        std::thread::spawn(move || CryptoWorker { q, state, store, ctx }.run());
    }
}

/// Everything a worker thread needs: the queue (for the follow-up jobs it
/// stages itself) plus the world handles it gathers from and publishes to.
struct CryptoWorker {
    q: Arc<CryptoQueue>,
    state: Arc<Mutex<ClientState>>,
    store: Arc<Mutex<Store>>,
    ctx: Context,
}

impl CryptoWorker {
    /// Pop and run jobs until the queue is empty, then exit (the latch
    /// clears under the queue lock, atomically with the empty check, so an
    /// idle session holds no thread and nothing staged can be stranded).
    /// A panicking job is caught and logged rather than killing the worker:
    /// the latch would otherwise strand every job staged behind it.
    fn run(&self) {
        loop {
            let job = {
                let mut inner = guard(&self.q.inner);
                match inner.queue.pop_front() {
                    Some(job) => job,
                    None => {
                        inner.worker_alive = false;
                        return;
                    }
                }
            };
            if let Err(p) =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.job(job)))
            {
                eprintln!("bysyc: crypto worker job panicked: {p:?}");
            }
        }
    }

    /// Dispatch one job. Every handler re-checks the generation under its
    /// gather lock and drops stale work before touching the engine or
    /// store (sign-out bumped the generation) — except `deleted`, whose
    /// idempotent store write always applies, exactly as this branch's
    /// store delete ran unconditionally before the worker existed.
    fn job(&self, job: CryptoJob) {
        match job {
            CryptoJob::Chat { generation, dto } => self.chat(generation, dto),
            CryptoJob::Deleted {
                generation,
                channel_id,
                message_id,
            } => self.deleted(generation, channel_id, message_id),
            CryptoJob::Mailbox { generation, items } => self.mailbox(generation, items),
            CryptoJob::EnsureEngine { generation, username } => {
                self.ensure_engine(generation, username)
            }
            CryptoJob::Backfill { generation, channel_id } => {
                self.backfill(generation, channel_id)
            }
        }
    }

    /// What `apply_chat_message` used to do under the state lock, now with
    /// the decrypt outside it: Megolm-decrypt, persist the plaintext (or
    /// apply the Delete), then a brief re-lock to publish the row (or the
    /// delete's effect) and the file chip, plus a repaint. Our own sends
    /// skip decryption: the send task already stored the plaintext from
    /// the REST response, and the engine deliberately holds no
    /// self-import. Undecryptable rows get a terminal "[undecryptable]"
    /// marker; with no engine the row stays NULL and renders as
    /// "[encrypted]" until backfill can retry it.
    fn chat(&self, generation: u64, dto: MessageDto) {
        let msg_id = dto.id;
        let channel_id = dto.channel_id;
        let (engine, own_id) = {
            let st = guard(&self.state);
            if st.ws_generation != generation {
                return;
            }
            let Some(m) = st.main() else { return };
            (m.engine.clone(), m.account.id)
        };
        let mut file = None;
        let mut deleted = None;
        let show = if dto.sender_id == own_id {
            true
        } else if let Some(engine) = engine {
            match decrypt_envelope_text(&engine, channel_id, dto.sender_id, &dto.content) {
                Decrypted::Text(text) => {
                    guard(&self.store).set_plaintext(msg_id, &text).ok();
                    true
                }
                Decrypted::File(fe) => {
                    // The attachment's key/nonce live only in this
                    // envelope: stash it (C4's UI renders from
                    // `file_meta`), persist it so the row survives a
                    // restart, then store the placeholder text like any
                    // other row.
                    let line = file_row_text(&fe);
                    persist_file_envelope(&self.store, msg_id, &fe);
                    guard(&self.store).set_plaintext(msg_id, &line).ok();
                    file = Some(fe);
                    true
                }
                Decrypted::Deleted(target) => {
                    let s = guard(&self.store);
                    let _ = s.delete_message(target);
                    let _ = s.delete_message(msg_id); // carrier never renders again
                    deleted = Some(target);
                    false
                }
                Decrypted::Failed => {
                    guard(&self.store).set_plaintext(msg_id, "[undecryptable]").ok();
                    true
                }
            }
        } else {
            true // no engine yet: row stays NULL, renders "[encrypted]"
        };
        let repaint = {
            let mut st = guard(&self.state);
            if st.ws_generation != generation {
                return;
            }
            match st.main_mut() {
                Some(m) => {
                    if let Some(target) = deleted {
                        m.remove_message(channel_id, target);
                    }
                    if show {
                        m.append_message(dto);
                        if !m.is_selected_channel(channel_id) {
                            m.unread.insert(channel_id);
                        }
                    }
                    if let Some(fe) = file {
                        m.file_meta.insert(msg_id, fe);
                    }
                    true
                }
                None => false,
            }
        };
        if repaint {
            self.ctx.request_repaint();
        }
    }

    /// Hide a deleted message: the store write first (idempotent), then a
    /// brief re-lock to drop the live row. The queue guarantees this runs
    /// after any still-pending decrypt of the same row.
    fn deleted(&self, generation: u64, channel_id: i64, message_id: i64) {
        let _ = guard(&self.store).delete_message(message_id);
        let repaint = {
            let mut st = guard(&self.state);
            if st.ws_generation != generation {
                return;
            }
            match st.main_mut() {
                Some(m) => {
                    m.remove_message(channel_id, message_id);
                    true
                }
                None => false,
            }
        };
        if repaint {
            self.ctx.request_repaint();
        }
    }

    /// What `process_mailbox` used to do under the state lock, now with the
    /// Olm work outside it: Olm-decrypt each item, expect an
    /// [`Envelope::SessionShare`], import the Megolm key. Items whose
    /// sender identity is not known yet are kept (not acked) for a later
    /// retry; stale items (older than [`MAILBOX_STALE_MS`]) and
    /// undecryptable/malformed ones are acked and dropped — the mailbox
    /// must never block. Publish re-locks briefly to return the keeps; acks
    /// flush straight out when the socket handle exists, else they queue
    /// in [`MainState::outbox_acks`] for the WS loop's follow-up drain
    /// (there is no handle at the first Ready yet).
    fn mailbox(&self, generation: u64, items: Vec<MailboxItem>) {
        let (engine, identities) = {
            let st = guard(&self.state);
            if st.ws_generation != generation {
                return;
            }
            let Some(m) = st.main() else { return };
            let mut identities = HashMap::with_capacity(items.len());
            for it in &items {
                if let Some(key) = m.identities.get(&it.sender_id) {
                    identities.insert(it.sender_id, key.clone());
                }
            }
            (m.engine.clone(), identities)
        };
        let mut keep = Vec::new();
        let mut acks: Vec<i64> = Vec::new();
        let mut imported: Vec<i64> = Vec::new();
        if let Some(engine) = engine {
            let now = now_ms();
            for item in items {
                if now.saturating_sub(item.created_at_ms) > MAILBOX_STALE_MS {
                    acks.push(item.id);
                    continue;
                }
                let Some(identity) = identities.get(&item.sender_id) else {
                    keep.push(item); // identity unknown yet; retry once learned
                    continue;
                };
                match engine.olm_decrypt_from(item.sender_id, identity, &item.content) {
                    Ok(plaintext) => match serde_json::from_str::<Envelope>(&plaintext) {
                        Ok(Envelope::SessionShare {
                            channel_id,
                            session_id,
                            session_key,
                        }) => {
                            match engine.megolm_import(
                                channel_id,
                                item.sender_id,
                                &session_id,
                                &session_key,
                            ) {
                                Ok(()) => imported.push(channel_id),
                                Err(e) => {
                                    eprintln!(
                                        "bysyc: megolm import failed (channel {channel_id}): {e}"
                                    )
                                }
                            }
                            acks.push(item.id);
                        }
                        _ => acks.push(item.id), // not a share → malformed for us: skip
                    },
                    Err(_) => acks.push(item.id), // undecryptable: ack + skip
                }
            }
        } else {
            keep = items; // no engine: keep everything, retry after bootstrap
        }
        let flush_direct;
        {
            let mut st = guard(&self.state);
            if st.ws_generation != generation {
                return;
            }
            let Some(m) = st.main_mut() else { return };
            m.mailbox.extend(keep);
            flush_direct = m.net.is_some();
            if !flush_direct {
                for &id in &acks {
                    push_capped(&mut m.outbox_acks, id, MAX_OUTBOX_ACKS);
                }
            }
        }
        if flush_direct && !acks.is_empty() {
            let handle = guard(&self.state).main().and_then(|m| m.net.clone());
            let sent = match handle {
                Some(h) => h
                    .out
                    .try_send(WsClientMsg {
                        id: crate::net::next_msg_id(),
                        body: WsClientBody::AckMailbox {
                            ids: acks.clone(),
                        },
                    })
                    .is_ok(),
                None => false,
            };
            if !sent {
                let mut st = guard(&self.state);
                if let Some(m) = st.main_mut() {
                    for &id in &acks {
                        push_capped(&mut m.outbox_acks, id, MAX_OUTBOX_ACKS);
                    }
                }
            }
        }
        // A freshly imported session may unlock history we already cached —
        // stage a backfill behind whatever is already queued.
        for channel_id in imported {
            stage_crypto_job(
                &self.q,
                CryptoJob::Backfill { generation, channel_id },
                &self.state,
                &self.store,
                &self.ctx,
            );
        }
        if !acks.is_empty() {
            self.ctx.request_repaint();
        }
    }

    /// Build the engine when login staged none: the KDF, unpickling of
    /// every session and the initial re-persist all happen on this thread;
    /// a brief re-lock then attaches the engine (and its persisted outbound
    /// set) or surfaces the failure notice.
    fn ensure_engine(&self, generation: u64, username: String) {
        if guard(&self.state).ws_generation != generation {
            return; // session superseded — no KDF for a dead world
        }
        let boot = crate::store::bootstrap_engine(&self.store, &username);
        let repaint = {
            let mut st = guard(&self.state);
            if st.ws_generation != generation {
                return;
            }
            match st.main_mut() {
                Some(m) if m.engine.is_none() => match boot {
                    Ok((engine, outbound)) => {
                        m.engine = Some(engine);
                        m.outbound.extend(outbound);
                        true
                    }
                    Err(e) => {
                        eprintln!("bysyc: {e}");
                        m.notice = Some("crypto engine unavailable — sending disabled".into());
                        true
                    }
                },
                _ => false,
            }
        };
        if repaint {
            self.ctx.request_repaint();
        }
    }

    /// Worker-side of [`MainState::backfill_plaintexts`]: the same retry
    /// pass ([`retry_undecrypted`]) plus the persisted-envelope rebuild
    /// ([`load_file_envelopes`]), run with no state lock held; only the
    /// resulting `file_meta` insertions and the repaint need the world.
    fn backfill(&self, generation: u64, channel_id: i64) {
        let (engine, own_id, known) = {
            let st = guard(&self.state);
            if st.ws_generation != generation {
                return;
            }
            let Some(m) = st.main() else { return };
            (
                m.engine.clone(),
                m.account.id,
                m.file_meta.keys().copied().collect::<HashSet<i64>>(),
            )
        };
        let mut files = load_file_envelopes(&self.store, channel_id, &known);
        let mut changed = !files.is_empty();
        if let Some(engine) = engine {
            let (texts, decrypted_files) =
                retry_undecrypted(&engine, own_id, &self.store, channel_id);
            changed = changed || !texts.is_empty();
            files.extend(decrypted_files);
        }
        if !changed {
            return;
        }
        let repaint = {
            let mut st = guard(&self.state);
            if st.ws_generation != generation {
                return;
            }
            match st.main_mut() {
                Some(m) => {
                    for (id, fe) in files {
                        m.file_meta.insert(id, fe);
                    }
                    true
                }
                None => false,
            }
        };
        if repaint {
            self.ctx.request_repaint();
        }
    }
}

// ---------------------------------------------------------------------------
// Server message application
// ---------------------------------------------------------------------------

/// Apply one server-pushed WS message to the world and request a repaint.
/// Returns `true` when the message was `Ready`.
///
/// Only cheap mutations happen under the state lock: the world swap and the
/// roster/identity updates below, plus staging the expensive tail of each
/// event — Megolm/Olm decrypt, engine bootstrap (KDF), plaintext and
/// message-row writes — onto the crypto queue (`CryptoJob`), drained
/// sequentially by the crypto worker with no lock held. Publishing re-locks
/// briefly, so a burst of incoming messages can no longer freeze the UI
/// thread, and per-channel decrypt order still matches arrival order (one
/// FIFO queue, one worker).
///
/// The WS task stamps `MainState::net` itself right after a `Ready` (it owns
/// the handle). Message persistence happens in the caller *before* this runs
/// (the caller holds the store and the raw dto); lock order is
/// state → queue, then engine → store on the worker — never the reverse.
pub fn apply_server_msg(
    state: &Arc<Mutex<ClientState>>,
    store: &Arc<Mutex<Store>>,
    ctx: &Context,
    msg: WsServerMsg,
) -> bool {
    let mut st = guard(state);
    let generation = st.ws_generation;
    let q = Arc::clone(&st.jobs);
    let mut jobs: Vec<CryptoJob> = Vec::new();
    let mut was_ready = false;
    match msg.body {
        WsServerBody::Ready {
            account,
            friends,
            incoming_requests,
            outgoing_requests,
            guilds,
            dm_channels,
            mailbox,
        } => {
            was_ready = true;
            st.login_error = None;
            if let Phase::LoggedIn(m) = &mut st.phase {
                // Reconnect resync: replace the server-owned world, keep
                // local caches (messages, selection, voice, pending signals,
                // crypto state).
                m.online = friends.iter().filter(|f| f.online).map(|f| f.id).collect();
                m.account = account;
                m.friends = friends;
                m.incoming_requests = incoming_requests;
                m.outgoing_requests = outgoing_requests;
                m.guilds = guilds;
                m.dms = dm_channels;
                m.mailbox = mailbox;
                m.connection = ConnStatus::Online;
                m.validate_selection();
            } else {
                let boot = st.pending_engine.take();
                st.phase = Phase::LoggedIn(MainState::from_ready(
                    account,
                    friends,
                    incoming_requests,
                    outgoing_requests,
                    guilds,
                    dm_channels,
                    mailbox,
                    boot,
                ));
            }
            if let Some(m) = st.main_mut() {
                m.seed_world();
                // The crypto tail stages onto the worker, in the order the
                // synchronous path used to run it: the engine must exist
                // before the mailbox is processed (session shares ride in
                // it) — login/restore stage one in `pending_engine`, and if
                // it is missing (crash between WS connect and login task?)
                // the worker bootstraps from the local store — then the
                // mailbox, then a backfill per loaded channel (a share that
                // arrived while we were offline may unlock history cached
                // from the previous session).
                let username = m.account.username.clone();
                let need_boot = m.engine.is_none();
                let items = std::mem::take(&mut m.mailbox);
                let loaded: Vec<i64> = m.loaded.iter().copied().collect();
                if need_boot {
                    jobs.push(CryptoJob::EnsureEngine { generation, username });
                }
                if !items.is_empty() {
                    jobs.push(CryptoJob::Mailbox { generation, items });
                }
                for ch in loaded {
                    jobs.push(CryptoJob::Backfill {
                        generation,
                        channel_id: ch,
                    });
                }
            }
        }
        WsServerBody::Message(dto) => {
            // v1 has no chat-routed control payloads; drop those, stage the
            // rest — the worker decrypts, persists and publishes the row.
            if dto.kind != MessageKind::Control && st.main().is_some() {
                jobs.push(CryptoJob::Chat { generation, dto });
            }
        }
        WsServerBody::MessageDeleted {
            channel_id,
            message_id,
        } => {
            // Drop the row from the live cache and SQLite alike; the
            // deleter's own UI already did both when its DELETE returned
            // (the broadcast reaches them too), so this may be a repeat —
            // both removals are idempotent. A message we never had (a
            // channel opened after the delete) is a no-op on either side.
            // Queued (not applied inline) so the delete lands after any
            // still-pending decrypt of the same row: the worker is FIFO.
            jobs.push(CryptoJob::Deleted {
                generation,
                channel_id,
                message_id,
            });
        }
        WsServerBody::MailboxAppend(item) => {
            if let Some(m) = st.main_mut() {
                m.mailbox.push(item);
                let items = std::mem::take(&mut m.mailbox);
                jobs.push(CryptoJob::Mailbox { generation, items });
            }
        }
        WsServerBody::Presence { account_id, online } => {
            if let Some(m) = st.main_mut() {
                if online {
                    m.online.insert(account_id);
                } else {
                    m.online.remove(&account_id);
                }
                if let Some(f) = m.friends.iter_mut().find(|f| f.id == account_id) {
                    f.online = online;
                }
            }
        }
        WsServerBody::Typing {
            channel_id,
            account_id,
        } => {
            if let Some(m) = st.main_mut() {
                m.typing.insert(channel_id, (account_id, Instant::now()));
            }
        }
        WsServerBody::FriendRequested { from } => {
            if let Some(m) = st.main_mut() {
                m.identities.insert(from.id, from.identity_key.clone());
                if !m.incoming_requests.iter().any(|a| a.id == from.id) {
                    m.incoming_requests.push(from);
                }
            }
        }
        WsServerBody::FriendRequestAccepted { by } => {
            if let Some(m) = st.main_mut() {
                m.identities.insert(by.id, by.identity_key.clone());
                m.outgoing_requests.retain(|a| a.id != by.id);
                if !m.friends.iter().any(|a| a.id == by.id) {
                    if by.online {
                        m.online.insert(by.id);
                    }
                    m.friends.push(by);
                }
            }
        }
        WsServerBody::FriendRemoved { account_id } => {
            if let Some(m) = st.main_mut() {
                m.friends.retain(|a| a.id != account_id);
                m.dms.retain(|d| d.peer.id != account_id);
                m.online.remove(&account_id);
            }
        }
        WsServerBody::GuildJoined { guild } => {
            if let Some(m) = st.main_mut() {
                let roster = m.guild_members.entry(guild.id).or_default();
                roster.insert(guild.owner_id);
                roster.insert(m.account.id);
                match m.guilds.iter_mut().find(|g| g.id == guild.id) {
                    Some(existing) => *existing = guild,
                    None => m.guilds.push(guild),
                }
            }
        }
        WsServerBody::ChannelCreated { guild_id, channel } => {
            if let Some(m) = st.main_mut() {
                if let Some(g) = m.guilds.iter_mut().find(|g| g.id == guild_id) {
                    if !g.channels.iter().any(|c| c.id == channel.id) {
                        g.channels.push(channel);
                    }
                }
            }
        }
        WsServerBody::ChannelDeleted {
            guild_id: _,
            channel_id,
        } => {
            if let Some(m) = st.main_mut() {
                for g in &mut m.guilds {
                    g.channels.retain(|c| c.id != channel_id);
                }
                if m.is_selected_channel(channel_id) {
                    m.selected = Selection::Friends;
                }
            }
        }
        WsServerBody::MemberJoined { guild_id, account } => {
            if let Some(m) = st.main_mut() {
                m.identities
                    .insert(account.id, account.identity_key.clone());
                m.guild_members
                    .entry(guild_id)
                    .or_default()
                    .insert(account.id);
                // Their session share may already sit in the mailbox.
                if !m.mailbox.is_empty() {
                    let items = std::mem::take(&mut m.mailbox);
                    jobs.push(CryptoJob::Mailbox { generation, items });
                }
                if account.id != m.account.id {
                    push_capped(
                        &mut m.pending_newcomers,
                        (guild_id, account.id),
                        MAX_PENDING_NEWCOMERS,
                    );
                }
            }
        }
        WsServerBody::MemberLeft {
            guild_id,
            account_id,
        } => {
            if let Some(m) = st.main_mut() {
                if let Some(roster) = m.guild_members.get_mut(&guild_id) {
                    roster.remove(&account_id);
                }
            }
        }
        WsServerBody::VoiceState {
            channel_id,
            participants,
        } => {
            if let Some(m) = st.main_mut() {
                for p in &participants {
                    m.identities.insert(p.id, p.identity_key.clone());
                }
                if participants.is_empty() {
                    m.voice.remove(&channel_id); // empty snapshot = call ended
                } else {
                    m.voice.insert(channel_id, participants);
                }
            }
        }
        WsServerBody::CallSignal {
            call_id,
            from,
            kind,
        } => {
            if let Some(m) = st.main_mut() {
                push_capped(&mut m.pending_signals, (from, call_id, kind), MAX_PENDING_SIGNALS);
            }
        }
        WsServerBody::Error {
            code: _,
            reply_to: _,
            message,
        } => {
            if let Some(m) = st.main_mut() {
                m.notice = Some(message);
            }
        }
    }
    drop(st);
    // Stage after releasing the state lock: spawning the worker (first job
    // of a burst) never happens under it. Job order = arrival order.
    for job in jobs {
        stage_crypto_job(&q, job, state, store, ctx);
    }
    ctx.request_repaint();
    was_ready
}

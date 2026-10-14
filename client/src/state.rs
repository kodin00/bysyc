//! Client world state shared between the UI thread and background network
//! tasks through `Arc<Mutex<ClientState>>`.
//!
//! The UI locks per frame (friends-scale data, short critical sections);
//! network tasks lock to push deltas and then call [`egui::Context::request_repaint`].
//!
//! `apply_server_msg` is the single entry point through which every
//! server-pushed [`WsServerMsg`] mutates the world — the WS loop in
//! [`crate::net`] calls it, nothing else touches these fields ad hoc.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use bysyc_common::protocol::{
    AccountBrief, AccountInfo, CallSignalKind, ChannelKind, DmChannel, FriendList, GuildInfo,
    MailboxItem, MessageDto, MessageKind, WsServerBody, WsServerMsg,
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
        let v = self.messages.entry(dto.channel_id).or_default();
        if !v.iter().any(|m| m.id == dto.id) {
            v.push(dto);
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
        let v = self.messages.entry(channel_id).or_default();
        for dto in incoming {
            if !v.iter().any(|m| m.id == dto.id) {
                v.push(dto);
            }
        }
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
    }

    /// Decrypt one incoming chat message (Megolm) and persist its plaintext.
    /// Returns `false` when the message must not render at all — the carrier
    /// of a Delete envelope. Our own sends skip decryption: the send task
    /// already stored the plaintext from the REST response, and the engine
    /// deliberately holds no self-import. Undecryptable rows get a terminal
    /// "[undecryptable]" marker; with no engine the row stays NULL and
    /// renders as "[encrypted]" until backfill can retry it.
    fn apply_chat_message(&mut self, store: &Arc<Mutex<Store>>, dto: &MessageDto) -> bool {
        if dto.sender_id == self.account.id {
            return true;
        }
        let Some(engine) = self.engine.clone() else {
            return true;
        };
        // Engine call first, store write after: the engine pickles into the
        // store while we hold no store lock (lock order state→engine→store).
        let plain = decrypt_envelope_text(&engine, dto.channel_id, dto.sender_id, &dto.content);
        match plain {
            Decrypted::Text(text) => {
                guard(store).set_plaintext(dto.id, &text).ok();
            }
            Decrypted::Deleted(target) => {
                self.remove_message(dto.channel_id, target);
                let s = guard(store);
                let _ = s.delete_message(target);
                let _ = s.delete_message(dto.id); // carrier never renders again
                return false;
            }
            Decrypted::Failed => {
                guard(store).set_plaintext(dto.id, "[undecryptable]").ok();
            }
        }
        true
    }

    /// Decrypt + apply every mailbox item we can: Olm-decrypt the transport,
    /// expect an [`Envelope::SessionShare`], import the Megolm key. Items
    /// whose sender identity is not known yet are kept (not acked) for a
    /// later retry; stale items (older than [`MAILBOX_STALE_MS`]) and
    /// undecryptable/malformed ones are acked and dropped — the mailbox must
    /// never block. Acks queue in [`MainState::outbox_acks`] for the WS loop
    /// to flush (there is no socket handle at the first Ready yet).
    fn process_mailbox(&mut self, store: &Arc<Mutex<Store>>) {
        let Some(engine) = self.engine.clone() else {
            return; // no engine: keep everything, retry after bootstrap
        };
        let now = now_ms();
        let mut keep = Vec::new();
        let mut acks = Vec::new();
        let mut imported: Vec<i64> = Vec::new();
        for item in std::mem::take(&mut self.mailbox) {
            if now.saturating_sub(item.created_at_ms) > MAILBOX_STALE_MS {
                acks.push(item.id);
                continue;
            }
            let Some(identity) = self.identities.get(&item.sender_id).cloned() else {
                keep.push(item); // identity unknown yet; retry once learned
                continue;
            };
            match engine.olm_decrypt_from(item.sender_id, &identity, &item.content) {
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
                                eprintln!("bysyc: megolm import failed (channel {channel_id}): {e}")
                            }
                        }
                        acks.push(item.id);
                    }
                    _ => acks.push(item.id), // not a share → malformed for us: skip
                },
                Err(_) => acks.push(item.id), // undecryptable: ack + skip
            }
        }
        self.mailbox = keep;
        self.outbox_acks.extend(acks);
        // A freshly imported session may unlock history we already cached.
        for ch in imported {
            self.backfill_plaintexts(store, ch);
        }
    }

    /// Retry decryption for cached history rows that still have no plaintext
    /// (e.g. loaded before the session share arrived). Store writes happen
    /// strictly after the engine calls — never under the store lock — for
    /// the same lock-order reason as [`MainState::apply_chat_message`].
    pub fn backfill_plaintexts(&self, store: &Arc<Mutex<Store>>, channel_id: i64) {
        let Some(engine) = self.engine.as_ref() else {
            return;
        };
        let rows = guard(store).undecrypted(channel_id);
        let mut decrypted: Vec<(i64, String)> = Vec::new();
        for (id, sender, content) in rows {
            if sender == self.account.id {
                continue; // own rows get their plaintext from the send task
            }
            if let Decrypted::Text(text) =
                decrypt_envelope_text(engine, channel_id, sender, &content)
            {
                decrypted.push((id, text));
            }
        }
        if decrypted.is_empty() {
            return;
        }
        let s = guard(store);
        for (id, text) in decrypted {
            let _ = s.set_plaintext(id, &text);
        }
    }
}

/// Result of decrypting one message ciphertext into renderable text.
enum Decrypted {
    Text(String),
    /// A Delete envelope: hide `target` (and the carrier).
    Deleted(i64),
    /// Could not decrypt or parse.
    Failed,
}

/// Megolm-decrypt `content` from `sender` in `channel` and map the envelope
/// to renderable text. Sharing [`Envelope::File`] rendering duties with C4:
/// v1 renders the "[file: name]" placeholder via plaintext.
fn decrypt_envelope_text(engine: &Engine, channel: i64, sender: i64, content: &str) -> Decrypted {
    let Ok(plaintext) = engine.megolm_decrypt(channel, sender, "", content) else {
        return Decrypted::Failed;
    };
    match serde_json::from_str::<Envelope>(&plaintext) {
        Ok(Envelope::Chat { text, .. }) => Decrypted::Text(text),
        Ok(Envelope::File { name, .. }) => Decrypted::Text(format!("[file: {name}]")),
        Ok(Envelope::Delete { target }) => Decrypted::Deleted(target),
        Ok(Envelope::SessionShare { .. }) | Err(_) => Decrypted::Failed,
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
}

impl ClientState {
    pub fn new() -> Self {
        ClientState {
            phase: Phase::Disconnected,
            ws_generation: 0,
            login_error: None,
            pending_engine: None,
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

    /// Tear the session down locally (does not touch the keychain — the
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
// Server message application
// ---------------------------------------------------------------------------

/// Apply one server-pushed WS message to the world and request a repaint.
/// Returns `true` when the message was `Ready`.
///
/// The WS task stamps `MainState::net` itself right after a `Ready` (it owns
/// the handle). Message persistence happens in the caller *before* this runs
/// (the caller holds the store and the raw dto); decryption, delete-marking
/// and plaintext writes happen here under the state lock (lock order:
/// state → engine → store, never store → engine).
pub fn apply_server_msg(
    state: &Mutex<ClientState>,
    store: &Arc<Mutex<Store>>,
    ctx: &Context,
    msg: WsServerMsg,
) -> bool {
    let mut st = guard(state);
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
            // The engine must exist before the mailbox below is processed
            // (session shares ride in it). Login/restore stage one in
            // `pending_engine`; if it is missing (crash between WS connect
            // and login task?) bootstrap inline from the local store.
            if let Some(m) = st.main_mut() {
                if m.engine.is_none() {
                    let username = m.account.username.clone();
                    match crate::store::bootstrap_engine(store, &username) {
                        Ok((engine, outbound)) => {
                            m.engine = Some(engine);
                            m.outbound.extend(outbound);
                        }
                        Err(e) => {
                            eprintln!("bysyc: {e}");
                            m.notice = Some("crypto engine unavailable — sending disabled".into());
                        }
                    }
                }
            }
            if let Some(m) = st.main_mut() {
                m.seed_world();
                m.process_mailbox(store);
                // A share that arrived while we were offline may unlock
                // history cached from the previous session.
                let loaded: Vec<i64> = m.loaded.iter().copied().collect();
                for ch in loaded {
                    m.backfill_plaintexts(store, ch);
                }
            }
        }
        WsServerBody::Message(dto) => {
            if let Some(m) = st.main_mut() {
                if dto.kind == MessageKind::Control {
                    // v1 has no chat-routed control payloads; drop.
                } else if m.apply_chat_message(store, &dto) {
                    m.append_message(dto.clone());
                    if !m.is_selected_channel(dto.channel_id) {
                        m.unread.insert(dto.channel_id);
                    }
                }
            }
        }
        WsServerBody::MailboxAppend(item) => {
            if let Some(m) = st.main_mut() {
                m.mailbox.push(item);
                m.process_mailbox(store);
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
                m.process_mailbox(store);
                if account.id != m.account.id {
                    m.pending_newcomers.push((guild_id, account.id));
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
                m.pending_signals.push((from, call_id, kind));
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
    ctx.request_repaint();
    was_ready
}

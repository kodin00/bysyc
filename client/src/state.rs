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
use std::sync::{Mutex, MutexGuard};
use std::time::Instant;

use bysyc_common::protocol::{
    AccountBrief, AccountInfo, CallSignalKind, ChannelKind, DmChannel, FriendList, GuildInfo,
    MailboxItem, MessageDto, MessageKind, WsServerBody, WsServerMsg,
};
use eframe::egui::Context;

use crate::net::NetHandle;

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
    ) -> Self {
        let online = friends.iter().filter(|f| f.online).map(|f| f.id).collect();
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

/// Root state. `ws_generation` invalidates stale WS loops: every spawned
/// loop carries the generation current at its start and exits once the
/// counter moves (logout, or a new login superseding it).
pub struct ClientState {
    pub phase: Phase,
    pub ws_generation: u64,
    /// Last login/restore failure to show on the login view.
    pub login_error: Option<String>,
}

impl ClientState {
    pub fn new() -> Self {
        ClientState {
            phase: Phase::Disconnected,
            ws_generation: 0,
            login_error: None,
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
/// the handle); message persistence to [`crate::store`] also happens in the
/// caller, which holds the store.
pub fn apply_server_msg(state: &Mutex<ClientState>, ctx: &Context, msg: WsServerMsg) -> bool {
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
                // local caches (messages, selection, voice, pending signals).
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
                st.phase = Phase::LoggedIn(MainState::from_ready(
                    account,
                    friends,
                    incoming_requests,
                    outgoing_requests,
                    guilds,
                    dm_channels,
                    mailbox,
                ));
            }
        }
        WsServerBody::Message(dto) => {
            if let Some(m) = st.main_mut() {
                m.append_message(dto.clone());
                if dto.kind == MessageKind::Chat && !m.is_selected_channel(dto.channel_id) {
                    m.unread.insert(dto.channel_id);
                }
            }
        }
        WsServerBody::MailboxAppend(item) => {
            if let Some(m) = st.main_mut() {
                m.mailbox.push(item);
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
                if !m.incoming_requests.iter().any(|a| a.id == from.id) {
                    m.incoming_requests.push(from);
                }
            }
        }
        WsServerBody::FriendRequestAccepted { by } => {
            if let Some(m) = st.main_mut() {
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
        WsServerBody::MemberLeft { .. } | WsServerBody::MemberJoined { .. } => {
            // v1 keeps no guild member roster; nothing to update.
        }
        WsServerBody::VoiceState {
            channel_id,
            participants,
        } => {
            if let Some(m) = st.main_mut() {
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

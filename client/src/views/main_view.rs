//! The logged-in main view: three columns.
//!
//! - left: guilds, then Friends, then DMs (with unread badges and presence
//!   dots), plus log out.
//! - middle: channels of the selected guild (voice channels list their call
//!   participant count; joining is C5's), or the friends panel (accept /
//!   decline requests, open DMs, add by username).
//! - right: message history of the selected channel or DM plus the composer
//!   (Enter sends, Shift+Enter breaks the line; attached or dropped files
//!   queue above it and ride the next send; emoji arrive via the OS IME
//!   and render through the Noto Emoji fallback installed in
//!   [`crate::app`]).
//!
//! History is loaded from SQLite first, then merged with a REST page on
//! first open; sends are optimistic (negative temp ids, pinned at the tail)
//! and reconciled when the REST response lands; a failed send restores its
//! text to the composer. Typing events are throttled to one per 3 s and
//! pruned after [`TYPING_TTL_SECS`].

use std::collections::{HashMap, HashSet, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui;

use bysyc_common::protocol::{
    AccountBrief, AttachmentMeta, ChannelKind, CreateChannelRequest, CreateGuildInviteRequest,
    CreateGuildRequest, DmChannel, GuildInfo, JoinGuildRequest, MessageDto, MessageKind,
    OpenDmRequest, WsClientBody, WsClientMsg,
};

use crate::app::BysycApp;
use crate::crypto::Envelope;
use crate::net::{self, NetHandle};
use crate::state::{
    ClientState, ConnStatus, MainState, Selection, TYPING_TTL_SECS, guard, now_ms,
};
use crate::store::Store;
use crate::views::attachments;

/// View-lifetime UI state (input buffers, throttles).
pub struct MainView {
    /// Composer text per channel id.
    pub composer: HashMap<i64, String>,
    /// Last time we sent a Typing event per channel (3 s throttle).
    pub last_typing_sent: HashMap<i64, Instant>,
    /// Source of negative optimistic message ids.
    pub temp_id: i64,
    /// Add-friend input.
    pub add_friend: String,
    /// Per channel: the message id the composer is replying to.
    pub reply_to: HashMap<i64, i64>,
    /// "+"-guild popup open?
    pub guild_popup: bool,
    /// Inputs for the guild popup (create / join-by-code).
    pub new_guild_name: String,
    pub join_code: String,
    /// "+ channel" popup open (guild owner only).
    pub channel_popup: bool,
    pub new_channel_name: String,
    /// `false` = text channel, `true` = voice channel.
    pub new_channel_voice: bool,
    /// "+ dm" friend picker open?
    pub dm_picker: bool,
    /// Settings window open (audio device pickers etc.).
    pub settings_open: bool,
    /// (channel, when) of the last auto-triggered "Load older" fetch — a
    /// cooldown so scrolling to the top doesn't fire a fetch every frame.
    pub last_load_attempt: Option<(i64, Instant)>,
    /// Decoded-and-downscaled attachment images by attachment id. UI-thread
    /// only (textures cannot be created elsewhere); never persisted.
    pub image_cache: HashMap<i64, egui::TextureHandle>,
    /// Worker threads hand finished image decodes to the UI thread here.
    pub image_tx: std::sync::mpsc::Sender<attachments::DecodedImage>,
    pub image_rx: std::sync::mpsc::Receiver<attachments::DecodedImage>,
    /// Open image lightbox: (attachment id, name).
    pub image_popup: Option<(i64, String)>,
    /// Channel the chat column last rendered; a change resets the message
    /// list scroll to the bottom (the list keeps one scroll state per
    /// channel — see [`MainView::chat_at_bottom`] and the anchor below).
    pub chat_channel_prev: Option<i64>,
    /// True while the message list sits at (or near) its bottom, from the
    /// last rendered frame. Gates "Load older" scroll anchoring: a reader
    /// stuck to the bottom must stay there when older rows prepend.
    pub chat_at_bottom: bool,
    /// Pending "Load older" scroll anchor: after older rows prepend, hold
    /// the previously-oldest message at the top of the viewport. See
    /// [`LoadAnchor`].
    pub load_anchor: Option<LoadAnchor>,
    /// Armed channel deletions: channel id → when the "×" was clicked.
    /// The second click within [`DELETE_CONFIRM_TTL`] deletes.
    pub delete_confirm: Option<(i64, Instant)>,
    /// Notice banner bookkeeping: the notice text last seen and when it
    /// appeared. `MainState::notice` carries no timestamp, so expiry is
    /// tracked here (a fresh or changed notice restarts the clock).
    pub notice_seen: Option<(String, Instant)>,
    /// Drafts rescued from failed sends (channel → text). The send task
    /// parks here from its own thread — it cannot reach this view — and
    /// the UI thread folds them back into the composers each frame.
    pub unsent: Arc<Mutex<HashMap<i64, String>>>,
    /// Files queued to ride a channel's next send (attach pick or OS
    /// drop), per channel like [`MainView::composer`]. The send path in
    /// `chat` drains them into the attachment upload pipeline; until then
    /// they only render in the pending strip.
    pub pending: HashMap<i64, Vec<attachments::PendingFile>>,
    /// The attach button's picker thread hands chosen files (with the
    /// channel the click happened in) to the UI thread here.
    pub attach_tx: std::sync::mpsc::Sender<(i64, PathBuf)>,
    pub attach_rx: std::sync::mpsc::Receiver<(i64, PathBuf)>,
    /// Focus the create-guild name field on the popup's next frame (set
    /// when the popup opens).
    pub guild_popup_focus: bool,
    /// Focus the new-channel name field on the popup's next frame.
    pub channel_popup_focus: bool,
    /// Armed message deletions: message id → when the trash button was
    /// clicked. The confirming "yes" within [`DELETE_CONFIRM_TTL`] fires
    /// the delete.
    pub msg_delete_confirm: Option<(i64, Instant)>,
    // -- Render caches ---------------------------------------------------------
    // The repaint model is event-driven but every repaint used to walk
    // SQLite and deep-clone the world several times over. These caches are
    // UI-thread only, filled at the moments data lands (channel open, row
    // render, roster discovery) so a steady-state frame costs no queries
    // and no tree clones.
    /// Decrypted message bodies by message id, seeded in one batch when a
    /// channel opens and topped up on cache miss (one SELECT per genuinely
    /// new visible row). Render borrows from here instead of querying the
    /// store per row per frame.
    pub plaintexts: HashMap<i64, String>,
    /// Display names by account id, resolved from the roster once per
    /// unknown id (replacing the O(roster) `account_name` scan per row).
    /// Unknown ids are NOT cached — their roster entry may appear later.
    pub names: HashMap<i64, String>,
    /// File envelopes by message id, cloned out of `file_meta` once per
    /// row (envelopes are immutable per message id).
    pub file_envs: HashMap<i64, Envelope>,
    /// Measured message-row heights (px, sans inter-row spacing) by
    /// message id, from the row's last layout. Drives the message list's
    /// variable-height virtualization together with the estimates from
    /// [`estimate_row_height`]. Cleared when the row width moves (wrapped
    /// bodies re-measure as they render).
    pub row_heights: HashMap<i64, f32>,
    /// Row content width the [`MainView::row_heights`] entries were
    /// measured at.
    pub row_w: f32,
    /// Loaded channel's message id → sender id, rebuilt when the channel's
    /// message list changes ((len, first, last) signature). Resolves reply
    /// prefixes in O(1) instead of a linear scan per replied row.
    pub reply_senders: HashMap<i64, i64>,
    /// Signature [`MainView::reply_senders`] was last rebuilt at:
    /// (channel, len, first id, last id).
    pub reply_sig: Option<(i64, usize, i64, i64)>,
    /// Reply banner text per channel: (sender name, body snippet),
    /// resolved once when the reply is armed instead of per frame.
    pub reply_banner: HashMap<i64, (String, String)>,
    /// Monotonic frame counter for the image-texture LRU.
    pub frame_no: u64,
    /// Attachment id → [`MainView::frame_no`] when its texture was last
    /// rendered (see [`MainView::evict_stale_images`]).
    pub image_frames: HashMap<i64, u64>,
    /// Memoized [`middle_min_width`]: input-signature hash → width (plus
    /// the style it was measured under, kept in
    /// [`MainView::mid_min_style`]).
    pub mid_min_cache: Option<(u64, f32)>,
    /// Style the memoized [`MainView::mid_min_cache`] width was measured
    /// under; a theme/style change re-measures.
    pub mid_min_style: Option<Arc<egui::Style>>,
}

/// A "Load older" scroll anchor (see [`MainView::load_anchor`]): keeps the
/// reading position stable while a page of older messages prepends.
#[derive(Clone, Copy)]
pub struct LoadAnchor {
    /// Channel the anchor lives in.
    pub channel: i64,
    /// Message id of the previously-oldest row.
    pub msg_id: i64,
    /// That row's index when armed; a larger index later means the older
    /// page has landed and the anchor scroll should run.
    pub idx_armed: usize,
    /// When armed. Anchors that never resolve (failed or empty fetch)
    /// time out instead of lingering.
    pub armed_at: Instant,
}

impl MainView {
    pub fn new() -> Self {
        let (image_tx, image_rx) = std::sync::mpsc::channel();
        let (attach_tx, attach_rx) = std::sync::mpsc::channel();
        MainView {
            composer: HashMap::new(),
            last_typing_sent: HashMap::new(),
            temp_id: -1,
            add_friend: String::new(),
            reply_to: HashMap::new(),
            guild_popup: false,
            new_guild_name: String::new(),
            join_code: String::new(),
            channel_popup: false,
            new_channel_name: String::new(),
            new_channel_voice: false,
            dm_picker: false,
            settings_open: false,
            last_load_attempt: None,
            image_cache: HashMap::new(),
            image_tx,
            image_rx,
            image_popup: None,
            chat_channel_prev: None,
            chat_at_bottom: true,
            load_anchor: None,
            delete_confirm: None,
            notice_seen: None,
            unsent: Arc::new(Mutex::new(HashMap::new())),
            pending: HashMap::new(),
            attach_tx,
            attach_rx,
            guild_popup_focus: false,
            channel_popup_focus: false,
            msg_delete_confirm: None,
            plaintexts: HashMap::new(),
            names: HashMap::new(),
            file_envs: HashMap::new(),
            row_heights: HashMap::new(),
            row_w: 0.0,
            reply_senders: HashMap::new(),
            reply_sig: None,
            reply_banner: HashMap::new(),
            frame_no: 0,
            image_frames: HashMap::new(),
            mid_min_cache: None,
            mid_min_style: None,
        }
    }

    /// Mark an image texture as rendered this frame (LRU touch). Ids with
    /// no texture yet simply record nothing — eviction timestamps them
    /// lazily when the texture lands.
    pub fn touch_image(&mut self, id: i64) {
        if self.image_cache.contains_key(&id) {
            self.image_frames.insert(id, self.frame_no);
        }
    }

    /// Drop decoded-image textures that went stale: entries not touched
    /// for [`IMAGE_IDLE_FRAMES`] frames, then the least-recently-touched
    /// beyond the [`IMAGE_CACHE_CAP`] hard cap. `keep` pins entries that
    /// must survive (the current channel's attachments and the open
    /// lightbox). Textures dropped here are re-fetched and re-decoded on
    /// demand if their row scrolls back into view.
    pub fn evict_stale_images(&mut self, keep: &HashSet<i64>) {
        let now = self.frame_no;
        // Textures inserted by the attachments view carry no touch yet —
        // treat insertion as first use instead of evicting them blind.
        for id in self.image_cache.keys() {
            self.image_frames.entry(*id).or_insert(now);
        }
        self.image_cache
            .retain(|id, _| keep.contains(id) || now.saturating_sub(self.image_frames.get(id).copied().unwrap_or(now)) <= IMAGE_IDLE_FRAMES);
        self.image_frames.retain(|id, _| self.image_cache.contains_key(id));
        if self.image_cache.len() > IMAGE_CACHE_CAP {
            let mut by_use: Vec<(i64, u64)> = self
                .image_cache
                .keys()
                .map(|id| (*id, self.image_frames.get(id).copied().unwrap_or(now)))
                .collect();
            by_use.sort_unstable_by_key(|&(_, used)| used);
            let excess = self.image_cache.len() - IMAGE_CACHE_CAP;
            let mut dropped = 0;
            for (id, _) in by_use {
                if dropped >= excess {
                    break;
                }
                if keep.contains(&id) {
                    continue;
                }
                self.image_cache.remove(&id);
                self.image_frames.remove(&id);
                dropped += 1;
            }
        }
    }
}

pub fn show(app: &mut BysycApp, ui: &mut egui::Ui) {
    let BysycApp {
        state,
        store,
        rt,
        login: _,
        main_view,
        net_task: _,
    } = app;
    let ctx = ui.ctx().clone();

    // Frame counter for the image-texture LRU.
    main_view.frame_no += 1;

    // One snapshot of the shared world per frame: every panel used to take
    // its own guard and deep-clone the guilds tree / friend lists, three
    // or four copies of the same data per repaint. The panels borrow this
    // snapshot; interaction handlers still lock state to mutate it.
    let snap = panel_snap(state);

    // egui 0.36: one `Panel` type with side constructors. Both side columns
    // are drag-resizable within a bounded range so they stay usable from
    // small windows (min) up to wide ones (max).
    egui::Panel::left("nav")
        .resizable(true)
        .default_size(140.0)
        .min_size(140.0)
        .max_size(400.0)
        .show(ui, |ui| nav(ui, state, store, rt, main_view, &ctx, snap.as_ref()));

    // The middle column's minimum (and first-run default) is its intrinsic
    // width — the widest visible row measured against the live state, so
    // no channel name or DM row ever wraps or truncates. egui clamps the
    // persisted width into [min, max] every frame, so a min that grows
    // with content also pulls the panel wider as needed. The measurement
    // walks every label of every guild, so it is memoized against a cheap
    // signature of its inputs (see [`cached_middle_min_width`]).
    let mid_min = cached_middle_min_width(main_view, &ctx, snap.as_ref());
    egui::Panel::left("middle")
        .resizable(true)
        .default_size(mid_min)
        .min_size(mid_min)
        .max_size(400.0)
        .show(ui, |ui| middle(ui, state, rt, main_view, &ctx, snap.as_ref()));

    egui::CentralPanel::default().show(ui, |ui| chat(ui, state, store, rt, main_view, &ctx, snap.as_ref()));

    // Transient popups driven by background tasks (invite codes).
    invite_window(state, &ctx);

    // Audio device settings (output/input pickers).
    crate::views::settings::settings_window(&ctx, state, store, &mut main_view.settings_open);

    // C5 renders the call overlay from here.
    crate::call::ui::overlay(&ctx, state, rt);
}

/// What the three columns render, cloned once per frame under one state
/// lock (see [`show`]). Voice enters as (participant count, am I in the
/// call) — the only facts the panels and width measurement read.
struct PanelSnap {
    my_id: i64,
    selected: Selection,
    guilds: Vec<GuildInfo>,
    dms: Vec<DmChannel>,
    friends: Vec<AccountBrief>,
    incoming: Vec<AccountBrief>,
    outgoing: Vec<AccountBrief>,
    unread: HashSet<i64>,
    online: HashSet<i64>,
    /// Voice channel id → (participants, joined by me).
    voice: HashMap<i64, (usize, bool)>,
}

fn panel_snap(state: &Arc<Mutex<ClientState>>) -> Option<PanelSnap> {
    let st = guard(state);
    let m = st.main()?;
    Some(PanelSnap {
        my_id: m.account.id,
        selected: m.selected,
        guilds: m.guilds.clone(),
        dms: m.dms.clone(),
        friends: m.friends.clone(),
        incoming: m.incoming_requests.clone(),
        outgoing: m.outgoing_requests.clone(),
        unread: m.unread.clone(),
        online: m.online.clone(),
        voice: m
            .voice
            .iter()
            .map(|(ch, ps)| (*ch, (ps.len(), ps.iter().any(|p| p.id == m.account.id))))
            .collect(),
    })
}

/// Display title of a channel from the per-frame snapshot (same output as
/// [`MainState::channel_name`], without another state lock).
fn snap_channel_name(snap: &PanelSnap, channel_id: i64) -> String {
    if let Some(dm) = snap.dms.iter().find(|d| d.channel.id == channel_id) {
        return format!("@{}", dm.peer.username);
    }
    snap.guilds
        .iter()
        .flat_map(|g| &g.channels)
        .find(|c| c.id == channel_id)
        .map(|c| format!("#{}", c.name))
        .unwrap_or_else(|| format!("channel {channel_id}"))
}

// ---------------------------------------------------------------------------
// Left column: guilds / friends / DMs
// ---------------------------------------------------------------------------

fn nav(
    ui: &mut egui::Ui,
    state: &Arc<Mutex<ClientState>>,
    store: &Arc<Mutex<Store>>,
    rt: &tokio::runtime::Handle,
    mv: &mut MainView,
    ctx: &egui::Context,
    snap: Option<&PanelSnap>,
) {
    let Some(snap) = snap else { return };
    let (guilds, dms, selected, unread, online, incoming) = (
        &snap.guilds,
        &snap.dms,
        snap.selected,
        &snap.unread,
        &snap.online,
        snap.incoming.len(),
    );

    ui.heading("Guilds");
    ui.separator();

    // The guild/friends/DM list scrolls when it outgrows the column; the
    // heading above and the Log out button below stay pinned.
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for g in guilds {
                let is_current =
                    matches!(selected, Selection::Channel(c) if g.channels.iter().any(|ch| ch.id == c));
                let marker = if is_current { "> " } else { "" };
                ui.horizontal(|ui| {
                    if ui
                        .selectable_label(is_current, format!("{marker}{}", g.name))
                        .clicked()
                    {
                        let mut st = guard(state);
                        if let Some(m) = st.main_mut() {
                            if let Some(ch) = m.first_text_channel(g.id) {
                                m.selected = Selection::Channel(ch);
                                m.unread.remove(&ch);
                            }
                        }
                    }
                    // Guild-level unread: any channel of the guild with
                    // unseen messages shows the same dot the DM rows use,
                    // so activity in a non-browsed guild is visible.
                    if g.channels.iter().any(|c| unread.contains(&c.id)) {
                        ui.colored_label(egui::Color32::RED, "•");
                    }
                });
            }
            if ui.button("+ guild").clicked() {
                mv.guild_popup = !mv.guild_popup;
                // Focus the create field when the popup opens.
                mv.guild_popup_focus = mv.guild_popup;
            }

            ui.add_space(8.0);
            ui.separator();

            let friends_label = if incoming > 0 {
                format!("Friends ({incoming})")
            } else {
                "Friends".to_string()
            };
            if ui
                .selectable_label(matches!(selected, Selection::Friends), friends_label)
                .clicked()
            {
                if let Some(m) = guard(state).main_mut() {
                    m.selected = Selection::Friends;
                }
            }

            ui.add_space(4.0);
            for dm in dms {
                let sel = matches!(selected, Selection::Dm(c) if c == dm.channel.id);
                ui.horizontal(|ui| {
                    let on = online.contains(&dm.peer.id);
                    ui.colored_label(
                        if on {
                            egui::Color32::LIGHT_GREEN
                        } else {
                            egui::Color32::GRAY
                        },
                        "●",
                    );
                    if ui.selectable_label(sel, dm.peer.username.as_str()).clicked() {
                        let mut st = guard(state);
                        if let Some(m) = st.main_mut() {
                            m.selected = Selection::Dm(dm.channel.id);
                            m.unread.remove(&dm.channel.id);
                        }
                    }
                    if unread.contains(&dm.channel.id) {
                        ui.colored_label(egui::Color32::RED, "•");
                    }
                });
            }
            if ui.button("+ dm").clicked() {
                mv.dm_picker = !mv.dm_picker;
            }
        });

    ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
        if ui.button("Log out").clicked() {
            logout(state, store, rt);
        }
        if ui.button("Settings").clicked() {
            mv.settings_open = !mv.settings_open;
        }
    });

    guild_popup(state, rt, mv, ctx);
    dm_picker(state, rt, mv, ctx);
}

/// Create-a-guild / join-by-code window ("+ guild"). The name field grabs
/// focus on open, Enter submits the section whose field holds it, and
/// Escape closes.
fn guild_popup(
    state: &Arc<Mutex<ClientState>>,
    rt: &tokio::runtime::Handle,
    mv: &mut MainView,
    ctx: &egui::Context,
) {
    let mut open = mv.guild_popup;
    let mut close = false;
    egui::Window::new("Add a guild")
        .id(egui::Id::new("guild_popup"))
        .open(&mut open)
        .collapsible(false)
        .show(ctx, |ui| {
            // Explicit ids keep each field's focus stable regardless of
            // which conditional sections render (same class of bug as the
            // chat composer).
            ui.label("Create");
            let name_field = ui
                .add(egui::TextEdit::singleline(&mut mv.new_guild_name).id_salt("new_guild_name"));
            if mv.guild_popup_focus {
                name_field.request_focus();
                mv.guild_popup_focus = false;
            }
            let create = ui.add_enabled(
                !mv.new_guild_name.trim().is_empty(),
                egui::Button::new("Create guild"),
            );
            if create.clicked()
                || (name_field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))
            {
                let name = mv.new_guild_name.trim().to_string();
                if !name.is_empty() {
                    mv.new_guild_name.clear();
                    close = true;
                    spawn_guild_rest(state, rt, ctx, move |h| async move {
                        h.net.create_guild(&CreateGuildRequest { name }).await
                    });
                }
            }
            ui.separator();
            ui.label("Join with an invite code");
            let code_field =
                ui.add(egui::TextEdit::singleline(&mut mv.join_code).id_salt("join_code"));
            let join = ui.add_enabled(!mv.join_code.trim().is_empty(), egui::Button::new("Join"));
            if join.clicked()
                || (code_field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))
            {
                let code = mv.join_code.trim().to_string();
                if !code.is_empty() {
                    mv.join_code.clear();
                    close = true;
                    spawn_guild_rest(state, rt, ctx, move |h| async move {
                        h.net.join_guild(&JoinGuildRequest { code }).await
                    });
                }
            }
            // Escape closes only while a field here holds focus — an
            // Escape aimed at the chat composer (cancel reply) must not
            // close this window.
            if (name_field.has_focus() || code_field.has_focus())
                && ui.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Escape))
            {
                close = true;
            }
        });
    mv.guild_popup = open && !close;
}

/// Shared REST half of create/join guild: run the call, merge the returned
/// guild locally (the WS `GuildJoined` echo is deduped on insert).
fn spawn_guild_rest<F, Fut>(
    state: &Arc<Mutex<ClientState>>,
    rt: &tokio::runtime::Handle,
    ctx: &egui::Context,
    fut_fn: F,
) where
    F: FnOnce(NetHandle) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<bysyc_common::protocol::GuildInfo, String>>
        + Send
        + 'static,
{
    let Some(h) = net_handle(state) else { return };
    let state = Arc::clone(state);
    let ctx = ctx.clone();
    rt.spawn(async move {
        let h2 = h.clone();
        match fut_fn(h).await {
            Ok(g) => {
                // Joined guild channels: subscribe now instead of waiting
                // out the periodic heartbeat (see NetHandle::heartbeat).
                h2.heartbeat();
                let mut st = guard(&state);
                if let Some(m) = st.main_mut() {
                    if !m.guilds.iter().any(|x| x.id == g.id) {
                        m.guilds.push(g);
                    }
                }
            }
            Err(e) => {
                if let Some(m) = guard(&state).main_mut() {
                    m.notice = Some(e);
                }
            }
        }
        ctx.request_repaint();
    });
}

fn logout(state: &Arc<Mutex<ClientState>>, store: &Arc<Mutex<Store>>, rt: &tokio::runtime::Handle) {
    let taken = {
        let st = guard(state);
        st.main()
            .map(|m| (m.account.username.clone(), m.net.clone()))
    };
    let (username, handle) = taken.unwrap_or_else(|| (String::new(), None));

    // Generation bump makes the WS loop stop reconnecting.
    guard(state).sign_out_local("Signed out.");

    if !username.is_empty() {
        crate::store::token_delete(&username);
        let s = guard(store);
        let _ = s.del_setting("username");
    }
    if let Some(h) = handle {
        rt.spawn(async move {
            let _ = h.net.logout().await;
        });
    }
}

/// "+ dm" picker: friends list → open (or reuse) a DM and select it.
fn dm_picker(
    state: &Arc<Mutex<ClientState>>,
    rt: &tokio::runtime::Handle,
    mv: &mut MainView,
    ctx: &egui::Context,
) {
    // Closed most frames — bail before cloning the friends list.
    if !mv.dm_picker {
        return;
    }
    let friends = {
        let st = guard(state);
        st.main().map(|m| m.friends.clone()).unwrap_or_default()
    };
    let mut open = mv.dm_picker;
    let mut close = false;
    let mut esc = false;
    egui::Window::new("Start a direct message")
        .id(egui::Id::new("dm_picker"))
        .open(&mut open)
        .collapsible(false)
        .show(ctx, |ui| {
            if ui.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Escape)) {
                esc = true;
            }
            if friends.is_empty() {
                ui.weak("no friends yet — add some on the Friends page");
            }
            for f in &friends {
                if ui.button(f.username.as_str()).clicked() {
                    close = true;
                    open_dm_and_select(state, rt, ctx, f.id);
                }
            }
        });
    mv.dm_picker = open && !close && !esc;
}

/// Open (or reuse) a DM with `peer_id` and select it.
fn open_dm_and_select(
    state: &Arc<Mutex<ClientState>>,
    rt: &tokio::runtime::Handle,
    ctx: &egui::Context,
    peer_id: i64,
) {
    let Some(h) = net_handle(state) else { return };
    let state = Arc::clone(state);
    let ctx = ctx.clone();
    rt.spawn(async move {
        match h
            .net
            .open_dm(&OpenDmRequest {
                account_id: peer_id,
            })
            .await
        {
            Ok(dm) => {
                // New channel: poke the gateway to subscribe us now (see
                // NetHandle::heartbeat) instead of waiting out the periodic
                // heartbeat interval.
                h.heartbeat();
                let channel_id = dm.channel.id;
                let mut st = guard(&state);
                if let Some(m) = st.main_mut() {
                    if !m.dms.iter().any(|d| d.channel.id == channel_id) {
                        m.dms.push(dm);
                    }
                    m.selected = Selection::Dm(channel_id);
                }
            }
            Err(e) => {
                if let Some(m) = guard(&state).main_mut() {
                    m.notice = Some(e);
                }
            }
        }
        ctx.request_repaint();
    });
}

/// Owner's "invite": mint a 24 h code and surface it in [`invite_window`].
fn spawn_invite(
    state: &Arc<Mutex<ClientState>>,
    rt: &tokio::runtime::Handle,
    ctx: &egui::Context,
    guild_id: i64,
    guild_name: String,
) {
    let Some(h) = net_handle(state) else { return };
    let state = Arc::clone(state);
    let ctx = ctx.clone();
    rt.spawn(async move {
        match h
            .net
            .create_guild_invite(
                guild_id,
                &CreateGuildInviteRequest {
                    max_uses: None,
                    ttl_secs: Some(24 * 60 * 60),
                },
            )
            .await
        {
            Ok(inv) => {
                if let Some(m) = guard(&state).main_mut() {
                    m.invite = Some((guild_name, inv.code));
                }
            }
            Err(e) => {
                if let Some(m) = guard(&state).main_mut() {
                    m.notice = Some(e);
                }
            }
        }
        ctx.request_repaint();
    });
}

/// Invite-code window: filled by the owner's "invite" action, with a
/// copy-to-clipboard button.
fn invite_window(state: &Arc<Mutex<ClientState>>, ctx: &egui::Context) {
    let invite = { guard(state).main().and_then(|m| m.invite.clone()) };
    let Some((guild, code)) = invite else { return };
    egui::Window::new("Guild invite")
        .id(egui::Id::new("invite_window"))
        .collapsible(false)
        .show(ctx, |ui| {
            ui.label(format!("Invite to {guild}:"));
            ui.monospace(code.clone());
            if ui.button("Copy").clicked() {
                ui.ctx().output_mut(|o| {
                    o.commands.push(egui::OutputCommand::CopyText(code.clone()));
                });
            }
            if ui.button("Close").clicked() {
                if let Some(m) = guard(state).main_mut() {
                    m.invite = None;
                }
            }
        });
}

// ---------------------------------------------------------------------------
// Middle column: channels of the guild, DM info, or friends panel
// ---------------------------------------------------------------------------

/// The middle column's intrinsic width: the widest row the current state
/// can render in it, so every label fits unwrapped and untruncated. All
/// three panes (guild channels, DM info, friends) are measured — not just
/// the visible one — so switching selections never changes the minimum
/// and the column doesn't lurch wider or narrower.
///
/// The measurement walks every label of every guild, so it is NOT run
/// per frame: [`cached_middle_min_width`] memoizes it against a cheap
/// hash of its inputs (guild/channel ids+names, rosters, call counts) and
/// the live style. Galley layout also caches by (text, font) inside the
/// fonts object, so re-measures are cache hits.
///
/// Widths come from `layout_no_wrap` plus the chrome egui wraps each
/// widget in: button-ish widgets (buttons and selectable labels, selected
/// or not) frame their content with `button_padding + expansion` on each
/// side; plain labels add nothing; siblings separate by `item_spacing.x`.
/// A trailing allowance covers the panel frame's inner margin, the
/// scrollbar the channel list may show, and slack for the bg-stroke
/// subtraction egui applies to button frames (skipping it above errs
/// wide, the safe direction).
fn middle_min_width(ctx: &egui::Context, style: &egui::Style, snap: &PanelSnap) -> f32 {
    let (my_id, guilds, dms, friends, incoming, outgoing, voice) = (
        snap.my_id,
        &snap.guilds,
        &snap.dms,
        &snap.friends,
        &snap.incoming,
        &snap.outgoing,
        &snap.voice,
    );

    let body = egui::TextStyle::Body.resolve(style);
    let button = egui::TextStyle::Button.resolve(style);
    let small = egui::TextStyle::Small.resolve(style);
    let heading = egui::TextStyle::Heading.resolve(style);
    let text_w = |t: &str, f: &egui::FontId| {
        ctx.fonts_mut(|fs| {
            fs.layout_no_wrap(t.to_owned(), f.clone(), egui::Color32::PLACEHOLDER)
                .size()
                .x
        })
    };
    // Button/selectable-label chrome: `button_padding + expansion` on each
    // side of the content (the resting — inactive — widget state).
    let pad = 2.0 * (style.spacing.button_padding.x + style.visuals.widgets.inactive.expansion);
    let gap = style.spacing.item_spacing.x;
    let btn = |t: &str, f: &egui::FontId| text_w(t, f) + pad;

    let mut w = 0.0f32;

    // Guild-channel pane: the guild heading, the owner's button strip, and
    // every channel row (text and voice labels reproduced as rendered,
    // including the live call count). The owner's delete control widens a
    // row by "×" at rest and by "yes"/"no" while armed — take the wider.
    for g in guilds {
        w = w.max(text_w(&g.name, &heading));
        if g.owner_id == my_id {
            w = w.max(btn("+ channel", &small) + gap + btn("invite", &small));
        }
        for c in &g.channels {
            let label = match c.kind {
                ChannelKind::Text => format!("# {}", c.name),
                ChannelKind::Voice => match voice.get(&c.id) {
                    Some((n, true)) => format!("(v) {} — {n} in call  [leave]", c.name),
                    Some((n, false)) => format!("(v) {} — {n} in call", c.name),
                    None => format!("(v) {} — 0 in call", c.name),
                },
                ChannelKind::Dm => continue,
            };
            let mut row = text_w(&label, &body) + pad; // selectable_label
            if g.owner_id == my_id {
                let rest = btn("×", &small);
                let armed = btn("yes", &small) + gap + btn("no", &small);
                row += gap + rest.max(armed);
            }
            w = w.max(row);
        }
    }

    // DM pane: peer heading, the E2EE note, the call button.
    for d in dms {
        w = w.max(text_w(&format!("@{}", d.peer.username), &heading));
    }
    w = w.max(text_w("private, end-to-end encrypted", &body) + gap + btn("Call", &button));

    // Friends pane: headings, request rows with their action buttons,
    // friend rows, and the add-friend strip (fixed 130-wide input).
    w = w.max(text_w("Friends", &heading));
    w = w.max(text_w("Incoming requests", &button));
    w = w.max(text_w("Sent requests", &button));
    let dot = text_w("●", &body);
    for f in incoming.iter().chain(friends) {
        let mut row = dot + gap + text_w(&f.username, &body);
        row += gap + btn("Accept", &button) + gap + btn("Decline", &button);
        w = w.max(row);
    }
    for f in outgoing {
        w = w.max(text_w(&f.username, &body) + gap + btn("cancel", &small));
    }
    if !friends.is_empty() {
        // A friend row also carries the "Message" button (no presence-dot
        // width difference — same dot either way).
        w = w.max(dot + gap + text_w(&friends[0].username, &body) + gap + btn("Message", &button));
    }
    w = w.max(130.0 + gap + btn("Send request", &button));

    // Panel chrome: default side-panel frame inner margin (8 each side),
    // the scrollbar the list may show, and slack for stroke rounding.
    let chrome = 2.0 * 8.0 + style.spacing.scroll.allocated_width() + 8.0;
    (w + chrome).clamp(140.0, 400.0)
}

/// [`middle_min_width`] behind the memo: re-measure only when the hashed
/// inputs moved (roster/guild/channel changes, call counts) or the style
/// changed; every other frame reuses the stored width. The signature
/// hashes ids, names and counts straight off the per-frame snapshot — no
/// allocations, no font work.
fn cached_middle_min_width(
    mv: &mut MainView,
    ctx: &egui::Context,
    snap: Option<&PanelSnap>,
) -> f32 {
    let Some(snap) = snap else {
        return 140.0;
    };
    let mut h = DefaultHasher::new();
    snap.my_id.hash(&mut h);
    for g in &snap.guilds {
        g.id.hash(&mut h);
        g.name.hash(&mut h);
        g.owner_id.hash(&mut h);
        for c in &g.channels {
            c.id.hash(&mut h);
            std::mem::discriminant(&c.kind).hash(&mut h);
            c.name.hash(&mut h);
        }
    }
    for d in &snap.dms {
        d.channel.id.hash(&mut h);
        d.peer.username.hash(&mut h);
    }
    for f in snap.incoming.iter().chain(&snap.friends).chain(&snap.outgoing) {
        f.username.hash(&mut h);
    }
    let mut voice: Vec<(&i64, &(usize, bool))> = snap.voice.iter().collect();
    voice.sort_unstable_by_key(|(ch, _)| **ch);
    for (ch, (n, joined)) in voice {
        ch.hash(&mut h);
        n.hash(&mut h);
        joined.hash(&mut h);
    }
    let sig = h.finish();

    // egui 0.36 keeps one style per theme; the live one is the active
    // theme's.
    let style = ctx.style_of(ctx.theme());
    let style_ok = mv
        .mid_min_style
        .as_ref()
        .is_some_and(|s| Arc::ptr_eq(s, &style) || **s == *style);
    if style_ok && mv.mid_min_cache.is_some_and(|(s, _)| s == sig) {
        return mv.mid_min_cache.unwrap().1;
    }
    let w = middle_min_width(ctx, &style, snap);
    mv.mid_min_cache = Some((sig, w));
    mv.mid_min_style = Some(style);
    w
}

fn middle(
    ui: &mut egui::Ui,
    state: &Arc<Mutex<ClientState>>,
    rt: &tokio::runtime::Handle,
    mv: &mut MainView,
    ctx: &egui::Context,
    snap: Option<&PanelSnap>,
) {
    let Some(snap) = snap else { return };
    let (selected, guilds, voice, my_id) = (snap.selected, &snap.guilds, &snap.voice, snap.my_id);

    // Channels / friends scroll so a long list never pushes the layout.
    egui::ScrollArea::vertical()
        .auto_shrink([false, true])
        .show(ui, |ui| match selected {
            Selection::Friends => friends_panel(ui, state, rt, mv, ctx, snap),
            Selection::Dm(ch) => {
                let Some(peer) = snap.dms.iter().find(|d| d.channel.id == ch).map(|d| &d.peer)
                else {
                    return;
                };
                ui.heading(format!("@{}", peer.username));
                ui.weak("private, end-to-end encrypted");
                if ui.button("Call").clicked() {
                    crate::call::start_private_call(state, rt, peer.clone(), ch);
                }
            }
            Selection::Channel(ch) => {
                let Some(g) = guilds
                    .iter()
                    .find(|g| g.channels.iter().any(|c| c.id == ch))
                else {
                    ui.weak("nothing selected");
                    return;
                };
                ui.heading(g.name.as_str());
                let is_owner = g.owner_id == my_id;
                if is_owner {
                    ui.horizontal(|ui| {
                        if ui.small_button("+ channel").clicked() {
                            mv.channel_popup = !mv.channel_popup;
                            // Focus the name field when the popup opens.
                            mv.channel_popup_focus = mv.channel_popup;
                        }
                        if ui.small_button("invite").clicked() {
                            spawn_invite(state, rt, ctx, g.id, g.name.clone());
                        }
                    });
                }
                ui.separator();
                for c in &g.channels {
                    match c.kind {
                        ChannelKind::Text => {
                            let sel = c.id == ch;
                            ui.horizontal(|ui| {
                                if ui.selectable_label(sel, format!("# {}", c.name)).clicked() {
                                    let mut st = guard(state);
                                    if let Some(m) = st.main_mut() {
                                        m.selected = Selection::Channel(c.id);
                                        m.unread.remove(&c.id);
                                    }
                                }
                                if is_owner && confirm_delete(ui, mv, c.id) {
                                    let id = c.id;
                                    spawn_rest(state, rt, ctx, move |h| async move {
                                        h.net.delete_channel(id).await
                                    });
                                }
                            });
                        }
                        ChannelKind::Voice => {
                            let (n, joined) = voice.get(&c.id).copied().unwrap_or((0, false));
                            let label = if joined {
                                format!("(v) {} — {n} in call  [leave]", c.name)
                            } else {
                                format!("(v) {} — {n} in call", c.name)
                            };
                            ui.horizontal(|ui| {
                                if ui.selectable_label(joined, label).clicked() {
                                    if joined {
                                        crate::call::leave_active_call(state, rt);
                                    } else {
                                        crate::call::join_voice_channel(state, rt, c.id);
                                    }
                                }
                                if is_owner && confirm_delete(ui, mv, c.id) {
                                    let id = c.id;
                                    spawn_rest(state, rt, ctx, move |h| async move {
                                        h.net.delete_channel(id).await
                                    });
                                }
                            });
                        }
                        ChannelKind::Dm => {}
                    }
                }
                channel_popup(state, rt, mv, ctx, g.id, is_owner);
            }
        });
}

/// "+ channel" window for guild owners: name + text/voice toggle. The
/// name field grabs focus on open, Enter creates, Escape closes.
fn channel_popup(
    state: &Arc<Mutex<ClientState>>,
    rt: &tokio::runtime::Handle,
    mv: &mut MainView,
    ctx: &egui::Context,
    guild_id: i64,
    is_owner: bool,
) {
    if !is_owner {
        return;
    }
    let mut open = mv.channel_popup;
    let mut close = false;
    egui::Window::new("New channel")
        .id(egui::Id::new("channel_popup"))
        .open(&mut open)
        .collapsible(false)
        .show(ctx, |ui| {
            // Explicit id: stable focus regardless of surrounding layout
            // (see the chat composer).
            let name_field = ui.add(
                egui::TextEdit::singleline(&mut mv.new_channel_name).id_salt("new_channel_name"),
            );
            if mv.channel_popup_focus {
                name_field.request_focus();
                mv.channel_popup_focus = false;
            }
            ui.checkbox(&mut mv.new_channel_voice, "voice channel");
            let create = ui.add_enabled(
                !mv.new_channel_name.trim().is_empty(),
                egui::Button::new("Create"),
            );
            if create.clicked()
                || (name_field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))
            {
                let name = mv.new_channel_name.trim().to_string();
                if !name.is_empty() {
                    mv.new_channel_name.clear();
                    close = true;
                    let kind = if mv.new_channel_voice {
                        ChannelKind::Voice
                    } else {
                        ChannelKind::Text
                    };
                    spawn_channel_rest(state, rt, ctx, guild_id, name, kind);
                }
            }
            if name_field.has_focus()
                && ui.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Escape))
            {
                close = true;
            }
        });
    mv.channel_popup = open && !close;
}

fn spawn_channel_rest(
    state: &Arc<Mutex<ClientState>>,
    rt: &tokio::runtime::Handle,
    ctx: &egui::Context,
    guild_id: i64,
    name: String,
    kind: ChannelKind,
) {
    let Some(h) = net_handle(state) else { return };
    let state = Arc::clone(state);
    let ctx = ctx.clone();
    rt.spawn(async move {
        match h
            .net
            .create_channel(guild_id, &CreateChannelRequest { name, kind })
            .await
        {
            Ok(c) => {
                let mut st = guard(&state);
                if let Some(m) = st.main_mut() {
                    if let Some(g) = m.guilds.iter_mut().find(|g| g.id == guild_id) {
                        if !g.channels.iter().any(|x| x.id == c.id) {
                            g.channels.push(c);
                        }
                    }
                }
            }
            Err(e) => {
                if let Some(m) = guard(&state).main_mut() {
                    m.notice = Some(e);
                }
            }
        }
        ctx.request_repaint();
    });
}

fn friends_panel(
    ui: &mut egui::Ui,
    state: &Arc<Mutex<ClientState>>,
    rt: &tokio::runtime::Handle,
    mv: &mut MainView,
    ctx: &egui::Context,
    snap: &PanelSnap,
) {
    let (friends, incoming, outgoing, online) =
        (&snap.friends, &snap.incoming, &snap.outgoing, &snap.online);

    ui.heading("Friends");
    ui.separator();

    if !incoming.is_empty() {
        ui.strong("Incoming requests");
        for f in incoming {
            ui.horizontal(|ui| {
                ui.colored_label(
                    if online.contains(&f.id) {
                        egui::Color32::LIGHT_GREEN
                    } else {
                        egui::Color32::GRAY
                    },
                    "●",
                );
                ui.label(f.username.as_str());
                if ui.button("Accept").clicked() {
                    let (id, brief) = (f.id, f.clone());
                    {
                        let mut st = guard(state);
                        if let Some(m) = st.main_mut() {
                            m.incoming_requests.retain(|a| a.id != id);
                            if !m.friends.iter().any(|a| a.id == id) {
                                m.friends.push(brief);
                            }
                        }
                    }
                    spawn_rest(state, rt, ctx, move |h| async move {
                        h.net.accept_friend_request(id).await
                    });
                }
                if ui.button("Decline").clicked() {
                    let id = f.id;
                    {
                        let mut st = guard(state);
                        if let Some(m) = st.main_mut() {
                            m.incoming_requests.retain(|a| a.id != id);
                        }
                    }
                    spawn_rest(state, rt, ctx, move |h| async move {
                        h.net.decline_friend_request(id).await
                    });
                }
            });
        }
        ui.add_space(4.0);
    }

    if !outgoing.is_empty() {
        ui.strong("Sent requests");
        for f in outgoing {
            ui.horizontal(|ui| {
                ui.label(f.username.as_str());
                if ui.small_button("cancel").clicked() {
                    let id = f.id;
                    {
                        let mut st = guard(state);
                        if let Some(m) = st.main_mut() {
                            m.outgoing_requests.retain(|a| a.id != id);
                        }
                    }
                    // The decline endpoint doubles as cancel for the
                    // caller's own outgoing request.
                    spawn_rest(state, rt, ctx, move |h| async move {
                        h.net.decline_friend_request(id).await
                    });
                }
            });
        }
        ui.add_space(4.0);
    }

    ui.strong("Friends");
    if friends.is_empty() {
        ui.weak("none yet — add someone below");
    }
    for f in friends {
        ui.horizontal(|ui| {
            let on = online.contains(&f.id);
            ui.colored_label(
                if on {
                    egui::Color32::LIGHT_GREEN
                } else {
                    egui::Color32::GRAY
                },
                "●",
            );
            ui.label(f.username.as_str());
            if ui.button("Message").clicked() {
                open_dm_and_select(state, rt, ctx, f.id);
            }
        });
    }

    ui.add_space(8.0);
    ui.separator();
    ui.label("Add friend");
    let field = ui.add(
        egui::TextEdit::singleline(&mut mv.add_friend)
            // Explicit id: the conditional request sections above shift
            // auto ids when they appear, dropping focus mid-typing (same
            // class of bug as the chat composer).
            .id_salt("add_friend")
            .hint_text("username")
            .desired_width(130.0),
    );
    let enter = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
    let send = ui.add_enabled(
        !mv.add_friend.trim().is_empty(),
        egui::Button::new("Send request"),
    );
    if enter || send.clicked() {
        let name = mv.add_friend.trim().to_string();
        if !name.is_empty() {
            mv.add_friend.clear();
            let state2 = Arc::clone(state);
            let ctx2 = ctx.clone();
            if let Some(h) = net_handle(state) {
                rt.spawn(async move {
                    // The protocol sends friend requests by account id, so
                    // resolve the username first.
                    match h.net.lookup_username(&name).await {
                        Ok(brief) => match h.net.send_friend_request(brief.id).await {
                            Ok(()) => {
                                let mut st = guard(&state2);
                                if let Some(m) = st.main_mut() {
                                    if !m.outgoing_requests.iter().any(|a| a.id == brief.id) {
                                        m.outgoing_requests.push(brief);
                                    }
                                }
                            }
                            Err(e) => {
                                if let Some(m) = guard(&state2).main_mut() {
                                    m.notice = Some(e);
                                }
                            }
                        },
                        Err(e) => {
                            if let Some(m) = guard(&state2).main_mut() {
                                m.notice = Some(e);
                            }
                        }
                    }
                    ctx2.request_repaint();
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Right column: chat
// ---------------------------------------------------------------------------

/// Composer growth cap, in text rows: up to this many lines the field
/// grows with its content, past it the field scrolls internally instead of
/// pushing the message list away.
const COMPOSER_MAX_ROWS: usize = 3;
/// Notice banner lifetime: the single notice slot auto-clears after this,
/// so a stale banner can neither sit forever nor mask a later one.
const NOTICE_TTL: Duration = Duration::from_secs(8);
/// How long a "Load older" scroll anchor stays armed before giving up (a
/// failed or empty fetch must not pin a stale anchor).
const LOAD_ANCHOR_TIMEOUT: Duration = Duration::from_secs(5);

/// "Send" paper-plane icon: white strokes on a 24×24 viewBox, tinted to
/// the text color at render time so it follows the theme.
const ICON_SEND: &[u8] = br##"<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><g fill="none" stroke="#ffffff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 2 11 13"/><path d="M22 2 15 22 11 13 2 9 22 2z"/></g></svg>"##;
/// "Attach file" paper-clip icon, same white-stroke convention as
/// [`ICON_SEND`].
const ICON_ATTACH: &[u8] = br##"<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><path fill="none" stroke="#ffffff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" d="M21.4 11l-9.2 9.2a6 6 0 0 1-8.5-8.5l9.2-9.2a4 4 0 0 1 5.6 5.6l-9.1 9.2a2 2 0 0 1-2.8-2.8l8.4-8.5"/></svg>"##;
/// "Reply" arrow, for a message row's hover action (same convention as
/// [`ICON_SEND`]).
const ICON_REPLY: &[u8] = br##"<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><g fill="none" stroke="#ffffff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 14 4 9l5-5"/><path d="M20 20v-7a4 4 0 0 0-4-4H4"/></g></svg>"##;
/// "Delete message" trash can, same convention as [`ICON_SEND`].
const ICON_TRASH: &[u8] = br##"<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><g fill="none" stroke="#ffffff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></g></svg>"##;

/// Frames an image texture may sit untouched before eviction
/// (see [`MainView::evict_stale_images`]).
const IMAGE_IDLE_FRAMES: u64 = 900;
/// Hard cap on cached image textures regardless of freshness.
const IMAGE_CACHE_CAP: usize = 48;
/// Pixel margin the message list renders outside the viewport on both
/// sides, absorbing estimate error in unmeasured rows so the seams stay
/// covered while scrolling.
const ROW_OVERDRAW_PX: f32 = 96.0;
/// One side of a message row's hover-action gutter: largest the bare hover
/// icons get; rows shorter than this shrink the icons to fit.
const MSG_ACTION_SIZE: f32 = 18.0;
/// Width reserved on the right of EVERY message row (hovered or not) so
/// the hover-revealed reply/delete buttons appearing there never shift
/// the content: two [`MSG_ACTION_SIZE`] buttons plus their gap.
const MSG_GUTTER_W: f32 = 2.0 * MSG_ACTION_SIZE + 8.0;
/// Breathing room kept under the newest message row.
const LIST_BOTTOM_PX: f32 = 8.0;

fn chat(
    ui: &mut egui::Ui,
    state: &Arc<Mutex<ClientState>>,
    store: &Arc<Mutex<Store>>,
    rt: &tokio::runtime::Handle,
    mv: &mut MainView,
    ctx: &egui::Context,
    snap: Option<&PanelSnap>,
) {
    // Bring finished background image decodes onto the UI thread as
    // textures (no-op when nothing is pending).
    attachments::drain_decoded(ctx, mv);

    // Fold drafts parked by failed sends back into their composers (the
    // send task cannot reach this view from its thread).
    let rescued = std::mem::take(&mut *guard(&mv.unsent));
    for (fch, text) in rescued {
        restore_draft(&mut mv.composer, fch, &text);
    }

    // Attach-button picks cross back here from the picker thread; the
    // channel is the one the click happened in (the dialog may outlive a
    // channel switch), so this drains even with no channel selected.
    while let Ok((fch, path)) = mv.attach_rx.try_recv() {
        attachments::add_pending(mv, fch, path);
    }

    // Stale message-delete confirmations disarm themselves — same TTL
    // policy as the channel delete control (see [`confirm_delete`]).
    if mv
        .msg_delete_confirm
        .is_some_and(|(_, at)| at.elapsed() > DELETE_CONFIRM_TTL)
    {
        mv.msg_delete_confirm = None;
    }

    // Status / notice banners.
    let (reconnecting, notice) = {
        let st = guard(state);
        match st.main() {
            Some(m) => {
                let r = match &m.connection {
                    ConnStatus::Reconnecting(reason) => Some(reason.clone()),
                    ConnStatus::Online => None,
                };
                (r, m.notice.clone())
            }
            None => (None, None),
        }
    };
    if let Some(reason) = reconnecting {
        ui.colored_label(egui::Color32::YELLOW, format!("offline — {reason}"));
    }
    if let Some(n) = notice {
        // Expiry bookkeeping (see NOTICE_TTL): the state carries text
        // only, so the view timestamps it. A changed notice restarts the
        // clock; an expired one clears itself instead of lingering or
        // masking the next one.
        let started = match &mv.notice_seen {
            Some((prev, at)) if prev == &n => *at,
            _ => Instant::now(),
        };
        let age = started.elapsed();
        if age >= NOTICE_TTL {
            if let Some(m) = guard(state).main_mut() {
                m.notice = None;
            }
            mv.notice_seen = None;
        } else {
            mv.notice_seen = Some((n.clone(), started));
            ctx.request_repaint_after(NOTICE_TTL - age);
            ui.horizontal(|ui| {
                ui.colored_label(egui::Color32::RED, n);
                if ui.small_button("x").clicked() {
                    if let Some(m) = guard(state).main_mut() {
                        m.notice = None;
                    }
                }
            });
        }
    } else {
        mv.notice_seen = None;
    }

    let ch = match snap.and_then(|s| match s.selected {
        Selection::Channel(c) | Selection::Dm(c) => Some(c),
        Selection::Friends => None,
    }) {
        Some(ch) => ch,
        None => {
            // Leaving the chat column forgets the last channel so returning
            // to one re-scrolls to the bottom (see the message list below).
            mv.chat_channel_prev = None;
            ui.weak("select a channel, a direct message, or Friends");
            // The image LRU still sweeps (only the open lightbox stays
            // pinned), and the lightbox itself keeps rendering here.
            let mut keep = HashSet::new();
            if let Some((aid, _)) = mv.image_popup {
                mv.touch_image(aid);
                keep.insert(aid);
            }
            mv.evict_stale_images(&keep);
            attachments::image_popup(state, rt, ctx, mv);
            return;
        }
    };

    let title = snap.map(|s| snap_channel_name(s, ch)).unwrap_or_default();
    ui.heading(title);

    // First open: seed from SQLite, then fetch the newest REST page.
    let newly_loaded = {
        let mut st = guard(state);
        st.main_mut().map(|m| m.loaded.insert(ch)).unwrap_or(false)
    };
    if newly_loaded {
        fetch_history(state, store, rt, ctx, mv, ch, None);
    }
    if let Some(m) = guard(state).main_mut() {
        m.unread.remove(&ch);
    }

    // Files dropped onto the window (anywhere) queue with the viewed
    // channel's composer — the same pending state the attach button feeds.
    attachments::add_dropped(ui, mv, ch);

    // Channel-switch detection for the message list's scroll state (see
    // the ScrollArea below).
    let scroll_reset = mv.chat_channel_prev != Some(ch);
    mv.chat_channel_prev = Some(ch);
    if scroll_reset {
        // Opening a channel seeds the plaintext cache in one batch; the
        // render loop below never queries the store per row.
        seed_plaintexts(mv, state, store, ch);
    }

    // Older history. The click remembers the currently-oldest row so the
    // message list can hold the reading position when the older page
    // prepends — but only for a reader scrolled up; someone stuck to the
    // bottom stays put (stick_to_bottom holds them there).
    let has_more = guard(state)
        .main()
        .and_then(|m| m.has_more.get(&ch).copied())
        .unwrap_or(true);
    let load_clicked = has_more && ui.button("Load older").clicked();

    // Composer strip, carved out as a bottom panel BEFORE the history
    // ScrollArea: a vertical ScrollArea claims all remaining height of its
    // parent, so widgets laid out after it were pushed off-screen (the
    // invisible-composer bug). Typing indicator, reply banner, pending
    // attachments, and upload progress strip live here too, directly above
    // the input.
    egui::Panel::bottom("chat_composer")
        .resizable(false)
        .min_size(52.0)
        .show(ui, |ui| {
            // Breathing room between the message list and everything the
            // composer stack renders (the panel's own frame adds only a
            // hairline separator above this).
            ui.add_space(8.0);

            // Typing indicator (pruned past its TTL). The server echoes our
            // own Typing events back to us; those are suppressed here so
            // the strip lists only the other side — sending itself still
            // happens (see `maybe_send_typing`).
            let typing_line: Option<String> = {
                let mut st = guard(state);
                match st.main_mut() {
                    Some(m) => match m.typing.get(&ch).copied() {
                        Some((sender, at)) if at.elapsed().as_secs() < TYPING_TTL_SECS => {
                            if sender == m.account.id {
                                None
                            } else {
                                Some(resolve_name(&mut mv.names, m, sender))
                            }
                        }
                        Some(_) => {
                            m.typing.remove(&ch);
                            None
                        }
                        None => None,
                    },
                    None => None,
                }
            };
            if let Some(name) = typing_line {
                ui.weak(format!("{name} is typing…"));
            }

            // Reply banner: who and what is being replied to, cancellable.
            // Both halves were resolved once, when the reply was armed
            // (see `message_row`); a target that has since left the
            // message list (deleted) drops the reply instead — the
            // reply-sender index tracks the live list.
            if let Some(rid) = mv.reply_to.get(&ch).copied() {
                let gone = !mv.reply_senders.contains_key(&rid);
                match mv.reply_banner.get(&ch).cloned() {
                    Some((name, snippet)) if !gone => {
                        ui.horizontal(|ui| {
                            ui.weak(format!("replying to {name}: {snippet}"));
                            if ui.small_button("cancel").clicked() {
                                mv.reply_to.remove(&ch);
                                mv.reply_banner.remove(&ch);
                            }
                        });
                    }
                    _ => {
                        mv.reply_to.remove(&ch);
                        mv.reply_banner.remove(&ch);
                    }
                }
            }

            // Pending attachments (attach button / OS drop): queued with
            // the next send, removable here.
            attachments::pending_ui(ui, mv, ch);

            // Attachment upload progress strip (above the composer).
            attachments::uploads_ui(ui, state);

            // Composer: [text field][send][attach] — the buttons sit to
            // the right of the input. Laid out right_to_left: attach lands
            // rightmost, send beside it, and the field — added last —
            // fills all remaining width (its INFINITY desired width clamps
            // to what is left). egui centers each child against the row's
            // growing height, so the buttons stay level with the text
            // whether the draft is one row or three.
            //
            // The TextEdit needs an explicit id: auto ids come from a
            // per-Ui allocation counter, so the conditional strips above
            // (typing indicator, reply banner, uploads) appearing or
            // vanishing shifted the id and silently dropped keyboard focus
            // mid-typing. The channel id in the salt keeps one cursor
            // state per conversation (drafts already live in
            // `mv.composer`).
            let line_height = ui.text_style_height(&egui::TextStyle::Body);
            let (send_clicked, field) = {
                ui.with_layout(
                    egui::Layout::right_to_left(egui::Align::Center),
                    |ui| {
                        let mut send_clicked = false;
                        if icon_button(ui, "bytes://attach.svg", ICON_ATTACH, "Attach file")
                            .clicked()
                        {
                            attachments::begin_attach(ctx, mv, ch);
                        }
                        if icon_button(ui, "bytes://send.svg", ICON_SEND, "Send").clicked() {
                            send_clicked = true;
                        }
                        let buf = mv.composer.entry(ch).or_default();
                        // The wrapping ScrollArea grows with the text up
                        // to COMPOSER_MAX_ROWS rows and scrolls past that,
                        // so a long draft never pushes the message list
                        // away. The TextEdit itself drives the scroll to
                        // keep the caret visible.
                        let field = egui::ScrollArea::vertical()
                            .id_salt(("composer_scroll", ch))
                            .auto_shrink([false, true])
                            .max_height(COMPOSER_MAX_ROWS as f32 * line_height)
                            .scroll_bar_visibility(
                                egui::containers::scroll_area::ScrollBarVisibility::AlwaysHidden,
                            )
                            .show(ui, |ui| {
                                ui.add(
                                    egui::TextEdit::multiline(buf)
                                        .id_salt(("composer", ch))
                                        .hint_text(
                                            "Message…  (Enter to send, Shift+Enter for a new line)",
                                        )
                                        .desired_width(f32::INFINITY)
                                        .desired_rows(1)
                                        // Keep only the horizontal inset:
                                        // no vertical padding, the field
                                        // hugs its lines exactly.
                                        .margin(egui::Margin::symmetric(4, 0)),
                                )
                            })
                            .inner;
                        (send_clicked, field)
                    },
                )
                .inner
            };
            if field.changed() {
                maybe_send_typing(state, mv, ch);
            }
            // Escape cancels a pending reply while the composer holds
            // focus, consuming the key so the call overlay — which only
            // acts when no widget is focused — never sees it (a focused
            // composer wins; the overlay renders after this view).
            if field.has_focus()
                && mv.reply_to.contains_key(&ch)
                && ui.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Escape))
            {
                mv.reply_to.remove(&ch);
                mv.reply_banner.remove(&ch);
            }
            // Enter (without Shift) sends; Shift+Enter keeps the newline
            // the field just inserted. `has_focus` gates the key so Enter
            // pressed in another field never sends here.
            let send = send_clicked
                || (field.has_focus()
                    && ui.input(|i| i.key_pressed(egui::Key::Enter) && !i.modifiers.shift));
            if send {
                let text = mv.composer.get(&ch).cloned().unwrap_or_default();
                // trim() also strips the "\n" the field inserts on the
                // sending Enter; whitespace-only drafts never send.
                let text = text.trim().to_string();
                mv.composer.insert(ch, String::new());
                if !text.is_empty() {
                    do_send(state, store, rt, ctx, mv, ch, text);
                }
                // Queued attachments ride the same send: each file enters
                // the upload pipeline as its own encrypted message.
                for file in mv.pending.remove(&ch).unwrap_or_default() {
                    attachments::queue_upload(state, store, rt, ctx, mv, ch, file);
                }
                // A button click moves focus to the button — put it back
                // so typing continues without a re-click.
                field.request_focus();
            }
        });

    // Message list — virtualized per ADR 0003.
    let mut att_keep = HashSet::new();
    let count = guard(state)
        .main()
        .and_then(|m| m.messages.get(&ch))
        .map_or(0, Vec::len);
    if count == 0 {
        // Between `loaded` (set when the channel first opens) and
        // `has_more` (set when the initial page lands) the first fetch is
        // in flight — spinner while it runs, empty state once it resolves.
        // The two sets already bracket the fetch, so no extra plumbing.
        let fetching = guard(state)
            .main()
            .is_some_and(|m| m.loaded.contains(&ch) && !m.has_more.contains_key(&ch));
        if fetching {
            ui.horizontal(|ui| {
                ui.add(egui::Spinner::new());
                ui.weak("loading history…");
            });
        } else {
            ui.weak("no messages yet — say hi");
        }
    } else {
        // Per-channel scroll state. Without an explicit id the offset —
        // and stick_to_bottom's stuck flag — leak across channel
        // switches: a channel opened mid-history and never re-stuck, so
        // new messages arrived off-screen. Keying the id by channel gives
        // each conversation its own scroll memory; a switch additionally
        // snaps to the newest message.
        //
        // A pending "Load older" anchor instead aims the reserved slot of
        // the previously-oldest row once the older page lands (its index
        // grows), so that row is laid out this frame and can be pinned
        // exactly (see the row loop below). Anchors that never resolve —
        // failed or empty fetch — time out.
        let mut anchor_offset = None;
        if let Some(a) = mv.load_anchor {
            if a.channel != ch || a.armed_at.elapsed() > LOAD_ANCHOR_TIMEOUT {
                mv.load_anchor = None;
            } else {
                let idx = guard(state).main().and_then(|m| {
                    m.messages
                        .get(&ch)
                        .and_then(|v| v.iter().position(|x| x.id == a.msg_id))
                });
                match idx {
                    Some(i) if i > a.idx_armed => anchor_offset = Some(i),
                    Some(_) => {}                  // older page not landed yet
                    None => mv.load_anchor = None, // row vanished (deleted)
                }
            }
        }
        // Row metrics for the virtualized walk: measured heights where a
        // row has rendered (see `message_row`), estimates before its
        // first render. Estimates only decide which rows intersect the
        // viewport; the first render replaces them with measured values.
        let line_h = ui.text_style_height(&egui::TextStyle::Body);
        let spacing = ui.spacing().item_spacing.y;
        let content_w = (ui.available_width() - MSG_GUTTER_W).max(60.0);
        let mut list = egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .id_salt(("chat_scroll", ch));
        if let Some(i) = anchor_offset {
            // Aim the viewport near the anchor row so it renders this
            // frame; `message_row` pins it exactly once laid out. Rows
            // above the anchor contribute measured heights, with
            // estimates filling never-rendered gaps.
            let mut off = 0.0;
            {
                let st = guard(state);
                if let Some(msgs) = st.main().and_then(|m| m.messages.get(&ch)) {
                    for msg in msgs.iter().take(i) {
                        if msg.kind == MessageKind::Control {
                            continue;
                        }
                        let body = mv
                            .plaintexts
                            .get(&msg.id)
                            .map(String::as_str)
                            .or_else(|| (msg.id < 0).then(|| msg.content.as_str()));
                        let h = mv
                            .row_heights
                            .get(&msg.id)
                            .copied()
                            .unwrap_or_else(|| {
                                estimate_row_height(msg, line_h, spacing, content_w, body)
                            });
                        off += h + spacing;
                    }
                }
            }
            list = list.vertical_scroll_offset(off);
        }
        let scrolled = list.show_viewport(ui, |ui, viewport| {
            // A width change re-wraps every body: drop the measured
            // heights so affected rows re-render and re-measure.
            if (mv.row_w - content_w).abs() > 0.5 {
                mv.row_heights.clear();
                mv.row_w = content_w;
            }
            let top = ui.max_rect().top();
            let total;
            let (mut y0, mut y1) = (0.0f32, 0.0f32);
            let mut i0 = usize::MAX;
            let rows: Vec<RowSnap>;
            let mut misses: Vec<i64> = Vec::new();
            {
                // Phase 1, one state guard: walk every row accumulating
                // heights and snapshot the ones intersecting the viewport
                // (plus the overdraw margin) — grouping verdict, sender
                // and reply names resolved here too. The guard must be
                // gone before widget code runs (rows re-lock state for
                // attachments and network), and the store is only ever
                // locked after state is released (state → store order).
                let st = guard(state);
                let Some(m) = st.main() else { return };
                let Some(msgs) = m.messages.get(&ch) else { return };
                // Reply-prefix index for the loaded channel: message id →
                // sender id, rebuilt when the message list moves. Resolves
                // the ↪ prefixes in O(1) instead of a linear scan per
                // replied row, and doubles as the reply banner's
                // "target still exists" check.
                let sig = (
                    ch,
                    msgs.len(),
                    msgs.first().map(|x| x.id).unwrap_or(0),
                    msgs.last().map(|x| x.id).unwrap_or(0),
                );
                if mv.reply_sig != Some(sig) {
                    mv.reply_senders = msgs
                        .iter()
                        .filter(|x| x.kind != MessageKind::Control)
                        .map(|x| (x.id, x.sender_id))
                        .collect();
                    mv.reply_sig = Some(sig);
                }
                let mut vis = Vec::new();
                let mut cursor = 0.0f32;
                // (sender, minute) of the previous non-Control row — the
                // grouping context of the next one.
                let mut prev: Option<(i64, i64)> = None;
                for (idx, msg) in msgs.iter().enumerate() {
                    if msg.kind == MessageKind::Control {
                        continue;
                    }
                    let body = mv
                        .plaintexts
                        .get(&msg.id)
                        .map(String::as_str)
                        .or_else(|| (msg.id < 0).then(|| msg.content.as_str()));
                    let h = mv
                        .row_heights
                        .get(&msg.id)
                        .copied()
                        .unwrap_or_else(|| {
                            estimate_row_height(msg, line_h, spacing, content_w, body)
                        });
                    if cursor < viewport.max.y + ROW_OVERDRAW_PX
                        && cursor + h > viewport.min.y - ROW_OVERDRAW_PX
                    {
                        if i0 == usize::MAX {
                            i0 = idx;
                            y0 = cursor;
                        }
                        if let Some(att) = &msg.attachment {
                            att_keep.insert(att.id);
                            // The envelope is immutable per message id —
                            // clone it out once and keep it.
                            if !mv.file_envs.contains_key(&msg.id) {
                                if let Some(fe) = m.file_meta.get(&msg.id) {
                                    mv.file_envs.insert(msg.id, fe.clone());
                                }
                            }
                        }
                        if msg.id > 0 && !mv.plaintexts.contains_key(&msg.id) {
                            misses.push(msg.id);
                        }
                        vis.push(RowSnap {
                            id: msg.id,
                            sender: resolve_name(&mut mv.names, m, msg.sender_id),
                            is_mine: msg.sender_id == m.account.id,
                            grouped: msg.reply_to.is_none()
                                && prev.is_some_and(|(p_sender, p_min)| {
                                    p_sender == msg.sender_id
                                        && p_min == msg.created_at_ms.div_euclid(60_000)
                                }),
                            created_at_ms: msg.created_at_ms,
                            reply_name: msg
                                .reply_to
                                .and_then(|rid| mv.reply_senders.get(&rid).copied())
                                .map(|sid| resolve_name(&mut mv.names, m, sid)),
                            temp_body: (msg.id < 0).then(|| msg.content.clone()),
                            attachment: msg.attachment.clone(),
                        });
                        y1 = cursor + h + spacing;
                    }
                    cursor += h + spacing;
                    prev = Some((msg.sender_id, msg.created_at_ms.div_euclid(60_000)));
                }
                // A small breathing gap under the newest row.
                total = (cursor - spacing + LIST_BOTTOM_PX).max(0.0);
                rows = vis;
            }
            // Cache-miss fallback: one store pass for the few genuinely
            // new visible rows (temps excluded — their body travels in
            // the dto).
            if !misses.is_empty() {
                let found: Vec<(i64, String)> = {
                    let s = guard(store);
                    misses
                        .iter()
                        .filter_map(|&id| s.plaintext(id).map(|p| (id, p)))
                        .collect()
                };
                for (id, p) in found {
                    mv.plaintexts.insert(id, p);
                }
            }
            // Reserve the full content height, then lay the visible rows
            // out inside their band — the same mechanics show_rows uses,
            // but with per-message measured heights (an image row is ~15×
            // the fixed 18 px slot the old reservation assumed).
            ui.set_height(total);
            if scroll_reset {
                // A fresh channel: land on the newest row this frame with no
                // animated jump (a fresh scroll state's offset otherwise
                // renders from the top for one frame before clamping down).
                let bottom = egui::Rect::from_min_size(
                    egui::pos2(ui.max_rect().left(), top + total),
                    egui::Vec2::splat(1.0),
                );
                ui.scroll_to_rect_animation(
                    bottom,
                    Some(egui::Align::BOTTOM),
                    egui::style::ScrollAnimation::none(),
                );
            }
            if rows.is_empty() {
                return;
            }
            let rect = egui::Rect::from_x_y_ranges(
                ui.max_rect().x_range(),
                (top + y0)..=(top + y1),
            );
            ui.scope_builder(egui::UiBuilder::new().max_rect(rect), |vui| {
                vui.skip_ahead_auto_ids(i0);
                for row in &rows {
                    message_row(vui, state, store, rt, ctx, mv, ch, row);
                }
            });
        });
        // Whether we sit at the bottom gates "Load older" anchoring on the
        // next click: a stuck-to-bottom reader must not be yanked up when
        // the older page prepends.
        mv.chat_at_bottom =
            scrolled.state.offset.y + 1.0 >= scrolled.content_size.y - scrolled.inner_rect.height();

        // Lazy scroll: reaching the top (or clicking "Load older") fetches
        // the page before the oldest message we hold. A cooldown stops a
        // held scroll-top from firing every frame; the anchor holds the
        // reading position as older rows prepend. Skipped on the channel-
        // switch frame (scroll_reset) so the bottom-landing pin above isn't
        // mistaken for a scroll-to-top.
        let at_top = scrolled.state.offset.y <= 1.0;
        let cooldown = mv
            .last_load_attempt
            .map_or(true, |(_, t)| t.elapsed() > std::time::Duration::from_millis(800));
        if load_clicked || (has_more && at_top && !scroll_reset && cooldown) {
            let oldest = guard(state).main().and_then(|m| {
                m.messages
                    .get(&ch)
                    .and_then(|v| v.iter().position(|x| x.id > 0).map(|idx| (v[idx].id, idx)))
            });
            if !mv.chat_at_bottom
                && let Some((id, idx)) = oldest
            {
                mv.load_anchor = Some(LoadAnchor {
                    channel: ch,
                    msg_id: id,
                    idx_armed: idx,
                    armed_at: Instant::now(),
                });
            }
            match oldest.map(|(id, _)| id) {
                Some(before) => fetch_history(state, store, rt, ctx, mv, ch, Some(before)),
                None => {
                    if let Some(m) = guard(state).main_mut() {
                        m.has_more.insert(ch, false);
                    }
                }
            }
            mv.last_load_attempt = Some((ch, Instant::now()));
        }
    }

    // The open lightbox outranks the LRU, and its texture counts as used.
    if let Some((aid, _)) = mv.image_popup {
        mv.touch_image(aid);
        att_keep.insert(aid);
    }
    // Image-texture LRU sweep: idle entries beyond the current channel's
    // attachments and the lightbox drop; their rows re-fetch and re-decode
    // on demand when they scroll back into view.
    mv.evict_stale_images(&att_keep);

    // Image lightbox for clicked thumbnails.
    attachments::image_popup(state, rt, ctx, mv);
}

/// A visible message row, snapshotted under the state lock in `chat` and
/// rendered after it is released (row widget code re-locks state through
/// the attachments view and the network helpers, so the guard cannot
/// survive into layout). Carries only what rendering reads; the body is
/// borrowed from `MainView::plaintexts`/`file_envs` at render time.
struct RowSnap {
    id: i64,
    sender: String,
    is_mine: bool,
    grouped: bool,
    created_at_ms: i64,
    reply_name: Option<String>,
    /// Optimistic-send body (`content` of a negative-id temp row).
    temp_body: Option<String>,
    attachment: Option<AttachmentMeta>,
}

/// Height estimate for a never-measured row — the virtualized walk needs
/// positions before rows can render and measure. Text rows: a header line
/// plus wrapped body lines at the row content width; attachment rows: the
/// inline image plus its caption chip. First render replaces the estimate
/// with the measured height.
fn estimate_row_height(
    msg: &MessageDto,
    line_h: f32,
    spacing: f32,
    content_w: f32,
    body: Option<&str>,
) -> f32 {
    if msg.attachment.is_some() {
        attachments::INLINE_IMAGE_PX + line_h + 3.0 * spacing + 12.0
    } else {
        let lines = body.map_or(1, |b| {
            // ~0.55 em average glyph advance at the body font size.
            let cpl = ((content_w / (line_h * 0.55)) as usize).max(8);
            b.chars().count().div_ceil(cpl).max(1)
        });
        (1 + lines) as f32 * line_h + spacing
    }
}

/// Display name for `id`: the name cache first, then the roster. The
/// `#id` fallback is never cached — the roster entry may arrive later and
/// must re-resolve (this replaces the O(roster) `account_name` scan that
/// used to run per row per frame).
fn resolve_name(names: &mut HashMap<i64, String>, m: &MainState, id: i64) -> String {
    if let Some(n) = names.get(&id) {
        return n.clone();
    }
    let n = m.account_name(id);
    if n != format!("#{id}") {
        names.insert(id, n.clone());
    }
    n
}

/// One-line snippet for the reply banner, resolved once when the reply is
/// armed (replacing the old per-frame store-locking `preview_body`).
fn truncate_preview(body: &str) -> String {
    const LEN: usize = 40;
    let flat: Vec<char> = body.chars().map(|c| if c == '\n' { ' ' } else { c }).collect();
    let mut s: String = flat.iter().take(LEN).collect();
    if flat.len() > LEN {
        s.push('…');
    }
    s
}

/// Batch-fill [`MainView::plaintexts`] for every cached message of `ch`
/// (channel open, history fetch), so the render loop never queries the
/// store per row. Lock order state → store: the id list is collected
/// under the state guard, which is dropped before the store locks.
fn seed_plaintexts(
    mv: &mut MainView,
    state: &Arc<Mutex<ClientState>>,
    store: &Arc<Mutex<Store>>,
    ch: i64,
) {
    let ids: Vec<i64> = {
        let st = guard(state);
        match st.main().and_then(|m| m.messages.get(&ch)) {
            Some(msgs) => msgs
                .iter()
                .filter(|x| x.id > 0 && !mv.plaintexts.contains_key(&x.id))
                .map(|x| x.id)
                .collect(),
            None => return,
        }
    };
    if ids.is_empty() {
        return;
    }
    let s = guard(store);
    for id in ids {
        if let Some(p) = s.plaintext(id) {
            mv.plaintexts.insert(id, p);
        }
    }
}

/// Lay out one visible message row (see the virtualized list in `chat`)
/// and record its measured height for the next walk. Identity — sender
/// name, grouping verdict, reply target, body — arrives pre-resolved in
/// `row`; this runs after the state guard is gone, so nothing here locks
/// state except the interaction handlers (delete popup, attachments,
/// net).
#[allow(clippy::too_many_arguments)]
fn message_row(
    ui: &mut egui::Ui,
    state: &Arc<Mutex<ClientState>>,
    store: &Arc<Mutex<Store>>,
    rt: &tokio::runtime::Handle,
    ctx: &egui::Context,
    mv: &mut MainView,
    ch: i64,
    row: &RowSnap,
) {
    // Hold the "Load older" reading position: pin the anchor row to the
    // top of the viewport now that it is laid out (instant — an animated
    // scroll would drift past the target).
    if mv
        .load_anchor
        .as_ref()
        .is_some_and(|a| a.channel == ch && a.msg_id == row.id)
    {
        let top = ui.next_widget_position();
        ui.scroll_to_rect_animation(
            egui::Rect::from_min_size(top, egui::Vec2::splat(1.0)),
            Some(egui::Align::TOP),
            egui::style::ScrollAnimation::none(),
        );
        mv.load_anchor = None;
    }

    let time = fmt_time(row.created_at_ms);
    let reply = row
        .reply_name
        .as_deref()
        .map(|n| format!("  ↪ [{n}]"))
        .unwrap_or_default();
    let header = format!("{time}  {}:{reply}", row.sender);

    // One message row: content in a fixed-width region (the full row
    // width minus the action gutter) plus the constant gutter itself.
    // Because the content width never changes — hover or not — the reveal
    // of the gutter buttons can't reflow or shift the text. push_id keeps
    // the row's interact ids stable against rows appearing and vanishing
    // around it. The row's height is measured around the whole scope.
    let top_y = ui.next_widget_position().y;
    ui.push_id(("msg_row", row.id), |ui| {
        ui.horizontal(|ui| {
            let content_w = (ui.available_width() - MSG_GUTTER_W).max(60.0);
            let content = ui.allocate_ui_with_layout(
                egui::Vec2::new(content_w, 0.0),
                egui::Layout::top_down(egui::Align::LEFT),
                |ui| {
                    // Group starters keep the full header ("time sender:
                    // ↪reply"); grouped followers render body-only — no
                    // repeated header, and a tighter gap since the fixed
                    // row slots hold only the body.
                    if !row.grouped {
                        ui.label(header);
                    }
                    // Attachment rows render from the stashed File
                    // envelope (cloned into `file_envs` once per message);
                    // everything else is the plain text body, borrowed
                    // from the plaintext cache — no store query per row.
                    // Bodies wrap at the content width — at the full row
                    // width the label would run under the gutter.
                    if let Some(att) = row.attachment.as_ref() {
                        // The envelope leaves the map for the call so `mv`
                        // can be reborrowed mutably, and goes right back.
                        let fe = mv.file_envs.remove(&row.id);
                        if let Some(fe) = fe.as_ref() {
                            mv.touch_image(att.id);
                            attachments::attachment_row(ui, state, rt, ctx, mv, att, fe);
                        } else {
                            ui.add(
                                egui::Label::new("[encrypted]")
                                    .wrap_mode(egui::TextWrapMode::Wrap),
                            );
                        }
                        if let Some(fe) = fe {
                            mv.file_envs.insert(row.id, fe);
                        }
                    } else if row.id < 0 {
                        ui.add(
                            egui::Label::new(format!(
                                "{} …",
                                row.temp_body.as_deref().unwrap_or_default()
                            ))
                            .wrap_mode(egui::TextWrapMode::Wrap),
                        );
                    } else {
                        let body = egui::WidgetText::from(
                            mv.plaintexts
                                .get(&row.id)
                                .map(String::as_str)
                                .unwrap_or("[encrypted]"),
                        );
                        ui.add(egui::Label::new(body).wrap_mode(egui::TextWrapMode::Wrap));
                    }
                },
            );

            // Hover-only actions, pinned to the row's far right: reply
            // for real messages, delete to the right of it for my own.
            // Hover covers the whole row — content plus gutter — via the
            // content rect extended to the panel edge. The buttons are
            // PLACED into the reserved gutter (ui.put), not laid out, so
            // they contribute no height — hovering never shifts the text —
            // and they render as bare tinted icons with no button frame.
            // A row with an armed delete confirmation keeps its buttons
            // (the popup they anchor to must keep rendering).
            let armed = mv.msg_delete_confirm.is_some_and(|(id, _)| id == row.id);
            let row_rect = content.response.rect.with_max_x(ui.max_rect().max.x);
            let hovered = ui
                .interact(row_rect, ui.id().with("hover"), egui::Sense::hover())
                .hovered();
            if hovered || armed {
                let size = egui::Vec2::splat(row_rect.height().min(MSG_ACTION_SIZE));
                let cy = row_rect.center().y;
                let mut right = row_rect.right() - 12.0;
                let place = |right: &mut f32| {
                    let rect =
                        egui::Rect::from_center_size(egui::pos2(*right - size.x * 0.5, cy), size);
                    *right -= size.x + 4.0;
                    rect
                };
                if row.is_mine && row.id > 0 {
                    // Placed first from the right edge, so delete sits
                    // right of reply.
                    let trash = gutter_button(
                        ui,
                        place(&mut right),
                        "bytes://trash.svg",
                        ICON_TRASH,
                        "Delete message",
                    );
                    if trash.clicked() {
                        mv.msg_delete_confirm = Some((row.id, Instant::now()));
                    }
                    msg_delete_confirm_popup(mv, state, store, rt, ctx, ch, row.id, &trash);
                }
                if row.id > 0 {
                    let reply = gutter_button(
                        ui,
                        place(&mut right),
                        "bytes://reply.svg",
                        ICON_REPLY,
                        "Reply",
                    );
                    if reply.clicked() {
                        // Arm the reply and resolve its banner here,
                        // once — the snippet comes from the already-
                        // cached plaintext.
                        mv.reply_to.insert(ch, row.id);
                        let snippet = mv
                            .plaintexts
                            .get(&row.id)
                            .map(|p| truncate_preview(p))
                            .unwrap_or_else(|| "[encrypted]".into());
                        mv.reply_banner.insert(ch, (row.sender.clone(), snippet));
                    }
                }
            }
        });
    });
    let h = (ui.min_rect().bottom() - top_y).max(12.0);
    mv.row_heights.insert(row.id, h);
}

/// Fetch a page of history into the cache + store. `before == None` fetches
/// the newest page (seeding from the local cache first).
fn fetch_history(
    state: &Arc<Mutex<ClientState>>,
    store: &Arc<Mutex<Store>>,
    rt: &tokio::runtime::Handle,
    ctx: &egui::Context,
    mv: &mut MainView,
    ch: i64,
    before: Option<i64>,
) {
    let Some(h) = net_handle(state) else { return };

    if before.is_none() {
        let local = guard(store).messages_for(ch, None, 200);
        if !local.is_empty() {
            {
                let mut st = guard(state);
                if let Some(m) = st.main_mut() {
                    m.merge_messages(ch, local);
                }
            }
            // Seed the plaintext cache for the locally-cached page in one
            // batch (pages fetched on the runtime thread cannot reach
            // this view; the render loop's cache-miss fallback covers
            // those rows as they scroll into view).
            seed_plaintexts(mv, state, store, ch);
        }
    }

    let state = Arc::clone(state);
    let store = Arc::clone(store);
    let ctx = ctx.clone();
    rt.spawn(async move {
        match h.net.channel_messages(ch, before, 50).await {
            Ok(page) => {
                {
                    let s = guard(&store);
                    let _ = s.insert_message_page(&page.messages);
                }
                {
                    let mut st = guard(&state);
                    if let Some(m) = st.main_mut() {
                        m.merge_messages(ch, page.messages);
                        m.has_more.insert(ch, page.has_more);
                    }
                }
                // Rows that arrived before their Megolm session share get a
                // second chance now that this page is cached.
                {
                    let mut st = guard(&state);
                    if let Some(m) = st.main_mut() {
                        m.backfill_plaintexts(&store, ch);
                    }
                }
            }
            Err(e) => {
                if let Some(m) = guard(&state).main_mut() {
                    // Mark the fetch resolved: the chat view's initial
                    // spinner gates on `has_more` being unset and would
                    // otherwise spin forever. `true` leaves "Load older"
                    // available for a retry.
                    m.has_more.insert(ch, true);
                    m.notice = Some(e);
                }
            }
        }
        ctx.request_repaint();
    });
}

/// The encrypted send path for chat text. Everything the crypto half needs
/// is gathered under one state lock up front; the network work then runs on
/// the runtime.
///
/// The encrypt → share-first → POST sequence itself lives in
/// [`attachments::encrypt_share_and_send`], shared with the attachment
/// send path (C4): Megolm-encrypt the [`Envelope::Chat`], and when this is
/// the channel's first send, a rotation, or an unknown sid after restart,
/// mailbox every roster peer the session key *before* the message POST so
/// the very first message is already decryptable. On success the plaintext
/// is stored for our own row (the engine deliberately holds no
/// self-import) and the optimistic temp row is reconciled.
///
/// No engine → no send: chat refuses to fall back to plaintext.
///
/// Every failure path parks the cleared composer text in
/// [`MainView::unsent`]; the chat view folds it back into the composer so
/// a failed send never loses what was typed.
#[allow(clippy::too_many_arguments)]
fn do_send(
    state: &Arc<Mutex<ClientState>>,
    store: &Arc<Mutex<Store>>,
    rt: &tokio::runtime::Handle,
    ctx: &egui::Context,
    mv: &mut MainView,
    ch: i64,
    text: String,
) {
    let temp = mv.temp_id;
    mv.temp_id -= 1;
    let reply_to = mv.reply_to.remove(&ch);
    mv.reply_banner.remove(&ch);

    let gather = {
        let st = guard(state);
        st.main().map(|m| (m.account.id, m.engine.clone()))
    };
    let Some((me, engine)) = gather else {
        guard(&mv.unsent).insert(ch, text);
        return;
    };
    let Some(engine) = engine else {
        if let Some(m) = guard(state).main_mut() {
            m.notice = Some("crypto engine unavailable — sending is disabled".into());
        }
        guard(&mv.unsent).insert(ch, text);
        return;
    };

    let optimistic = MessageDto {
        id: temp,
        channel_id: ch,
        sender_id: me,
        kind: MessageKind::Chat,
        content: text.clone(),
        reply_to,
        attachment: None,
        created_at_ms: now_ms(),
    };
    if let Some(m) = guard(state).main_mut() {
        m.messages.entry(ch).or_default().push(optimistic);
    }

    let Some(h) = net_handle(state) else {
        if let Some(m) = guard(state).main_mut() {
            if let Some(v) = m.messages.get_mut(&ch) {
                v.retain(|x| x.id != temp);
            }
            m.notice = Some("not connected".into());
        }
        guard(&mv.unsent).insert(ch, text);
        return;
    };

    let state = Arc::clone(state);
    let store = Arc::clone(store);
    let ctx = ctx.clone();
    // Failure parks the draft here from this task's thread; the UI thread
    // drains it back into the composer (see `chat`).
    let unsent = Arc::clone(&mv.unsent);
    rt.spawn(async move {
        let envelope = Envelope::Chat {
            text: text.clone(),
            reply_to,
        };
        if let Err(e) = attachments::encrypt_share_and_send(
            &state, &store, &h.net, &engine, ch, &envelope, temp, None,
        )
        .await
        {
            let mut st = guard(&state);
            if let Some(m) = st.main_mut() {
                if let Some(v) = m.messages.get_mut(&ch) {
                    v.retain(|x| x.id != temp);
                }
                m.notice = Some(format!("send failed: {e}"));
            }
            guard(&unsent).insert(ch, text);
        }
        ctx.request_repaint();
    });
}

/// Put a failed send's text back into the channel's composer, prepending
/// it to whatever was typed since without duplicating it (the rescue may
/// land twice or the user may have retyped the same words).
fn restore_draft(composer: &mut HashMap<i64, String>, ch: i64, text: &str) {
    let cur = composer.entry(ch).or_default();
    if cur.starts_with(text) {
        return;
    }
    if cur.is_empty() {
        cur.push_str(text);
    } else {
        let joined = format!("{text}\n{cur}");
        *cur = joined;
    }
}

/// One Typing event per channel per 3 s while the composer changes.
fn maybe_send_typing(state: &Arc<Mutex<ClientState>>, mv: &mut MainView, ch: i64) {
    let now = Instant::now();
    let due = match mv.last_typing_sent.get(&ch) {
        Some(t) => now.duration_since(*t) >= Duration::from_secs(3),
        None => true,
    };
    if due {
        mv.last_typing_sent.insert(ch, now);
        if let Some(h) = net_handle(state) {
            let _ = h.out.try_send(WsClientMsg {
                id: net::next_msg_id(),
                body: WsClientBody::Typing { channel_id: ch },
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// How long an armed channel deletion stays confirmable before the "×"
/// disarms itself again.
const DELETE_CONFIRM_TTL: Duration = Duration::from_secs(4);

/// Two-step delete control for one channel row (text or voice): the first
/// "×" click arms an inline "sure?" yes/no confirmation that disarms itself
/// after [`DELETE_CONFIRM_TTL`]; returns `true` only on the confirming
/// click. One stray click must not wipe a channel and its E2EE history for
/// the whole guild.
fn confirm_delete(ui: &mut egui::Ui, mv: &mut MainView, channel_id: i64) -> bool {
    // Lazily disarm stale confirmations.
    if mv
        .delete_confirm
        .is_some_and(|(_, at)| at.elapsed() > DELETE_CONFIRM_TTL)
    {
        mv.delete_confirm = None;
    }
    if mv.delete_confirm.is_some_and(|(id, _)| id == channel_id) {
        let yes = ui.small_button("yes");
        let no = ui.small_button("no");
        if yes.clicked() {
            mv.delete_confirm = None;
            return true;
        }
        if no.clicked() {
            mv.delete_confirm = None;
        }
        false
    } else {
        let x = ui.small_button("×").on_hover_text(
            "Delete this channel — the encrypted history is lost for the \
             whole guild. A confirmation step follows.",
        );
        if x.clicked() {
            mv.delete_confirm = Some((channel_id, Instant::now()));
        }
        false
    }
}

/// One hover-revealed message-row action: a bare tinted SVG icon placed
/// into `rect` — no button frame, and placed (not laid out) so it never
/// contributes height to the row. Same white-stroke SVG convention as
/// [`icon_button`].
fn gutter_button(
    ui: &mut egui::Ui,
    rect: egui::Rect,
    uri: &'static str,
    svg: &'static [u8],
    tooltip: &str,
) -> egui::Response {
    let tint = ui.visuals().widgets.inactive.fg_stroke.color;
    ui.put(
        rect,
        egui::Image::from_bytes(uri, svg)
            .tint(tint)
            .sense(egui::Sense::click()),
    )
    .on_hover_cursor(egui::CursorIcon::PointingHand)
    .on_hover_text(tooltip)
}

/// Two-step delete confirmation for one message, following the channel
/// delete control's TTL policy ([`DELETE_CONFIRM_TTL`]) but scoped to a
/// message: a popup anchored at the row's trash button asks "yes"/"no".
/// One stray click must not delete a message. "yes" fires the DELETE;
/// "no", Escape, or a click outside disarms.
fn msg_delete_confirm_popup(
    mv: &mut MainView,
    state: &Arc<Mutex<ClientState>>,
    store: &Arc<Mutex<Store>>,
    rt: &tokio::runtime::Handle,
    ctx: &egui::Context,
    ch: i64,
    msg_id: i64,
    anchor: &egui::Response,
) {
    if !mv.msg_delete_confirm.is_some_and(|(id, _)| id == msg_id) {
        return;
    }
    let mut open = true;
    egui::Popup::from_response(anchor)
        .id(egui::Id::new("msg_delete_confirm"))
        .close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside)
        .show(|ui| {
            ui.label("Delete this message?");
            ui.horizontal(|ui| {
                if ui.small_button("yes").clicked() {
                    open = false;
                    spawn_delete_message(state, store, rt, ctx, ch, msg_id);
                }
                if ui.small_button("no").clicked() {
                    open = false;
                }
            });
        });
    // A close by Escape or an outside click writes `open` back false.
    if !open {
        mv.msg_delete_confirm = None;
    }
}

/// DELETE one of my messages; on success drop it locally right away
/// (in-memory cache, then SQLite — lock order state → store). The WS
/// `MessageDeleted` broadcast reaches us too; every removal involved is
/// idempotent. A failure surfaces as a notice banner.
fn spawn_delete_message(
    state: &Arc<Mutex<ClientState>>,
    store: &Arc<Mutex<Store>>,
    rt: &tokio::runtime::Handle,
    ctx: &egui::Context,
    ch: i64,
    msg_id: i64,
) {
    let Some(h) = net_handle(state) else { return };
    let state = Arc::clone(state);
    let store = Arc::clone(store);
    let ctx = ctx.clone();
    rt.spawn(async move {
        match h.net.delete_message(ch, msg_id).await {
            Ok(()) => {
                {
                    let mut st = guard(&state);
                    if let Some(m) = st.main_mut() {
                        m.remove_message(ch, msg_id);
                    }
                }
                let _ = guard(&store).delete_message(msg_id);
            }
            Err(e) => {
                if let Some(m) = guard(&state).main_mut() {
                    m.notice = Some(e);
                }
            }
        }
        ctx.request_repaint();
    });
}

/// Square icon button rendering an embedded white-stroke SVG, tinted to
/// the theme's text color so it adapts to light/dark. The tooltip keeps
/// the action discoverable without a text label.
fn icon_button(
    ui: &mut egui::Ui,
    uri: &'static str,
    svg: &'static [u8],
    tooltip: &str,
) -> egui::Response {
    let tint = ui.visuals().widgets.inactive.fg_stroke.color;
    // Bare icon, no Button frame: zero vertical padding so the composer
    // row hugs its text height. A click sense + pointer cursor keep it
    // discoverable, matching the row hover-action icons.
    ui.add(
        egui::Image::from_bytes(uri, svg)
            .fit_to_exact_size(egui::Vec2::splat(14.0))
            .tint(tint)
            .sense(egui::Sense::click()),
    )
    .on_hover_cursor(egui::CursorIcon::PointingHand)
    .on_hover_text(tooltip)
}

/// Current net handle, or `None` while disconnected. Shared with the
/// attachments view (C4).
pub(crate) fn net_handle(state: &Arc<Mutex<ClientState>>) -> Option<NetHandle> {
    guard(state).main().and_then(|m| m.net.clone())
}

/// Run a REST call on the runtime, surfacing failures as a notice.
fn spawn_rest<F, Fut>(
    state: &Arc<Mutex<ClientState>>,
    rt: &tokio::runtime::Handle,
    ctx: &egui::Context,
    fut_fn: F,
) where
    F: FnOnce(NetHandle) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<(), String>> + Send + 'static,
{
    let Some(h) = net_handle(state) else { return };
    let state = Arc::clone(state);
    let ctx = ctx.clone();
    rt.spawn(async move {
        if let Err(e) = fut_fn(h).await {
            if let Some(m) = guard(&state).main_mut() {
                m.notice = Some(e);
            }
        }
        ctx.request_repaint();
    });
}

/// UTC hh:mm (local timezones are C3 polish).
fn fmt_time(ms: i64) -> String {
    let secs = ms.div_euclid(1000).rem_euclid(86_400);
    format!("{:02}:{:02}", secs / 3600, (secs % 3600) / 60)
}

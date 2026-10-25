//! Left column of the logged-in view (guilds / friends / DMs) plus the
//! shared view-lifetime state ([`MainView`]) and the per-frame world
//! snapshot the three columns render from.
//!
//! [`show`] is the top-level orchestrator: it takes one [`PanelSnap`] per
//! frame (cheaply, skipping the deep clone when nothing moved since the
//! previous frame — see [`panel_snap`]) and hands `&`-references of it to
//! [`super::chat::middle`] / [`super::chat::chat`] and the popups in
//! [`super::popups`]. Interaction handlers still lock [`crate::state`] to
//! mutate it; the snapshot is read-only.

use std::collections::{HashMap, HashSet, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use eframe::egui;

use bysyc_common::protocol::{
    AccountBrief, CreateGuildInviteRequest, CreateGuildRequest, DmChannel, GuildInfo,
    JoinGuildRequest, OpenDmRequest,
};

use crate::app::BysycApp;
use crate::crypto::Envelope;
use crate::net::NetHandle;
use crate::state::{ClientState, MainState, Selection, guard};
use crate::store::Store;
use crate::views::attachments;

use super::chat::{cached_middle_min_width, chat, middle};
use super::popups::{dm_picker, guild_popup, invite_window};

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
    /// True while the message list sits at (or near) its bottom, from
    /// the last rendered frame. Gates "Load older" scroll anchoring: a reader
    /// stuck to the bottom must stay there when older rows prepend.
    pub chat_at_bottom: bool,
    /// Pending "Load older" scroll anchor: after older rows prepend, hold
    /// the previously-oldest message at the top of the viewport. See
    /// [`LoadAnchor`].
    pub load_anchor: Option<LoadAnchor>,
    /// Armed channel deletions: channel id → when the "×" was clicked.
    /// The second click within `super::chat::DELETE_CONFIRM_TTL` deletes.
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
    /// clicked. The confirming "yes" within `super::chat::DELETE_CONFIRM_TTL`
    /// fires the delete.
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
    /// `super::chat::estimate_row_height`. Cleared when the row width
    /// moves (wrapped bodies re-measure as they render).
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
    /// Memoized `super::chat::middle_min_width`: input-signature hash → width (plus
    /// the style it was measured under, kept in
    /// [`MainView::mid_min_style`]).
    pub mid_min_cache: Option<(u64, f32)>,
    /// Style the memoized [`MainView::mid_min_cache`] width was measured
    /// under; a theme/style change re-measures.
    pub mid_min_style: Option<Arc<egui::Style>>,
    /// Per-frame world snapshot cache (see [`panel_snap`]): the signature
    /// of the last built [`PanelSnap`] and the snapshot itself, reused
    /// while the inputs are unchanged so the steady-state frame deep-clones
    /// nothing. None until the first snapshot is built.
    panel_snap_cache: Option<(u64, Arc<PanelSnap>)>,
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

/// Frames an image texture may sit untouched before eviction
/// (see [`MainView::evict_stale_images`]).
const IMAGE_IDLE_FRAMES: u64 = 900;
/// Hard cap on cached image textures regardless of freshness.
const IMAGE_CACHE_CAP: usize = 48;

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
            panel_snap_cache: None,
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
    // [`panel_snap`] memoizes the clone: when nothing moved since the
    // previous frame it hands back the same `Arc<PanelSnap>`, so a
    // steady-state repaint costs one lock and zero Vec clones.
    let snap = panel_snap(state, main_view);

    // egui 0.36: one `Panel` type with side constructors. Both side columns
    // are drag-resizable within a bounded range so they stay usable from
    // small windows (min) up to wide ones (max).
    egui::Panel::left("nav")
        .resizable(true)
        .default_size(140.0)
        .min_size(140.0)
        .max_size(400.0)
        .show(ui, |ui| nav(ui, state, store, rt, main_view, &ctx, snap.as_deref()));

    // The middle column's minimum (and first-run default) is its intrinsic
    // width — the widest visible row measured against the live state, so
    // no channel name or DM row ever wraps or truncates. egui clamps the
    // persisted width into [min, max] every frame, so a min that grows
    // with content also pulls the panel wider as needed. The measurement
    // walks every label of every guild, so it is memoized against a cheap
    // signature of its inputs (see [`cached_middle_min_width`]).
    let mid_min = cached_middle_min_width(main_view, &ctx, snap.as_deref());
    egui::Panel::left("middle")
        .resizable(true)
        .default_size(mid_min)
        .min_size(mid_min)
        .max_size(400.0)
        .show(ui, |ui| middle(ui, state, rt, main_view, &ctx, snap.as_deref()));

    egui::CentralPanel::default().show(ui, |ui| chat(ui, state, store, rt, main_view, &ctx, snap.as_deref()));

    // Transient popups driven by background tasks (invite codes).
    invite_window(state, &ctx);

    // Audio device settings (output/input pickers).
    crate::views::settings::settings_window(&ctx, state, store, rt, &mut main_view.settings_open);

    // C5 renders the call overlay from here.
    crate::call::ui::overlay(&ctx, state, rt);
}

/// What the three columns render, cloned once per frame under one state
/// lock (see [`show`]). Voice enters as (participant count, am I in the
/// call) — the only facts the panels and width measurement read.
pub(super) struct PanelSnap {
    pub(super) my_id: i64,
    pub(super) selected: Selection,
    pub(super) guilds: Vec<GuildInfo>,
    pub(super) dms: Vec<DmChannel>,
    pub(super) friends: Vec<AccountBrief>,
    pub(super) incoming: Vec<AccountBrief>,
    pub(super) outgoing: Vec<AccountBrief>,
    pub(super) unread: HashSet<i64>,
    pub(super) online: HashSet<i64>,
    /// Voice channel id → (participants, joined by me).
    pub(super) voice: HashMap<i64, (usize, bool)>,
}

/// Build (or reuse) the per-frame world snapshot. Steady-state repaints
/// carry no server or UI mutation, so the snapshot is memoized against a
/// cheap signature of its inputs: when the signature matches the previous
/// frame's, the cached [`PanelSnap`] is handed back (one `Arc` refcount
/// bump, no `Vec` clones); only a genuinely changed world pays the deep
/// clone. The signature is computed under the same single state lock as
/// the build, so a hit avoids both the clone and the second lock the old
/// per-panel guards used to take.
fn panel_snap(state: &Arc<Mutex<ClientState>>, mv: &mut MainView) -> Option<Arc<PanelSnap>> {
    let st = guard(state);
    let m = st.main()?;
    let sig = panel_snap_signature(m);
    if let Some((prev_sig, cached)) = &mv.panel_snap_cache {
        if *prev_sig == sig {
            return Some(Arc::clone(cached));
        }
    }
    let snap = Arc::new(PanelSnap {
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
    });
    mv.panel_snap_cache = Some((sig, Arc::clone(&snap)));
    Some(snap)
}

/// Cheap, allocation-free signature of everything that goes into a
/// [`PanelSnap`]: a match drives the cache in [`panel_snap`]. Vec fields are
/// hashed in-order (their position is part of what the panels render), and
/// the sets/maps (unread, online, voice) use an order-independent XOR fold
/// so iteration order — arbitrary for `HashSet`/`HashMap` — cannot flutter
/// the signature between identical frames. Mirrors the inputs field-by-field
/// so any mutation the panels would render also moves the signature.
fn panel_snap_signature(m: &MainState) -> u64 {
    let mut h = DefaultHasher::new();
    m.account.id.hash(&mut h);
    match m.selected {
        Selection::Channel(c) => {
            0u8.hash(&mut h);
            c.hash(&mut h);
        }
        Selection::Dm(c) => {
            1u8.hash(&mut h);
            c.hash(&mut h);
        }
        Selection::Friends => {
            2u8.hash(&mut h);
        }
    }
    for g in &m.guilds {
        g.id.hash(&mut h);
        g.name.hash(&mut h);
        g.owner_id.hash(&mut h);
        for c in &g.channels {
            c.id.hash(&mut h);
            c.guild_id.hash(&mut h);
            std::mem::discriminant(&c.kind).hash(&mut h);
            c.name.hash(&mut h);
        }
    }
    for d in &m.dms {
        d.channel.id.hash(&mut h);
        d.channel.guild_id.hash(&mut h);
        std::mem::discriminant(&d.channel.kind).hash(&mut h);
        d.channel.name.hash(&mut h);
        d.peer.id.hash(&mut h);
        d.peer.username.hash(&mut h);
        d.peer.identity_key.hash(&mut h);
        d.peer.online.hash(&mut h);
    }
    for f in &m.friends {
        f.id.hash(&mut h);
        f.username.hash(&mut h);
        f.identity_key.hash(&mut h);
        f.online.hash(&mut h);
    }
    for f in &m.incoming_requests {
        f.id.hash(&mut h);
        f.username.hash(&mut h);
        f.identity_key.hash(&mut h);
        f.online.hash(&mut h);
    }
    for f in &m.outgoing_requests {
        f.id.hash(&mut h);
        f.username.hash(&mut h);
        f.identity_key.hash(&mut h);
        f.online.hash(&mut h);
    }
    // Order-independent fold for the two sets: membership is what matters,
    // iteration order is not.
    let xor_set = |set: &HashSet<i64>| -> u64 {
        let mut acc = 0u64;
        for id in set {
            let mut hh = DefaultHasher::new();
            id.hash(&mut hh);
            acc ^= hh.finish();
        }
        acc
    };
    m.unread.len().hash(&mut h);
    xor_set(&m.unread).hash(&mut h);
    m.online.len().hash(&mut h);
    xor_set(&m.online).hash(&mut h);
    // Voice: per-entry (channel, count, joined-by-me) XOR-folded so map
    // iteration order cannot perturb the signature.
    m.voice.len().hash(&mut h);
    let mut vacc = 0u64;
    for (ch, ps) in &m.voice {
        let mut hh = DefaultHasher::new();
        ch.hash(&mut hh);
        ps.len().hash(&mut hh);
        ps.iter().any(|p| p.id == m.account.id).hash(&mut hh);
        vacc ^= hh.finish();
    }
    vacc.hash(&mut h);
    h.finish()
}

/// Display title of a channel from the per-frame snapshot (same output as
/// [`MainState::channel_name`], without another state lock).
pub(super) fn snap_channel_name(snap: &PanelSnap, channel_id: i64) -> String {
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

#[allow(clippy::too_many_arguments)]
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

/// Open (or reuse) a DM with `peer_id` and select it.
pub(super) fn open_dm_and_select(
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
pub(super) fn spawn_invite(
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

/// Shared REST half of create/join guild: run the call, merge the returned
/// guild locally (the WS `GuildJoined` echo is deduped on insert).
pub(super) fn spawn_guild_rest<F, Fut>(
    state: &Arc<Mutex<ClientState>>,
    rt: &tokio::runtime::Handle,
    ctx: &egui::Context,
    fut_fn: F,
) where
    F: FnOnce(NetHandle) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<GuildInfo, String>> + Send + 'static,
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

/// Current net handle, or `None` while disconnected. Shared with the other
/// view modules (chat / composer / popups) and the attachments view (C4).
pub(crate) fn net_handle(state: &Arc<Mutex<ClientState>>) -> Option<NetHandle> {
    guard(state).main().and_then(|m| m.net.clone())
}
